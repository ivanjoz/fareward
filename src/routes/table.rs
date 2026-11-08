//! The route policy table (plan D1): what a request must hold and what it costs, by method and
//! exact path, as the backend's own gate decides it.
//!
//! The file is written by the Genix backend from the catalogue it embeds (`access.toml`, the route
//! numbers, the tariff and its special cases), so the edge enforces the same policy the backend
//! does. The limiter core never sees this: it is adapter policy, the counterpart of
//! `enforceAccessAndCredits` in `backend/main-handlers.go`.
//!
//! A route that is not in the table is refused. There are no defaults.

use std::collections::{HashMap, HashSet};

use serde::Deserialize;
use thiserror::Error;

use crate::limiter::{
    access::MAX_REQUIRED_ACCESS,
    credits_blob::{Credits, MAX_ROUTE_ID},
    protocol::Request,
};

/// The size steps of one method's tariff. Global per method, not per route: a route only states
/// how many credits each step costs.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Tariff {
    /// Bytes covered by `base_credits`, in KiB.
    pub base_kib: u32,
    /// Each started block past the base costs `step_credits`, in KiB.
    pub step_kib: u32,
}

/// Identity-dependent rules the backend applies. In the file because they are policy, but applied
/// by `RouteTable::admission`, which is the only place that knows the identity.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// First path segments the backend strips before matching (`api`, `go1`…).
    pub api_prefixes: Vec<String>,
    /// The only company allowed on a `saas_only` route.
    pub saas_company_id: i32,
    /// The user whose stored grants are empty because login synthesizes them: it skips the access
    /// check (`resolveRouteAccess`), never the charge.
    pub access_exempt_user_id: i32,
    /// The platform operator's company: charged like any tenant, but a credit refusal does not
    /// reach it (`TolerateCreditRefusal`), so it can always get in to raise its own budget. An
    /// access refusal still does.
    pub operator_company_id: i32,
}

impl Policy {
    pub fn tolerates_credit_refusal(&self, company_id: i32) -> bool {
        company_id == self.operator_company_id
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RouteEntry {
    pub method: String,
    /// The route as the backend names it after stripping the leading slash and the API prefix:
    /// `productos`, `p-company-names-by-ids`. Matched exactly.
    pub path: String,
    pub route_id: u16,
    /// Packed grants, `acceso_id << 2 | (nivel - 1)`; the caller must hold one. Empty means a
    /// session is enough.
    #[serde(default)]
    pub slots: Vec<u16>,
    /// Zero means the route is not charged (the credit panel's own routes, methods with no
    /// tariff).
    #[serde(default)]
    pub base_credits: u16,
    #[serde(default)]
    pub step_credits: u16,
    /// No session, no access, no charge.
    #[serde(default)]
    pub public: bool,
    /// Only `policy.saas_company_id` may call it.
    #[serde(default)]
    pub saas_only: bool,
    /// The backend refuses this route with this status (an unmapped write is 403), except to
    /// `policy.access_exempt_user_id`, which the backend lets through before it gets that far. So the
    /// entry still carries its tariff: that user is charged.
    #[serde(default)]
    pub deny: Option<u16>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RouteFile {
    version: String,
    policy: Policy,
    #[serde(default)]
    tariff: HashMap<String, Tariff>,
    #[serde(default, rename = "route")]
    routes: Vec<RouteEntry>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RouteTableError {
    #[error("routes file is not valid TOML for the expected shape: {0}")]
    Parse(String),
    #[error("routes file has an empty version")]
    MissingVersion,
    #[error("tariff for {0} must have positive base_kib and step_kib")]
    InvalidTariff(String),
    #[error("route {method} {path}: {reason}")]
    InvalidRoute {
        method: String,
        path: String,
        reason: &'static str,
    },
    #[error("route {method} {path} is declared twice")]
    Duplicate { method: String, path: String },
}

/// Why the edge refuses a request before asking the limiter. Each maps to the status the backend
/// would have answered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// Not in the table: refused, there are no defaults.
    UnknownRoute,
    /// The table says the backend refuses it (`deny`).
    Denied(u16),
    /// A `saas_only` route from another company.
    SaasOnly,
    /// A charged write with no `Content-Length`: its cost depends on its size.
    LengthRequired,
    /// The computed charge does not fit the sixteen bits the backend's tariff allows.
    PayloadTooLarge,
}

impl Refusal {
    /// The status the backend answers in the same situation, which is the contract (plan §7). Its
    /// error responses default to 400 when no code is set, and both the unknown route ("no hay una
    /// lambda") and the SaaS-only refusal are answered that way.
    pub fn status(self) -> u16 {
        match self {
            Refusal::UnknownRoute => 400,
            Refusal::Denied(status) => status,
            Refusal::SaasOnly => 400,
            // Edge-only: the backend reads the whole body instead of trusting a header.
            Refusal::LengthRequired => 411,
            // The backend fails closed with a 503 when the tariff overflows sixteen bits; 413 says
            // what actually happened. A divergence shadow mode will show, by design.
            Refusal::PayloadTooLarge => 413,
        }
    }
}

/// What the edge does with one request, once the route and the identity are known.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admission {
    /// A public route: no identity was needed and nothing is charged.
    Public {
        route_id: u16,
    },
    /// Nothing to charge and nothing to check: the session alone admits it, as the backend does for
    /// an unmapped GET.
    SessionOnly {
        route_id: u16,
    },
    /// Ask the limiter.
    Ask(Request),
    Refuse(Refusal),
}

/// Where a request stands before its identity is known.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteMatch<'table> {
    Public {
        route_id: u16,
    },
    /// A session is required; `admission` finishes the decision.
    Private(&'table RouteEntry),
    Refuse(Refusal),
}

#[derive(Debug)]
pub struct RouteTable {
    version: String,
    policy: Policy,
    api_prefixes: HashSet<String>,
    tariff: HashMap<String, Tariff>,
    routes: HashMap<(String, String), RouteEntry>,
}

impl RouteTable {
    pub fn parse(content: &str) -> Result<Self, RouteTableError> {
        let file: RouteFile =
            toml::from_str(content).map_err(|error| RouteTableError::Parse(error.to_string()))?;
        if file.version.trim().is_empty() {
            return Err(RouteTableError::MissingVersion);
        }
        for (method, tariff) in &file.tariff {
            if tariff.base_kib == 0 || tariff.step_kib == 0 {
                return Err(RouteTableError::InvalidTariff(method.clone()));
            }
        }

        let mut routes = HashMap::with_capacity(file.routes.len());
        for entry in file.routes {
            validate_entry(&entry, &file.tariff)?;
            let key = (entry.method.clone(), entry.path.clone());
            if routes.contains_key(&key) {
                return Err(RouteTableError::Duplicate {
                    method: entry.method,
                    path: entry.path,
                });
            }
            routes.insert(key, entry);
        }

        Ok(Self {
            version: file.version,
            api_prefixes: file.policy.api_prefixes.iter().cloned().collect(),
            policy: file.policy,
            tariff: file.tariff,
            routes,
        })
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    pub fn len(&self) -> usize {
        self.routes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    /// The route name the backend matches, from a raw request path: the query string, the leading
    /// slash and an API prefix segment go, exactly as `mainHandler` strips them.
    pub fn route_name<'path>(&self, raw_path: &'path str) -> &'path str {
        let path = raw_path.split(['?', '#']).next().unwrap_or_default();
        let path = path.strip_prefix('/').unwrap_or(path);
        match path.split_once('/') {
            Some((first, rest)) if self.api_prefixes.contains(first) => rest,
            None if self.api_prefixes.contains(path) => "",
            _ => path,
        }
    }

    /// Matches a request by method and raw path. Exact: no prefixes, no parameters.
    pub fn lookup(&self, method: &str, raw_path: &str) -> RouteMatch<'_> {
        let route = self.route_name(raw_path);
        let Some(entry) = self.routes.get(&(method.to_owned(), route.to_owned())) else {
            return RouteMatch::Refuse(Refusal::UnknownRoute);
        };
        if entry.public {
            return RouteMatch::Public {
                route_id: entry.route_id,
            };
        }
        // `deny` waits for the identity: the exempt user passes it.
        RouteMatch::Private(entry)
    }

    /// The credits the pre-handler charge carries. A GET is charged its base only: its size is the
    /// response's, which does not exist yet, and the backend settles the rest afterwards. A write is
    /// charged in full from its declared length.
    pub fn charge(&self, entry: &RouteEntry, content_length: Option<u64>) -> Result<u64, Refusal> {
        if entry.base_credits == 0 {
            return Ok(0);
        }
        let base = u64::from(entry.base_credits);
        if entry.method == "GET" {
            return Ok(base);
        }
        let tariff = self
            .tariff
            .get(&entry.method)
            .expect("validated: a charged route has a tariff");
        let length = content_length.ok_or(Refusal::LengthRequired)?;
        let base_bytes = u64::from(tariff.base_kib) * 1024;
        let step_bytes = u64::from(tariff.step_kib) * 1024;
        let extra_steps = length.saturating_sub(base_bytes).div_ceil(step_bytes);
        let credits = extra_steps
            .checked_mul(u64::from(entry.step_credits))
            .and_then(|extra| extra.checked_add(base))
            .ok_or(Refusal::PayloadTooLarge)?;
        if credits > u64::from(u16::MAX) {
            return Err(Refusal::PayloadTooLarge);
        }
        Ok(credits)
    }

    /// Finishes the decision once the session is verified: the SaaS-only check, the exempt user,
    /// and whether the limiter needs asking at all.
    pub fn admission(
        &self,
        entry: &RouteEntry,
        company_id: i32,
        user_id: i32,
        content_length: Option<u64>,
    ) -> Admission {
        // Before the access check, like the backend: no grant can give another company this.
        if entry.saas_only && company_id != self.policy.saas_company_id {
            return Admission::Refuse(Refusal::SaasOnly);
        }
        // The backend's order (resolveRouteAccess): the exempt user skips the access check before a
        // route with no access is refused, so the refusal only reaches everyone else.
        let exempt = user_id == self.policy.access_exempt_user_id;
        if let Some(status) = entry.deny
            && !exempt
        {
            return Admission::Refuse(Refusal::Denied(status));
        }
        let cpu = match self.charge(entry, content_length) {
            Ok(cpu) => cpu,
            Err(refusal) => return Admission::Refuse(refusal),
        };
        let mut required_access = [0_u16; MAX_REQUIRED_ACCESS];
        if !exempt {
            required_access[..entry.slots.len()].copy_from_slice(&entry.slots);
        }
        if cpu == 0 && required_access[0] == 0 {
            return Admission::SessionOnly {
                route_id: entry.route_id,
            };
        }
        Admission::Ask(Request {
            company_id,
            user_id,
            route_id: entry.route_id,
            credits: Credits { cpu, inference: 0 },
            required_access,
            // Only a charged read may fall back to the pool, derived from the method exactly as the
            // backend's client does, so a write can never be marked as a read.
            extra_credits_allowed: entry.method == "GET" && cpu > 0,
        })
    }
}

fn validate_entry(
    entry: &RouteEntry,
    tariff: &HashMap<String, Tariff>,
) -> Result<(), RouteTableError> {
    let invalid = |reason| RouteTableError::InvalidRoute {
        method: entry.method.clone(),
        path: entry.path.clone(),
        reason,
    };
    if entry.method.is_empty() || entry.method != entry.method.to_ascii_uppercase() {
        return Err(invalid("method must be non-empty and uppercase"));
    }
    if entry.path.is_empty() || entry.path.starts_with('/') || entry.path.contains(['?', '#']) {
        return Err(invalid(
            "path must be the route name: non-empty, no leading slash, no query",
        ));
    }
    if entry.route_id > MAX_ROUTE_ID {
        return Err(invalid("route_id does not fit fourteen bits"));
    }
    if entry.slots.len() > MAX_REQUIRED_ACCESS {
        return Err(invalid(
            "more than four slots: truncating would authorize against fewer accesses",
        ));
    }
    // A zero slot would mean acceso 0, which does not exist, and would end the frame's list early.
    if entry.slots.contains(&0) {
        return Err(invalid("a slot cannot be zero"));
    }
    if entry.base_credits == 0 && entry.step_credits != 0 {
        return Err(invalid("step_credits without base_credits"));
    }
    if entry.base_credits > 0 && !tariff.contains_key(&entry.method) {
        return Err(invalid("charged route on a method with no tariff"));
    }
    if entry.public && (entry.saas_only || entry.deny.is_some() || !entry.slots.is_empty()) {
        return Err(invalid(
            "a public route cannot carry slots, saas_only or deny",
        ));
    }
    if entry
        .deny
        .is_some_and(|status| !(400..=599).contains(&status))
    {
        return Err(invalid("deny must be an HTTP error status"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const FILE: &str = r#"
version = "test-1"

[policy]
api_prefixes = ["api", "go1"]
saas_company_id = 1
access_exempt_user_id = 1
operator_company_id = 1

[tariff.GET]
base_kib = 8
step_kib = 16

[tariff.POST]
base_kib = 8
step_kib = 8

[[route]]
method = "GET"
path = "productos"
route_id = 103
slots = [0x0139, 0x008B]
base_credits = 2
step_credits = 1

[[route]]
method = "GET"
path = "unmapped-read"
route_id = 7
base_credits = 2
step_credits = 1

[[route]]
method = "GET"
path = "credit-usage"
route_id = 11

[[route]]
method = "POST"
path = "productos"
route_id = 104
slots = [0x013A]
base_credits = 5
step_credits = 1

[[route]]
method = "POST"
path = "unmapped-write"
route_id = 105
base_credits = 5
step_credits = 1
deny = 403

[[route]]
method = "GET"
path = "empresas"
route_id = 14
saas_only = true

[[route]]
method = "GET"
path = "p-company-names-by-ids"
route_id = 60
public = true
"#;

    fn table() -> RouteTable {
        RouteTable::parse(FILE).unwrap()
    }

    fn entry<'t>(table: &'t RouteTable, method: &str, path: &str) -> &'t RouteEntry {
        match table.lookup(method, path) {
            RouteMatch::Private(entry) => entry,
            other => panic!("expected a private route, got {other:?}"),
        }
    }

    #[test]
    fn the_path_is_stripped_the_way_the_backend_strips_it() {
        let table = table();
        assert_eq!(table.route_name("/api/productos?x=1"), "productos");
        assert_eq!(table.route_name("/go1/productos"), "productos");
        assert_eq!(table.route_name("/productos"), "productos");
        assert_eq!(table.route_name("/other/productos"), "other/productos");
        assert_eq!(table.route_name("/api"), "");
    }

    #[test]
    fn matching_is_exact_and_an_unknown_route_is_refused() {
        let table = table();
        assert!(matches!(
            table.lookup("GET", "/api/productos"),
            RouteMatch::Private(_)
        ));
        for (method, path) in [
            ("GET", "/api/productos/1"),
            ("GET", "/api/product"),
            ("PUT", "/api/productos"),
            ("get", "/api/productos"),
        ] {
            assert_eq!(
                table.lookup(method, path),
                RouteMatch::Refuse(Refusal::UnknownRoute),
                "{method} {path}"
            );
        }
    }

    #[test]
    fn a_public_route_is_decided_before_the_identity() {
        let table = table();
        assert_eq!(
            table.lookup("GET", "/api/p-company-names-by-ids"),
            RouteMatch::Public { route_id: 60 }
        );
    }

    /// The backend refuses an unmapped write to everyone except the exempt user, who reaches it
    /// before the refusal and is charged like any write.
    #[test]
    fn a_denied_route_refuses_everyone_but_the_exempt_user() {
        let table = table();
        let unmapped = entry(&table, "POST", "/api/unmapped-write");
        assert_eq!(
            table.admission(unmapped, 7, 42, Some(10)),
            Admission::Refuse(Refusal::Denied(403))
        );
        let Admission::Ask(request) = table.admission(unmapped, 7, 1, Some(10)) else {
            panic!("the exempt user passes a denied route");
        };
        assert_eq!(request.credits.cpu, 5);
        assert_eq!(request.required_access, [0; MAX_REQUIRED_ACCESS]);
    }

    #[test]
    fn a_get_is_charged_its_base_and_marked_for_the_pool() {
        let table = table();
        let admission = table.admission(entry(&table, "GET", "/api/productos"), 7, 42, None);
        let Admission::Ask(request) = admission else {
            panic!("expected a limiter request, got {admission:?}");
        };
        assert_eq!(request.credits.cpu, 2);
        assert_eq!(request.route_id, 103);
        assert_eq!(request.required_access, [0x0139, 0x008B, 0, 0]);
        assert!(request.extra_credits_allowed);
    }

    #[test]
    fn a_write_is_charged_in_full_from_its_length() {
        let table = table();
        let post = entry(&table, "POST", "/api/productos");
        let cpu = |length| match table.admission(post, 7, 42, length) {
            Admission::Ask(request) => {
                assert!(!request.extra_credits_allowed);
                request.credits.cpu
            }
            other => panic!("expected a limiter request, got {other:?}"),
        };
        // The backend's own figures (APICPUCredits): 5 up to 8 KiB, then 1 per started 8 KiB.
        assert_eq!(cpu(Some(0)), 5);
        assert_eq!(cpu(Some(8 * 1024)), 5);
        assert_eq!(cpu(Some(8 * 1024 + 1)), 6);
        assert_eq!(cpu(Some(16 * 1024 + 1)), 7);
        assert_eq!(
            table.admission(post, 7, 42, None),
            Admission::Refuse(Refusal::LengthRequired)
        );
        assert_eq!(
            table.admission(post, 7, 42, Some(u64::MAX)),
            Admission::Refuse(Refusal::PayloadTooLarge)
        );
    }

    #[test]
    fn nothing_to_charge_or_check_needs_only_the_session() {
        let table = table();
        assert_eq!(
            table.admission(entry(&table, "GET", "/api/credit-usage"), 7, 42, None),
            Admission::SessionOnly { route_id: 11 }
        );
        // An unmapped read is charged: the backend sends its base too.
        assert!(matches!(
            table.admission(entry(&table, "GET", "/api/unmapped-read"), 7, 42, None),
            Admission::Ask(_)
        ));
    }

    #[test]
    fn the_exempt_user_skips_the_access_check_but_not_the_charge() {
        let table = table();
        let Admission::Ask(request) =
            table.admission(entry(&table, "GET", "/api/productos"), 7, 1, None)
        else {
            panic!("user 1 is still charged");
        };
        assert_eq!(request.required_access, [0; MAX_REQUIRED_ACCESS]);
        assert_eq!(request.credits.cpu, 2);
    }

    #[test]
    fn a_saas_only_route_admits_only_the_saas_company() {
        let table = table();
        let empresas = entry(&table, "GET", "/api/empresas");
        assert_eq!(
            table.admission(empresas, 7, 42, None),
            Admission::Refuse(Refusal::SaasOnly)
        );
        assert_eq!(
            table.admission(empresas, 1, 42, None),
            Admission::SessionOnly { route_id: 14 }
        );
    }

    #[test]
    fn an_invalid_file_is_refused_whole() {
        let with_route = |route: &str| {
            format!(
                "version = \"v\"\n[policy]\napi_prefixes = []\nsaas_company_id = 1\n\
                 access_exempt_user_id = 1\noperator_company_id = 1\n[tariff.GET]\nbase_kib = 8\nstep_kib = 16\n\
                 [[route]]\n{route}"
            )
        };
        for (route, why) in [
            (
                "method = \"GET\"\npath = \"a\"\nroute_id = 1\nslots = [1, 2, 3, 4, 5]",
                "five slots",
            ),
            (
                "method = \"GET\"\npath = \"a\"\nroute_id = 1\nslots = [0]",
                "zero slot",
            ),
            (
                "method = \"POST\"\npath = \"a\"\nroute_id = 1\nbase_credits = 5",
                "no POST tariff",
            ),
            (
                "method = \"GET\"\npath = \"/a\"\nroute_id = 1",
                "leading slash",
            ),
            (
                "method = \"GET\"\npath = \"a\"\nroute_id = 20000",
                "route id too wide",
            ),
            (
                "method = \"GET\"\npath = \"a\"\nroute_id = 1\npublic = true\nslots = [5]",
                "public with slots",
            ),
            (
                "method = \"GET\"\npath = \"a\"\nroute_id = 1\nstep_credits = 1",
                "step without base",
            ),
            (
                "method = \"GET\"\npath = \"a\"\nroute_id = 1\nunknown = 1",
                "unknown field",
            ),
            (
                "method = \"GET\"\npath = \"a\"\nroute_id = 1\n[[route]]\nmethod = \"GET\"\n\
                 path = \"a\"\nroute_id = 2",
                "duplicate",
            ),
        ] {
            assert!(RouteTable::parse(&with_route(route)).is_err(), "{why}");
        }
        assert_eq!(
            RouteTable::parse(&FILE.replace("test-1", " ")).unwrap_err(),
            RouteTableError::MissingVersion
        );
    }

    /// The cross-language check against a file the Genix backend generated: run its
    /// `TestFarewardRouteFileIsWrittenWhole` with `FAREWARD_ROUTES_DUMP=<path>`, then this with
    /// `FAREWARD_ROUTES_FILE_CHECK=<path>`.
    #[test]
    #[ignore = "needs a file generated by the Genix backend"]
    fn a_generated_routes_file_parses() {
        let path = std::env::var("FAREWARD_ROUTES_FILE_CHECK")
            .expect("FAREWARD_ROUTES_FILE_CHECK names the generated file");
        let content = std::fs::read_to_string(path).unwrap();
        let table = RouteTable::parse(&content).unwrap();
        assert!(!table.is_empty());
    }
}
