//! Opcode `0x09`, report queries: how the backend reads usage, budgets and server metrics now
//! that Fareward is their source of truth (plan D7). Mirrored by `go/reports.go`.
//!
//! The request is a colbin message like every other opcode's. The reply is shape `0x0B`,
//! `[length:u32][body]`, the only reply that may be large; the body is
//! `[kind:u8][rows:u32][row…]`, big-endian throughout, with the values in the store's own layouts
//! (`store::codec`) so the client reads one format per table:
//!
//! | Kind | Asks | Row |
//! |---|---|---|
//! | 1 company usage | company, frames `[first, last]` | `[frame:i32][len:u32][usage_company value]` |
//! | 2 user usage | company, user (0 = every user), frames | `[user:i32][frame:i32][len:u32][usage_user value]` |
//! | 3 every company's usage | frames | `[company:i32][frame:i32][len:u32][usage_company value]` |
//! | 4 budgets | company (0 = every company) | `[company:i32][budget value]` |
//! | 5 server metrics | `first`/`last` as `date << 16 \| slot` | `[date:i16][slot:i16][server_metrics value]` |
//!
//! Company 0 is a real company in kind 1: the platform-wide aggregate lives under it.

use anyhow::{Result, bail};
use colbin::Colbin;
use thiserror::Error;

use crate::store::FjallStore;

/// Five fields at their widest, plus the root.
pub const QUERY_MAX_PAYLOAD_SIZE: usize = 48;

/// A reply larger than this is refused rather than sent: it would hold the connection for every
/// other request multiplexed on it. Thirty days of every company is far below it.
pub const MAX_REPORT_BYTES: usize = 32 << 20;

/// The widest range a usage query may span, in frames. Daily frames step by one per day and
/// five-minute frames by one per five minutes, so this is about three years of days or eleven days
/// of five-minute buckets — the reports ask for thirty days and twenty-four hours.
pub const MAX_FRAME_SPAN: i64 = 4_000;

/// The frame as colbin carries it. Mirrors `reportQueryFrame` in fareward/go/reports.go.
#[derive(Colbin, Debug, Default, PartialEq, Eq)]
pub struct ReportQueryFrame {
    #[cb(1)]
    pub kind: u8,
    #[cb(2)]
    pub company_id: i32,
    #[cb(3)]
    pub user_id: i32,
    #[cb(4)]
    pub first: i64,
    #[cb(5)]
    pub last: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReportQuery {
    CompanyUsage {
        company_id: i32,
        first: i32,
        last: i32,
    },
    UserUsage {
        company_id: i32,
        user_id: Option<i32>,
        first: i32,
        last: i32,
    },
    EveryCompanyUsage {
        first: i32,
        last: i32,
    },
    Budgets {
        company_id: Option<i32>,
    },
    ServerMetrics {
        first: (i16, i16),
        last: (i16, i16),
    },
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum QueryProtocolError {
    #[error("report payload is not a valid colbin message: {0}")]
    Malformed(#[from] colbin::Error),
    #[error("unknown report kind {0}")]
    UnknownKind(u8),
    #[error("company_id must not be negative")]
    InvalidCompany,
    #[error("the range [{0}, {1}] is empty, out of range or too wide")]
    InvalidRange(i64, i64),
}

pub fn parse_report_query(payload: &[u8]) -> Result<ReportQuery, QueryProtocolError> {
    let frame = ReportQueryFrame::decode(payload)?;
    if frame.company_id < 0 || frame.user_id < 0 {
        return Err(QueryProtocolError::InvalidCompany);
    }
    let frames = || {
        let valid = frame.first <= frame.last
            && frame.last - frame.first <= MAX_FRAME_SPAN
            && i32::try_from(frame.first).is_ok()
            && i32::try_from(frame.last).is_ok();
        if valid {
            Ok((frame.first as i32, frame.last as i32))
        } else {
            Err(QueryProtocolError::InvalidRange(frame.first, frame.last))
        }
    };
    let optional = |id: i32| (id != 0).then_some(id);
    Ok(match frame.kind {
        1 => {
            let (first, last) = frames()?;
            ReportQuery::CompanyUsage {
                company_id: frame.company_id,
                first,
                last,
            }
        }
        2 => {
            let (first, last) = frames()?;
            ReportQuery::UserUsage {
                company_id: frame.company_id,
                user_id: optional(frame.user_id),
                first,
                last,
            }
        }
        3 => {
            let (first, last) = frames()?;
            ReportQuery::EveryCompanyUsage { first, last }
        }
        4 => ReportQuery::Budgets {
            company_id: optional(frame.company_id),
        },
        5 => {
            let unpack = |packed: i64| -> Option<(i16, i16)> {
                let date = i16::try_from(packed >> 16).ok()?;
                Some((date, (packed & 0xFFFF) as u16 as i16))
            };
            match (unpack(frame.first), unpack(frame.last)) {
                (Some(first), Some(last)) if frame.first <= frame.last => {
                    ReportQuery::ServerMetrics { first, last }
                }
                _ => return Err(QueryProtocolError::InvalidRange(frame.first, frame.last)),
            }
        }
        kind => return Err(QueryProtocolError::UnknownKind(kind)),
    })
}

impl ReportQuery {
    fn kind(&self) -> u8 {
        match self {
            Self::CompanyUsage { .. } => 1,
            Self::UserUsage { .. } => 2,
            Self::EveryCompanyUsage { .. } => 3,
            Self::Budgets { .. } => 4,
            Self::ServerMetrics { .. } => 5,
        }
    }

    /// Reads the rows and builds the reply body.
    pub fn answer(&self, store: &FjallStore) -> Result<Vec<u8>> {
        let mut body = ReportBody::new(self.kind());
        match *self {
            Self::CompanyUsage {
                company_id,
                first,
                last,
            } => {
                for (frame, value) in store.company_usage(company_id, first, last)? {
                    body.row(|row| {
                        row.extend_from_slice(&frame.to_be_bytes());
                        put_value(row, &value.encode());
                    })?;
                }
            }
            Self::UserUsage {
                company_id,
                user_id,
                first,
                last,
            } => {
                let rows = match user_id {
                    Some(user_id) => store
                        .user_usage(company_id, user_id, first, last)?
                        .into_iter()
                        .map(|(frame, blob)| (user_id, frame, blob))
                        .collect(),
                    None => store.company_users_usage(company_id, first, last)?,
                };
                for (user_id, frame, blob) in rows {
                    body.row(|row| {
                        row.extend_from_slice(&user_id.to_be_bytes());
                        row.extend_from_slice(&frame.to_be_bytes());
                        put_value(row, &crate::store::codec::encode_user_usage(&blob));
                    })?;
                }
            }
            Self::EveryCompanyUsage { first, last } => {
                for (company_id, frame, value) in store.every_company_usage(first, last)? {
                    body.row(|row| {
                        row.extend_from_slice(&company_id.to_be_bytes());
                        row.extend_from_slice(&frame.to_be_bytes());
                        put_value(row, &value.encode());
                    })?;
                }
            }
            Self::Budgets { company_id } => {
                let records = match company_id {
                    Some(company_id) => store.budget(company_id)?.into_iter().collect(),
                    None => store.budgets()?,
                };
                for record in records {
                    body.row(|row| {
                        row.extend_from_slice(&record.budget.company_id.to_be_bytes());
                        row.extend_from_slice(&record.encode());
                    })?;
                }
            }
            Self::ServerMetrics { first, last } => {
                for (date, slot, sample) in store.metrics(first, last)? {
                    body.row(|row| {
                        row.extend_from_slice(&date.to_be_bytes());
                        row.extend_from_slice(&slot.to_be_bytes());
                        row.extend_from_slice(&crate::store::codec::encode_metrics(&sample));
                    })?;
                }
            }
        }
        Ok(body.finish())
    }
}

fn put_value(row: &mut Vec<u8>, value: &[u8]) {
    row.extend_from_slice(&(value.len() as u32).to_be_bytes());
    row.extend_from_slice(value);
}

/// `[kind][rows:u32][row…]`, with the row count patched in at the end.
struct ReportBody {
    bytes: Vec<u8>,
    rows: u32,
}

impl ReportBody {
    fn new(kind: u8) -> Self {
        Self {
            bytes: vec![kind, 0, 0, 0, 0],
            rows: 0,
        }
    }

    fn row(&mut self, write: impl FnOnce(&mut Vec<u8>)) -> Result<()> {
        write(&mut self.bytes);
        self.rows += 1;
        if self.bytes.len() > MAX_REPORT_BYTES {
            bail!("the report is larger than {MAX_REPORT_BYTES} bytes");
        }
        Ok(())
    }

    fn finish(mut self) -> Vec<u8> {
        self.bytes[1..5].copy_from_slice(&self.rows.to_be_bytes());
        self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limiter::block::Rejections;
    use crate::store::temporary_store;

    fn frame(kind: u8, company_id: i32, user_id: i32, first: i64, last: i64) -> Vec<u8> {
        ReportQueryFrame {
            kind,
            company_id,
            user_id,
            first,
            last,
        }
        .encode()
    }

    #[test]
    fn every_kind_parses_and_its_payload_fits_the_ceiling() {
        let widest = frame(5, i32::MAX, i32::MAX, i64::MAX, i64::MAX);
        assert!(widest.len() <= QUERY_MAX_PAYLOAD_SIZE, "{}", widest.len());

        assert_eq!(
            parse_report_query(&frame(1, 0, 0, 200_000_001, 200_000_030)),
            Ok(ReportQuery::CompanyUsage {
                company_id: 0,
                first: 200_000_001,
                last: 200_000_030
            })
        );
        assert_eq!(
            parse_report_query(&frame(2, 7, 0, 1, 2)),
            Ok(ReportQuery::UserUsage {
                company_id: 7,
                user_id: None,
                first: 1,
                last: 2
            })
        );
        assert_eq!(
            parse_report_query(&frame(4, 0, 0, 0, 0)),
            Ok(ReportQuery::Budgets { company_id: None })
        );
        assert_eq!(
            parse_report_query(&frame(5, 0, 0, (20_400 << 16) | 17_000, (20_401 << 16) | 3)),
            Ok(ReportQuery::ServerMetrics {
                first: (20_400, 17_000),
                last: (20_401, 3)
            })
        );
    }

    #[test]
    fn bad_queries_are_refused() {
        // The same bytes go/reports_test.go pins for the Go encoder: the two must agree.
        assert_eq!(
            frame(2, 7, 42, 200_000_000, 200_000_029),
            [
                0x01, 0x14, 0x07, 0x24, 0x2A, 0x37, 0x00, 0xC2, 0xEB, 0x0B, 0x47, 0x1D, 0xC2, 0xEB,
                0x0B
            ]
        );
        assert_eq!(
            parse_report_query(&frame(9, 0, 0, 0, 0)),
            Err(QueryProtocolError::UnknownKind(9))
        );
        assert_eq!(
            parse_report_query(&frame(1, -1, 0, 0, 0)),
            Err(QueryProtocolError::InvalidCompany)
        );
        assert!(parse_report_query(&frame(1, 1, 0, 10, 9)).is_err());
        assert!(parse_report_query(&frame(3, 0, 0, 0, MAX_FRAME_SPAN + 1)).is_err());
        assert!(parse_report_query(&frame(1, 1, 0, 0, i64::from(i32::MAX) + 1)).is_err());
    }

    #[test]
    fn a_company_report_carries_counters_and_credits() {
        let (_directory, store) = temporary_store();
        store
            .put_usage(7, None, 200_000_010, vec![0, 4, 1, 2])
            .unwrap();
        store
            .add_rejections(
                7,
                200_000_010,
                Rejections {
                    short: 1,
                    long: 2,
                    no_funds: 3,
                },
            )
            .unwrap();
        let body = ReportQuery::CompanyUsage {
            company_id: 7,
            first: 200_000_000,
            last: 200_000_020,
        }
        .answer(&store)
        .unwrap();
        assert_eq!(
            body,
            [
                1, 0, 0, 0, 1, // kind, one row
                0x0B, 0xEB, 0xC2, 0x0A, // frame 200_000_010
                0, 0, 0, 17, // value length
                1, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 4, 1, 2,
            ]
        );
    }

    #[test]
    fn an_empty_report_is_just_its_head() {
        let (_directory, store) = temporary_store();
        let body = ReportQuery::Budgets { company_id: None }
            .answer(&store)
            .unwrap();
        assert_eq!(body, [4, 0, 0, 0, 0]);
    }
}
