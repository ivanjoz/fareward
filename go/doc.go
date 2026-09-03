// Package fareward is the Go client for the fareward daemon: the access gate and credit limiter,
// the lock service, and the request log, all reached over one multiplexed raw-TCP connection.
//
// It is also the reference implementation of that wire protocol. The daemon's README calls the
// frame format "contract 1"; this package is what that contract looks like written out, so a
// backend in another language has something to port rather than a specification to re-derive from
// the Rust source.
//
// # Using it
//
// Configure once at startup, then call package-level functions. There is no client object to
// thread through call sites — the connection is process-wide because the daemon keys its frame
// sequence per connection, and one process wants one sequence:
//
//	fareward.SetLogger(myLogger)                          // optional, no-op until set
//	if err := fareward.ConfigureFareward(addr, secret); err != nil {
//		return err
//	}
//
//	err := fareward.ChargeAPIUsage(ctx, companyID, userID, routeID, method, payloadBytes, required)
//	lock, err := fareward.AcquireLock(ctx, action, identifier, maxWaiters)
//	err := fareward.SendRequestLog(ctx, record)
//
// Every call is safe for concurrent use and dials lazily, so ConfigureFareward does not fail
// because the daemon has not started yet, and a dropped connection redials on the next call. A
// call made before ConfigureFareward returns ErrCreditLimiterMissing or its per-service
// equivalent rather than panicking.
//
// There is deliberately no package-level shutdown. The connection is meant to live as long as the
// process, and calling ConfigureFareward again closes the previous one — which is what a config
// reload wants. A caller that needs to drop the connection for its own reasons does not have a
// way to today; say so if you need one rather than reaching for a fork.
//
// # What this package decides, and what it does not
//
// It owns the wire: framing, the connection nonce, the sequence-bound SipHash tag, reply correlation,
// and the codecs for each opcode. It also owns the *tariff* — APICPUCredits, APICPUBaseCredits
// and InferenceCredits — because the daemon charges the credit counts a frame names and does not
// compute them.
//
// It owns none of the policy around that. Which route maps to which access, which routes are
// exempt from charging, which identities bypass the check, and how a refusal becomes an HTTP
// status are all the caller's. The daemon holds no copy of an access catalogue, deliberately, and
// neither does this package: AccessDenied carries a verdict, not a name.
//
// # Dependencies
//
// The standard library, and nothing else. That is a property worth keeping: this package is the
// one piece of the system a backend has to link into its own binary, so its dependency list is
// somebody else's transitive dependency list.
package fareward
