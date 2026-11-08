//! Route policy for the edge (plan D1): the table the Genix backend generates from its own gate,
//! and its hot reload. Used by the HAProxy SPOE agent; the limiter core never sees it.

pub mod table;
pub mod watch;

pub use table::{Admission, Refusal, RouteMatch, RouteTable, RouteTableError};
pub use watch::RouteTableHandle;
