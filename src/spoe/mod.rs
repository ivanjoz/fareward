//! The HAProxy SPOE agent (plan phase 4): the SPOP codec and the agent that answers HAProxy with
//! the backend's own gate, before the request body is read.

pub mod agent;
pub mod codec;

pub use agent::{Agent, AgentLimits, Verdict};
