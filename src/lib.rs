mod input;
mod propagation;

use hickory_resolver::proto::rr::RecordType;
use std::fmt;
use std::net::SocketAddr;

pub const TEST_RESOLVERS_ENV: &str = "DNS_CHECK_TEST_RESOLVERS";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Server {
    socket_addr: SocketAddr,
    location: String,
    provider: String,
}

#[derive(Debug, PartialEq, Eq)]
enum CliError {
    Usage(String),
    Validation(String),
    AllLookupsFailed,
}

impl CliError {
    fn exit_code(&self) -> u8 {
        match self {
            Self::Usage(_) | Self::Validation(_) => 2,
            Self::AllLookupsFailed => 1,
        }
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage(message) | Self::Validation(message) => write!(f, "{message}"),
            Self::AllLookupsFailed => write!(f, "All DNS lookups failed."),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct QueryRequest {
    query_name: String,
    record_type: RecordType,
    servers: Vec<Server>,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct RunReport {
    pub stdout_lines: Vec<String>,
    pub stderr_lines: Vec<String>,
    pub exit_code: u8,
}

impl RunReport {
    fn from_error(err: CliError) -> Self {
        Self {
            stdout_lines: Vec::new(),
            stderr_lines: vec![err.to_string()],
            exit_code: err.exit_code(),
        }
    }
}

pub async fn execute(args: Vec<String>) -> RunReport {
    match input::parse_request(&args, std::env::var(TEST_RESOLVERS_ENV)) {
        Ok(request) => propagation::execute_request(request).await,
        Err(err) => RunReport::from_error(err),
    }
}
