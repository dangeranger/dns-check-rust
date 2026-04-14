use hickory_resolver::config::{NameServerConfig, NameServerConfigGroup, ResolverConfig};
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::proto::rr::{domain::Name, RecordType};
use hickory_resolver::proto::xfer::Protocol;
use hickory_resolver::TokioResolver;
use std::env;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::process::ExitCode;
use tokio::task::JoinSet;

const TEST_RESOLVERS_ENV: &str = "DNS_CHECK_TEST_RESOLVERS";

#[derive(Clone)]
struct Server {
    socket_addr: SocketAddr,
    location: String,
    provider: String,
}

#[derive(Debug)]
enum CliError {
    Usage(String),
    Validation(String),
    AllLookupsFailed,
}

impl CliError {
    fn exit_code(&self) -> ExitCode {
        match self {
            Self::Usage(_) | Self::Validation(_) => ExitCode::from(2),
            Self::AllLookupsFailed => ExitCode::from(1),
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

#[tokio::main]
async fn main() -> ExitCode {
    match run(env::args().collect()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{err}");
            err.exit_code()
        }
    }
}

async fn run(args: Vec<String>) -> Result<(), CliError> {
    let binary_name = args
        .first()
        .map(|arg| binary_name(arg))
        .unwrap_or_else(|| "dns-check-rust".to_string());

    if args.len() < 3 {
        return Err(CliError::Usage(format!(
            "Usage: {binary_name} <domain> <record_type>"
        )));
    }

    let record_type = parse_record_type(&args[2]).map_err(CliError::Validation)?;
    let query_name = normalize_query_name(&args[1], record_type);
    let servers = load_servers().map_err(CliError::Validation)?;

    check_dns_propagation(&query_name, record_type, &servers).await
}

fn binary_name(arg0: &str) -> String {
    Path::new(arg0)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("dns-check-rust")
        .to_string()
}

fn load_servers() -> Result<Vec<Server>, String> {
    match env::var(TEST_RESOLVERS_ENV) {
        Ok(raw) => parse_test_servers(&raw),
        Err(env::VarError::NotPresent) => Ok(default_servers()),
        Err(err) => Err(format!("Failed to read {TEST_RESOLVERS_ENV}: {err}")),
    }
}

fn parse_test_servers(raw: &str) -> Result<Vec<Server>, String> {
    let servers = raw
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(|entry| {
            entry
                .parse::<SocketAddr>()
                .map(|socket_addr| Server {
                    socket_addr,
                    location: "Local test".to_string(),
                    provider: "Injected resolver".to_string(),
                })
                .map_err(|_| format!("Invalid {TEST_RESOLVERS_ENV} entry: {entry}"))
        })
        .collect::<Result<Vec<_>, _>>()?;

    if servers.is_empty() {
        return Err(format!(
            "{TEST_RESOLVERS_ENV} must contain at least one ip:port entry"
        ));
    }

    Ok(servers)
}

fn default_servers() -> Vec<Server> {
    vec![
        Server {
            socket_addr: "8.8.8.8:53".parse().unwrap(),
            location: "Mountain View, California".to_string(),
            provider: "Google LLC".to_string(),
        },
        Server {
            socket_addr: "1.1.1.1:53".parse().unwrap(),
            location: "San Francisco, California".to_string(),
            provider: "Cloudflare, Inc".to_string(),
        },
    ]
}

fn normalize_query_name(query_name: &str, record_type: RecordType) -> String {
    if record_type == RecordType::PTR {
        if let Ok(ip) = query_name.parse::<IpAddr>() {
            return Name::from(ip).to_string();
        }
    }

    query_name.to_string()
}

fn parse_record_type(record_type: &str) -> Result<RecordType, String> {
    match record_type {
        "A" => Ok(RecordType::A),
        "NS" => Ok(RecordType::NS),
        "CNAME" => Ok(RecordType::CNAME),
        "MX" => Ok(RecordType::MX),
        "TXT" => Ok(RecordType::TXT),
        "AAAA" => Ok(RecordType::AAAA),
        "SRV" => Ok(RecordType::SRV),
        "SOA" => Ok(RecordType::SOA),
        "PTR" => Ok(RecordType::PTR),
        "CAA" => Ok(RecordType::CAA),
        _ => Err(format!("Unsupported record type: {record_type}")),
    }
}

async fn check_dns_propagation(
    query_name: &str,
    record_type: RecordType,
    servers: &[Server],
) -> Result<(), CliError> {
    let mut tasks = JoinSet::new();
    let mut success_count = 0;

    for server in servers.iter().cloned() {
        let query_name = query_name.to_string();
        tasks.spawn(async move { query_server(&query_name, record_type, server).await });
    }

    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(Ok(message)) => {
                println!("{message}");
                success_count += 1;
            }
            Ok(Err(err)) => eprintln!("{err}"),
            Err(err) => eprintln!("Task failed: {err}"),
        }
    }

    if success_count == 0 {
        return Err(CliError::AllLookupsFailed);
    }

    Ok(())
}

async fn query_server(
    query_name: &str,
    record_type: RecordType,
    server: Server,
) -> Result<String, String> {
    let resolver = TokioResolver::builder_with_config(
        resolver_config_for_server(server.socket_addr),
        TokioConnectionProvider::default(),
    )
    .build();

    match resolver.lookup(query_name, record_type).await {
        Ok(response) => {
            let answer_str = response
                .iter()
                .map(|record| record.to_string())
                .collect::<Vec<_>>()
                .join("\n - ");

            Ok(format!(
                "Server {} ({}, {}) reports:\n - {}",
                server.socket_addr, server.provider, server.location, answer_str
            ))
        }
        Err(err) => Err(format!("Error querying {}: {:?}", server.socket_addr, err)),
    }
}

fn resolver_config_for_server(socket_addr: SocketAddr) -> ResolverConfig {
    let mut name_servers = NameServerConfigGroup::with_capacity(2);
    name_servers.push(NameServerConfig::new(socket_addr, Protocol::Udp));
    name_servers.push(NameServerConfig::new(socket_addr, Protocol::Tcp));
    ResolverConfig::from_parts(None, vec![], name_servers)
}
