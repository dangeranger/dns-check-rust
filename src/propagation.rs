use crate::{CliError, QueryRequest, RunReport, Server};
use hickory_resolver::config::{NameServerConfig, NameServerConfigGroup, ResolverConfig};
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::proto::rr::RecordType;
use hickory_resolver::proto::xfer::Protocol;
use hickory_resolver::TokioResolver;
use std::future::Future;
use std::net::SocketAddr;
use tokio::task::JoinSet;

pub(crate) async fn execute_request(request: QueryRequest) -> RunReport {
    execute_request_with_lookup(request, |query_name, record_type, server| async move {
        query_server(&query_name, record_type, server).await
    })
    .await
}

pub(crate) async fn execute_request_with_lookup<F, Fut>(
    request: QueryRequest,
    lookup: F,
) -> RunReport
where
    F: Fn(String, RecordType, Server) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = Result<String, String>> + Send + 'static,
{
    let mut tasks = JoinSet::new();
    let mut report = RunReport::default();

    for server in request.servers {
        let query_name = request.query_name.clone();
        let record_type = request.record_type;
        let lookup = lookup.clone();

        tasks.spawn(async move { lookup(query_name, record_type, server).await });
    }

    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(Ok(message)) => report.stdout_lines.push(message),
            Ok(Err(err)) => report.stderr_lines.push(err),
            Err(err) => report.stderr_lines.push(format!("Task failed: {err}")),
        }
    }

    if report.stdout_lines.is_empty() {
        report
            .stderr_lines
            .push(CliError::AllLookupsFailed.to_string());
        report.exit_code = CliError::AllLookupsFailed.exit_code();
    }

    report
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

pub(crate) fn resolver_config_for_server(socket_addr: SocketAddr) -> ResolverConfig {
    let mut name_servers = NameServerConfigGroup::with_capacity(2);
    name_servers.push(NameServerConfig::new(socket_addr, Protocol::Udp));
    name_servers.push(NameServerConfig::new(socket_addr, Protocol::Tcp));
    ResolverConfig::from_parts(None, vec![], name_servers)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_request(providers: &[&str]) -> QueryRequest {
        QueryRequest {
            query_name: "example.com".to_string(),
            record_type: RecordType::A,
            servers: providers
                .iter()
                .enumerate()
                .map(|(index, provider)| Server {
                    socket_addr: SocketAddr::from(([127, 0, 0, 1], 5300 + index as u16)),
                    provider: (*provider).to_string(),
                    location: format!("Location {provider}"),
                })
                .collect(),
        }
    }

    #[tokio::test]
    async fn execute_request_collects_all_successes() {
        let report = execute_request_with_lookup(
            test_request(&["success-a", "success-b"]),
            |query_name, record_type, server| async move {
                Ok(format!(
                    "success:{}:{query_name}:{record_type:?}",
                    server.provider
                ))
            },
        )
        .await;

        assert_eq!(report.exit_code, 0);
        assert_eq!(report.stderr_lines, Vec::<String>::new());
        assert_eq!(report.stdout_lines.len(), 2);
        assert!(report
            .stdout_lines
            .iter()
            .any(|line| line.contains("success:success-a")));
        assert!(report
            .stdout_lines
            .iter()
            .any(|line| line.contains("success:success-b")));
    }

    #[tokio::test]
    async fn execute_request_keeps_success_when_some_lookups_fail() {
        let report = execute_request_with_lookup(
            test_request(&["success", "error"]),
            |query_name, _, server| async move {
                match server.provider.as_str() {
                    "success" => Ok(format!("resolved:{}:{query_name}", server.socket_addr)),
                    "error" => Err(format!("Error querying {}: NXDomain", server.socket_addr)),
                    other => unreachable!("unexpected provider {other}"),
                }
            },
        )
        .await;

        assert_eq!(report.exit_code, 0);
        assert_eq!(report.stdout_lines.len(), 1);
        assert_eq!(report.stderr_lines.len(), 1);
        assert!(report.stdout_lines[0].contains("resolved:127.0.0.1:5300:example.com"));
        assert!(report.stderr_lines[0].contains("Error querying 127.0.0.1:5301: NXDomain"));
    }

    #[tokio::test]
    async fn execute_request_reports_all_failures() {
        let report = execute_request_with_lookup(
            test_request(&["error-a", "error-b"]),
            |_, _, server| async move {
                Err(format!("Error querying {}: NXDomain", server.socket_addr))
            },
        )
        .await;

        assert_eq!(report.exit_code, 1);
        assert_eq!(report.stdout_lines, Vec::<String>::new());
        assert_eq!(report.stderr_lines.len(), 3);
        assert!(report
            .stderr_lines
            .iter()
            .any(|line| line.contains("Error querying 127.0.0.1:5300: NXDomain")));
        assert!(report
            .stderr_lines
            .iter()
            .any(|line| line.contains("Error querying 127.0.0.1:5301: NXDomain")));
        assert_eq!(
            report.stderr_lines.last().unwrap(),
            "All DNS lookups failed."
        );
    }

    #[tokio::test]
    async fn execute_request_keeps_success_when_a_task_panics() {
        let report = execute_request_with_lookup(
            test_request(&["panic", "success"]),
            |query_name, _, server| async move {
                match server.provider.as_str() {
                    "panic" => {
                        panic!(
                            "synthetic lookup panic for test provider at {}",
                            server.socket_addr
                        )
                    }
                    "success" => Ok(format!("resolved:{}:{query_name}", server.socket_addr)),
                    other => unreachable!("unexpected provider {other}"),
                }
            },
        )
        .await;

        assert_eq!(report.exit_code, 0);
        assert_eq!(report.stdout_lines.len(), 1);
        assert_eq!(report.stderr_lines.len(), 1);
        assert!(report.stdout_lines[0].contains("resolved:127.0.0.1:5301:example.com"));
        assert!(report.stderr_lines[0].starts_with("Task failed:"));
    }

    #[tokio::test]
    async fn execute_request_reports_all_failed_when_errors_and_panics_leave_no_successes() {
        let report = execute_request_with_lookup(
            test_request(&["panic", "error"]),
            |_, _, server| async move {
                match server.provider.as_str() {
                    "panic" => {
                        panic!(
                            "synthetic lookup panic for test provider at {}",
                            server.socket_addr
                        )
                    }
                    "error" => Err(format!("Error querying {}: NXDomain", server.socket_addr)),
                    other => unreachable!("unexpected provider {other}"),
                }
            },
        )
        .await;

        assert_eq!(report.exit_code, 1);
        assert_eq!(report.stdout_lines, Vec::<String>::new());
        assert_eq!(report.stderr_lines.len(), 3);
        assert!(report
            .stderr_lines
            .iter()
            .any(|line| line.starts_with("Task failed:")));
        assert!(report
            .stderr_lines
            .iter()
            .any(|line| line.contains("Error querying 127.0.0.1:5301: NXDomain")));
        assert_eq!(
            report.stderr_lines.last().unwrap(),
            "All DNS lookups failed."
        );
    }

    #[test]
    fn resolver_config_uses_udp_and_tcp_for_the_same_socket() {
        let socket_addr: SocketAddr = "127.0.0.1:5300".parse().unwrap();
        let config = resolver_config_for_server(socket_addr);
        let name_servers = config.name_servers();

        assert_eq!(name_servers.len(), 2);
        assert_eq!(name_servers[0].socket_addr, socket_addr);
        assert_eq!(name_servers[0].protocol, Protocol::Udp);
        assert_eq!(name_servers[1].socket_addr, socket_addr);
        assert_eq!(name_servers[1].protocol, Protocol::Tcp);
    }
}
