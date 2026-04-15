use crate::{CliError, QueryRequest, Server, TEST_RESOLVERS_ENV};
use hickory_resolver::proto::rr::{domain::Name, RecordType};
use std::env;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;

pub(crate) fn parse_request(
    args: &[String],
    resolver_env: Result<String, env::VarError>,
) -> Result<QueryRequest, CliError> {
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
    let servers = load_servers_from_env_result(resolver_env).map_err(CliError::Validation)?;

    Ok(QueryRequest {
        query_name,
        record_type,
        servers,
    })
}

fn binary_name(arg0: &str) -> String {
    Path::new(arg0)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("dns-check-rust")
        .to_string()
}

fn load_servers_from_env_result(
    resolver_env: Result<String, env::VarError>,
) -> Result<Vec<Server>, String> {
    match resolver_env {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    #[cfg(unix)]
    use std::os::unix::ffi::OsStringExt;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    #[test]
    fn parse_request_rejects_missing_args() {
        let error =
            parse_request(&args(&["dns-check-rust"]), Err(env::VarError::NotPresent)).unwrap_err();

        assert_eq!(
            error,
            CliError::Usage("Usage: dns-check-rust <domain> <record_type>".to_string())
        );
    }

    #[test]
    fn parse_request_rejects_empty_arg_list_using_default_binary_name() {
        let args = Vec::<String>::new();
        let error = parse_request(&args, Err(env::VarError::NotPresent)).unwrap_err();

        assert_eq!(
            error,
            CliError::Usage("Usage: dns-check-rust <domain> <record_type>".to_string())
        );
    }

    #[test]
    fn binary_name_uses_final_path_component() {
        assert_eq!(
            binary_name("/usr/local/bin/dns-check-rust"),
            "dns-check-rust"
        );
    }

    #[test]
    fn parse_request_accepts_supported_record_types() {
        let cases = [
            ("A", RecordType::A),
            ("NS", RecordType::NS),
            ("CNAME", RecordType::CNAME),
            ("MX", RecordType::MX),
            ("TXT", RecordType::TXT),
            ("AAAA", RecordType::AAAA),
            ("SRV", RecordType::SRV),
            ("SOA", RecordType::SOA),
            ("PTR", RecordType::PTR),
            ("CAA", RecordType::CAA),
        ];

        for (raw, expected) in cases {
            let request = parse_request(
                &args(&["dns-check-rust", "example.com", raw]),
                Err(env::VarError::NotPresent),
            )
            .unwrap();

            assert_eq!(request.record_type, expected, "{raw} should parse");
        }
    }

    #[test]
    fn parse_request_rejects_unsupported_record_type_before_env_validation() {
        let error = parse_request(
            &args(&["dns-check-rust", "example.com", "ANY"]),
            Ok("not-a-socket".to_string()),
        )
        .unwrap_err();

        assert_eq!(
            error,
            CliError::Validation("Unsupported record type: ANY".to_string())
        );
    }

    #[test]
    fn parse_request_normalizes_ipv4_ptr_queries() {
        let request = parse_request(
            &args(&["dns-check-rust", "8.8.8.8", "PTR"]),
            Err(env::VarError::NotPresent),
        )
        .unwrap();

        assert_eq!(request.query_name, "8.8.8.8.in-addr.arpa.");
    }

    #[test]
    fn parse_request_normalizes_ipv6_ptr_queries() {
        let request = parse_request(
            &args(&["dns-check-rust", "::1", "PTR"]),
            Err(env::VarError::NotPresent),
        )
        .unwrap();

        assert_eq!(
            request.query_name,
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa."
        );
    }

    #[test]
    fn parse_request_leaves_non_ip_ptr_queries_unchanged() {
        let request = parse_request(
            &args(&["dns-check-rust", "dns.google.", "PTR"]),
            Err(env::VarError::NotPresent),
        )
        .unwrap();

        assert_eq!(request.query_name, "dns.google.");
    }

    #[test]
    fn parse_request_leaves_non_ptr_queries_unchanged() {
        let request = parse_request(
            &args(&["dns-check-rust", "8.8.8.8", "A"]),
            Err(env::VarError::NotPresent),
        )
        .unwrap();

        assert_eq!(request.query_name, "8.8.8.8");
    }

    #[test]
    fn parse_request_uses_default_servers_when_env_is_missing() {
        let request = parse_request(
            &args(&["dns-check-rust", "example.com", "A"]),
            Err(env::VarError::NotPresent),
        )
        .unwrap();

        assert_eq!(request.servers, default_servers());
    }

    #[test]
    fn load_servers_parses_multiple_injected_resolvers() {
        let servers =
            load_servers_from_env_result(Ok("127.0.0.1:5300, 127.0.0.1:5301".to_string())).unwrap();

        assert_eq!(servers.len(), 2);
        assert_eq!(servers[0].socket_addr, "127.0.0.1:5300".parse().unwrap());
        assert_eq!(servers[1].socket_addr, "127.0.0.1:5301".parse().unwrap());
        assert!(servers
            .iter()
            .all(|server| server.provider == "Injected resolver"));
    }

    #[test]
    fn load_servers_rejects_invalid_injected_resolvers() {
        let error =
            load_servers_from_env_result(Ok("127.0.0.1:5300, invalid".to_string())).unwrap_err();

        assert_eq!(
            error,
            "Invalid DNS_CHECK_TEST_RESOLVERS entry: invalid".to_string()
        );
    }

    #[test]
    fn load_servers_rejects_empty_injected_resolver_lists() {
        let error = load_servers_from_env_result(Ok(" , ".to_string())).unwrap_err();

        assert_eq!(
            error,
            "DNS_CHECK_TEST_RESOLVERS must contain at least one ip:port entry".to_string()
        );
    }

    #[cfg(unix)]
    #[test]
    fn load_servers_reports_non_unicode_env_errors() {
        let error =
            load_servers_from_env_result(Err(env::VarError::NotUnicode(OsString::from_vec(vec![
                0xf0, 0x28, 0x8c, 0x28,
            ]))))
            .unwrap_err();

        assert!(error.starts_with("Failed to read DNS_CHECK_TEST_RESOLVERS:"));
    }
}
