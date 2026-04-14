use hickory_resolver::config::*;
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::proto::rr::RecordType;
use hickory_resolver::TokioResolver;
use std::env;
use tokio::task::JoinSet;

#[derive(Clone)]
struct Server {
    ip: String,
    location: String,
    provider: String,
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 3 {
        println!("Usage: dnscheck <domain> <record_type>");
        return;
    }

    let domain = &args[1];
    let record_type = match parse_record_type(&args[2]) {
        Ok(record_type) => record_type,
        Err(err) => {
            eprintln!("{err}");
            return;
        }
    };

    let servers = vec![
        Server {
            ip: "8.8.8.8".to_string(),
            location: "Mountain View, California".to_string(),
            provider: "Google LLC".to_string(),
        },
        Server {
            ip: "1.1.1.1".to_string(),
            location: "San Francisco, California".to_string(),
            provider: "Cloudflare, Inc".to_string(),
        },
        // ... Add other servers as needed
    ];

    check_dns_propagation(domain, record_type, &servers).await;
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
        "ANY" => Ok(RecordType::ANY),
        _ => Err(format!("Unsupported record type: {record_type}")),
    }
}

async fn check_dns_propagation(domain: &str, record_type: RecordType, servers: &[Server]) {
    let mut tasks = JoinSet::new();

    for server in servers.iter().cloned() {
        let domain = domain.to_string();
        tasks.spawn(async move { query_server(&domain, record_type, server).await });
    }

    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(message) => println!("{message}"),
            Err(err) => eprintln!("Task failed: {err}"),
        }
    }
}

async fn query_server(domain: &str, record_type: RecordType, server: Server) -> String {
    let resolver_config = ResolverConfig::from_parts(
        None,
        vec![],
        NameServerConfigGroup::from_ips_clear(&[server.ip.parse().unwrap()], 53, true),
    );
    let resolver =
        TokioResolver::builder_with_config(resolver_config, TokioConnectionProvider::default())
            .build();

    match resolver.lookup(domain, record_type).await {
        Ok(response) => {
            let answer_str = response
                .iter()
                .map(|record| record.to_string())
                .collect::<Vec<_>>()
                .join("\n - ");
            format!(
                "Server {} ({}, {}) reports:\n - {}",
                server.ip, server.provider, server.location, answer_str
            )
        }
        Err(err) => format!("Error querying {}: {:?}", server.ip, err),
    }
}
