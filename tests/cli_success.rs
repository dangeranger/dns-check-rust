mod support;

use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::net::Ipv4Addr;
use std::process::Command;
use support::{MockResolver, MockResponse, TEST_RESOLVERS_ENV};

#[test]
fn successful_a_lookup_reports_server_details() {
    let resolver = MockResolver::spawn(MockResponse::Address(Ipv4Addr::new(127, 0, 0, 1)));

    Command::cargo_bin("dns-check-rust")
        .unwrap()
        .env(TEST_RESOLVERS_ENV, resolver.socket_addr().to_string())
        .args(["example.com", "A"])
        .assert()
        .success()
        .stderr(predicate::str::is_empty())
        .stdout(
            predicate::str::contains(format!("Server {}", resolver.socket_addr()))
                .and(predicate::str::contains("Injected resolver"))
                .and(predicate::str::contains("Local test"))
                .and(predicate::str::contains("127.0.0.1")),
        );
}

#[test]
fn mixed_lookup_results_still_exit_successfully() {
    let resolver_success = MockResolver::spawn(MockResponse::Address(Ipv4Addr::new(127, 0, 0, 1)));
    let resolver_failure = MockResolver::spawn(MockResponse::NxDomain);

    Command::cargo_bin("dns-check-rust")
        .unwrap()
        .env(
            TEST_RESOLVERS_ENV,
            format!(
                "{},{}",
                resolver_success.socket_addr(),
                resolver_failure.socket_addr()
            ),
        )
        .args(["example.com", "A"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains(format!("Server {}", resolver_success.socket_addr()))
                .and(predicate::str::contains("127.0.0.1")),
        )
        .stderr(
            predicate::str::contains(format!("Error querying {}", resolver_failure.socket_addr()))
                .and(predicate::str::contains("NXDomain"))
                .and(predicate::str::contains("All DNS lookups failed.").not()),
        );
}

#[test]
fn ptr_lookup_normalizes_ip_inputs() {
    let resolver = MockResolver::spawn(MockResponse::Ptr("dns.google."));

    Command::cargo_bin("dns-check-rust")
        .unwrap()
        .env(TEST_RESOLVERS_ENV, resolver.socket_addr().to_string())
        .args(["8.8.8.8", "PTR"])
        .assert()
        .success()
        .stderr(predicate::str::is_empty())
        .stdout(predicate::str::contains("dns.google"));

    let queries = resolver.queries();
    assert!(queries.iter().any(|query| {
        query.record_type == hickory_proto::rr::RecordType::PTR
            && query.name == "8.8.8.8.in-addr.arpa."
    }));
    assert!(!queries.iter().any(|query| query.name == "8.8.8.8."));
}
