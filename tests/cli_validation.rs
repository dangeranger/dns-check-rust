mod support;

use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::net::Ipv4Addr;
use std::process::Command;
use support::{MockResolver, MockResponse, TEST_RESOLVERS_ENV};

#[test]
fn missing_args_exit_with_usage_error() {
    Command::cargo_bin("dns-check-rust")
        .unwrap()
        .assert()
        .failure()
        .code(2)
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains(
            "Usage: dns-check-rust <domain> <record_type>",
        ));
}

#[test]
fn unsupported_record_types_are_rejected_before_lookup() {
    let resolver = MockResolver::spawn(MockResponse::Address(Ipv4Addr::new(127, 0, 0, 1)));

    Command::cargo_bin("dns-check-rust")
        .unwrap()
        .env(TEST_RESOLVERS_ENV, resolver.socket_addr().to_string())
        .args(["example.com", "ANY"])
        .assert()
        .failure()
        .code(2)
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains("Unsupported record type: ANY"));

    assert!(resolver.queries().is_empty());
}

#[test]
fn malformed_injected_resolver_env_is_rejected_before_lookup() {
    let resolver = MockResolver::spawn(MockResponse::Address(Ipv4Addr::new(127, 0, 0, 1)));

    Command::cargo_bin("dns-check-rust")
        .unwrap()
        .env(
            TEST_RESOLVERS_ENV,
            format!("{},not-a-socket", resolver.socket_addr()),
        )
        .args(["example.com", "A"])
        .assert()
        .failure()
        .code(2)
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains(
            "Invalid DNS_CHECK_TEST_RESOLVERS entry: not-a-socket",
        ));

    assert!(resolver.queries().is_empty());
}

#[test]
fn empty_injected_resolver_env_is_rejected() {
    Command::cargo_bin("dns-check-rust")
        .unwrap()
        .env(TEST_RESOLVERS_ENV, " , ")
        .args(["example.com", "A"])
        .assert()
        .failure()
        .code(2)
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains(
            "DNS_CHECK_TEST_RESOLVERS must contain at least one ip:port entry",
        ));
}

#[test]
fn all_failed_lookups_exit_non_zero() {
    let resolver_a = MockResolver::spawn(MockResponse::NxDomain);
    let resolver_b = MockResolver::spawn(MockResponse::NxDomain);

    Command::cargo_bin("dns-check-rust")
        .unwrap()
        .env(
            TEST_RESOLVERS_ENV,
            format!("{},{}", resolver_a.socket_addr(), resolver_b.socket_addr()),
        )
        .args(["missing.example", "A"])
        .assert()
        .failure()
        .code(1)
        .stdout(predicate::str::is_empty())
        .stderr(
            predicate::str::contains(format!("Error querying {}", resolver_a.socket_addr()))
                .and(predicate::str::contains(format!(
                    "Error querying {}",
                    resolver_b.socket_addr()
                )))
                .and(predicate::str::contains("NXDomain"))
                .and(predicate::str::contains("All DNS lookups failed.")),
        );
}
