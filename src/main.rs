use std::env;
use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    let report = dns_check_rust::execute(env::args().collect()).await;

    for line in report.stdout_lines {
        println!("{line}");
    }

    for line in report.stderr_lines {
        eprintln!("{line}");
    }

    ExitCode::from(report.exit_code)
}
