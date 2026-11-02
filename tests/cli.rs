use assert_cmd::Command;
use predicates::prelude::*;

fn sak() -> Command {
    Command::cargo_bin("sak").unwrap()
}

#[test]
fn merge_requires_output() {
    sak().arg("merge").assert().failure();
}

#[test]
fn merge_rejects_unknown_output_extension() {
    sak()
        .args(["merge", "-o", "out.zip"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(".nsp or .xci"));
}
