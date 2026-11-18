//! Smoke test of the `warca` binary: init, import, list, edit, export, verify.

use std::fs;
use std::process::{Command, Output};

const PASS: &str = "correct horse battery staple";

fn warca(vault: &std::path::Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_warca"))
        .arg("--vault")
        .arg(vault)
        .args(args)
        .env("WARCA_PASSPHRASE", PASS)
        .env_remove("WARCA_NEW_PASSPHRASE")
        .output()
        .expect("run warca")
}

fn ok(out: Output) -> String {
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        out.status.success(),
        "warca failed\nstdout:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    stdout
}

#[test]
fn end_to_end() {
    let tmp = tempfile::tempdir().unwrap();
    let vault = tmp.path().join("my.vault");
    let pdf = tmp.path().join("Lease.pdf");
    fs::write(&pdf, "%PDF-1.4\n% synthetic lease\n%%EOF\n").unwrap();

    let out = ok(warca(&vault, &["init", "--insecure-fast-kdf"]));
    assert!(out.contains("RECOVERY PHRASE"));
    assert!(out.contains("24."));

    let out = ok(warca(
        &vault,
        &["import", "--tag", "home", pdf.to_str().unwrap()],
    ));
    assert!(out.contains("1 imported, 0 duplicates, 0 failed"), "{out}");
    let id = out.split_whitespace().nth(1).unwrap().to_string();

    let out = ok(warca(&vault, &["import", pdf.to_str().unwrap()]));
    assert!(out.contains("0 imported, 1 duplicates"), "{out}");

    ok(warca(
        &vault,
        &[
            "edit",
            &id,
            "--title",
            "Flat lease 2026",
            "--add-tag",
            "contract",
        ],
    ));
    let out = ok(warca(&vault, &["list", "--tag", "contract"]));
    assert!(
        out.contains("Flat lease 2026") && out.contains("1 document(s)"),
        "{out}"
    );

    let exported = tmp.path().join("out.pdf");
    ok(warca(&vault, &["export", &id, exported.to_str().unwrap()]));
    assert_eq!(fs::read(&exported).unwrap(), fs::read(&pdf).unwrap());

    assert!(ok(warca(&vault, &["verify"])).contains("1 of 1 document(s) verified"));

    let bad = Command::new(env!("CARGO_BIN_EXE_warca"))
        .arg("--vault")
        .arg(&vault)
        .arg("list")
        .env("WARCA_PASSPHRASE", "not the passphrase")
        .output()
        .unwrap();
    assert!(!bad.status.success());
    assert!(String::from_utf8_lossy(&bad.stderr).contains("wrong passphrase"));
}
