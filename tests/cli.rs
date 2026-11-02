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

mod common;

use common::{TitleKind, TitleSpec, build_nsp, test_keys_file};
use sak::container::{Entry, open_entries, pfs0_header};
use std::fs;
use std::path::{Path, PathBuf};

const BASE: u64 = 0x0100_0000_0000_0000;
const UPD: u64 = 0x0100_0000_0000_0800;

fn spec(id: u64, kind: TitleKind, version: u32) -> TitleSpec {
    TitleSpec {
        title_id: id,
        base_id: BASE,
        version,
        kind,
        rights_id: None,
        delta: false,
        key_gen: 3,
    }
}
fn base() -> TitleSpec {
    spec(BASE, TitleKind::Application, 0)
}
fn upd(v: u32) -> TitleSpec {
    spec(UPD, TitleKind::Patch, v)
}

/// A work folder holding inputs, plus a separate folder for the keys file.
struct Work {
    dir: tempfile::TempDir,
    keys: tempfile::TempDir,
}
impl Work {
    fn new() -> Work {
        Work {
            dir: tempfile::tempdir().unwrap(),
            keys: tempfile::tempdir().unwrap(),
        }
    }
    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }
    fn merge(&self, out: &str) -> assert_cmd::Command {
        let keys = test_keys_file(self.keys.path());
        let mut c = sak();
        c.current_dir(self.dir.path())
            .args(["merge", "-o", out, "--keys"])
            .arg(keys);
        c
    }
}

fn read_entry(e: &Entry) -> Vec<u8> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = fs::File::open(&e.source).unwrap();
    f.seek(SeekFrom::Start(e.offset)).unwrap();
    let mut buf = vec![0u8; e.size as usize];
    f.read_exact(&mut buf).unwrap();
    buf
}

fn names(path: &Path) -> Vec<String> {
    open_entries(path)
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect()
}

#[test]
fn nsp_output_contains_selected_files_byte_identical() {
    let w = Work::new();
    let mut b = base();
    b.rights_id = Some([0xAB; 16]);
    build_nsp(&w.path("a.nsp"), &[b, upd(0x10000)]);
    w.merge("out.nsp").assert().success();
    let src = open_entries(&w.path("a.nsp")).unwrap();
    let out = open_entries(&w.path("out.nsp")).unwrap();
    assert_eq!(out.len(), src.len());
    for e in &out {
        let s = src.iter().find(|s| s.name == e.name).unwrap();
        assert_eq!(read_entry(e), read_entry(s), "{}", e.name);
    }
}

#[test]
fn nsp_excludes_old_update_and_delta() {
    let w = Work::new();
    build_nsp(&w.path("a.nsp"), &[base(), upd(0x10000)]);
    let mut u2 = upd(0x20000);
    u2.delta = true;
    build_nsp(&w.path("b.nsp"), &[u2]);
    w.merge("out.nsp").assert().success();
    let old = names(&w.path("a.nsp"));
    let new = names(&w.path("b.nsp")); // [content, delta, meta]
    let out = names(&w.path("out.nsp"));
    assert_eq!(out.len(), 4, "{out:?}");
    assert!(!out.contains(&old[2]), "old update meta present");
    assert!(!out.contains(&old[3]), "old update content present");
    assert!(!out.contains(&new[1]), "delta fragment present");
    assert!(out.contains(&new[0]) && out.contains(&new[2]));
}

#[test]
fn nsp_includes_tik_and_cert_once() {
    let w = Work::new();
    let mut b = base();
    b.rights_id = Some([0xAB; 16]);
    let mut u = upd(0x10000);
    u.rights_id = Some([0xAB; 16]);
    build_nsp(&w.path("a.nsp"), &[b, u]);
    w.merge("out.nsp").assert().success();
    let out = names(&w.path("out.nsp"));
    let rid = "ab".repeat(16);
    assert_eq!(
        out.iter().filter(|n| **n == format!("{rid}.tik")).count(),
        1
    );
    assert_eq!(
        out.iter().filter(|n| **n == format!("{rid}.cert")).count(),
        1
    );
    let mut sorted = out.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), out.len());
}

fn title_lines(stdout: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(stdout)
        .lines()
        .filter(|l| l.contains("base game") || l.contains("update") || l.contains("DLC"))
        .filter(|l| !l.contains("superseded") && !l.contains("already have"))
        .map(|l| l.trim().to_string())
        .collect()
}

#[test]
fn nsp_output_merges_again() {
    let w = Work::new();
    build_nsp(&w.path("a.nsp"), &[base(), upd(0x10000)]);
    let first = w
        .merge("out.nsp")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let w2 = Work::new();
    fs::copy(w.path("out.nsp"), w2.path("only.nsp")).unwrap();
    let second = w2
        .merge("again.nsp")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let t = title_lines(&first);
    assert_eq!(t.len(), 2, "{t:?}");
    assert_eq!(t, title_lines(&second));
    assert_eq!(names(&w2.path("again.nsp")), names(&w.path("out.nsp")));
}

#[test]
fn refuses_existing_output_without_force() {
    let w = Work::new();
    build_nsp(&w.path("a.nsp"), &[base()]);
    fs::write(w.path("out.nsp"), b"precious").unwrap();
    w.merge("out.nsp").assert().failure().stderr(
        predicate::str::contains("already exists").and(predicate::str::contains("--force")),
    );
    assert_eq!(fs::read(w.path("out.nsp")).unwrap(), b"precious");
    assert!(!w.path("out.nsp.part").exists());
}

#[test]
fn force_overwrites() {
    let w = Work::new();
    build_nsp(&w.path("a.nsp"), &[base()]);
    fs::write(w.path("out.nsp"), b"old").unwrap();
    fs::write(w.path("out.nsp.part"), b"stale").unwrap();
    w.merge("out.nsp").arg("--force").assert().success();
    assert_eq!(names(&w.path("out.nsp")), names(&w.path("a.nsp")));
    assert!(!w.path("out.nsp.part").exists());
}

#[test]
fn failed_run_leaves_no_part_file() {
    let w = Work::new();
    // no inputs: the run fails
    w.merge("out.nsp").assert().failure();
    assert!(!w.path("out.nsp").exists());
    assert!(!w.path("out.nsp.part").exists());
}

#[test]
fn write_atomic_removes_part_when_writer_fails() {
    let d = tempfile::tempdir().unwrap();
    let out = d.path().join("o.nsp");
    let r = sak::write_atomic(&out, false, 10, |f| {
        use std::io::Write;
        f.write_all(b"abc")?;
        anyhow::bail!("boom")
    });
    let msg = format!("{:#}", r.unwrap_err());
    assert!(msg.contains("o.nsp.part"), "{msg}");
    assert!(msg.contains("boom"), "{msg}");
    assert!(!out.exists());
    assert!(!d.path().join("o.nsp.part").exists());
}

#[test]
fn write_atomic_renames_on_success() {
    let d = tempfile::tempdir().unwrap();
    let out = d.path().join("o.nsp");
    sak::write_atomic(&out, false, 3, |f| {
        use std::io::Write;
        f.write_all(b"abc")?;
        Ok(())
    })
    .unwrap();
    assert_eq!(fs::read(&out).unwrap(), b"abc");
    assert!(!d.path().join("o.nsp.part").exists());
}

#[test]
fn write_atomic_errors_when_space_is_short() {
    let d = tempfile::tempdir().unwrap();
    let out = d.path().join("o.nsp");
    let e = sak::write_atomic(&out, false, u64::MAX, |_| Ok(())).unwrap_err();
    assert!(format!("{e:#}").contains("not enough free space"), "{e:#}");
    assert!(!d.path().join("o.nsp.part").exists());
}

#[test]
fn prints_found_titles() {
    let w = Work::new();
    build_nsp(&w.path("a.nsp"), &[base(), upd(0x10000)]);
    build_nsp(&w.path("b.nsp"), &[upd(0x20000)]);
    w.merge("out.nsp").assert().success().stdout(
        predicate::str::contains("base game 0100000000000000 version 0")
            .and(predicate::str::contains(
                "update 0100000000000800 version 131072",
            ))
            .and(predicate::str::contains("a.nsp"))
            .and(predicate::str::contains("out.nsp")),
    );
}

#[test]
fn missing_ticket_is_error_naming_rights_id() {
    let w = Work::new();
    let mut b = base();
    b.rights_id = Some([0xAB; 16]);
    build_nsp(&w.path("full.nsp"), &[b]);
    // rebuild without the ticket and cert
    let kept: Vec<(String, Vec<u8>)> = open_entries(&w.path("full.nsp"))
        .unwrap()
        .iter()
        .filter(|e| !e.name.ends_with(".tik") && !e.name.ends_with(".cert"))
        .map(|e| (e.name.clone(), read_entry(e)))
        .collect();
    fs::remove_file(w.path("full.nsp")).unwrap();
    let list: Vec<_> = kept
        .iter()
        .map(|(n, d)| (n.clone(), d.len() as u64))
        .collect();
    let mut raw = pfs0_header(&list);
    for (_, d) in &kept {
        raw.extend_from_slice(d);
    }
    fs::write(w.path("noticket.nsp"), raw).unwrap();
    w.merge("out.nsp")
        .assert()
        .failure()
        .stderr(predicate::str::contains("ab".repeat(16)));
    assert!(!w.path("out.nsp").exists());
    assert!(!w.path("out.nsp.part").exists());
}

#[test]
fn missing_output_folder_is_error_naming_path() {
    let w = Work::new();
    build_nsp(&w.path("a.nsp"), &[base()]);
    w.merge("nope/out.nsp")
        .assert()
        .failure()
        .stderr(predicate::str::contains("nope"));
    assert!(!w.path("nope").exists());
}

#[cfg(unix)]
#[test]
fn read_only_output_folder_is_error() {
    use std::os::unix::fs::PermissionsExt;
    let w = Work::new();
    build_nsp(&w.path("a.nsp"), &[base()]);
    let ro = w.path("ro");
    fs::create_dir(&ro).unwrap();
    fs::set_permissions(&ro, fs::Permissions::from_mode(0o555)).unwrap();
    // root ignores permissions: probe for real, and skip visibly
    if fs::write(ro.join("probe"), b"x").is_ok() {
        eprintln!(
            "SKIPPED read_only_output_folder_is_error: folder is writable (running as root?)"
        );
        fs::set_permissions(&ro, fs::Permissions::from_mode(0o755)).unwrap();
        return;
    }
    w.merge("ro/out.nsp")
        .assert()
        .failure()
        .stderr(predicate::str::contains("ro/out.nsp.part"));
    assert_eq!(fs::read_dir(&ro).unwrap().count(), 0);
    fs::set_permissions(&ro, fs::Permissions::from_mode(0o755)).unwrap();
}
