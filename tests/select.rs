mod common;

use common::{TitleKind, TitleSpec, build_nsp, build_nsp_two_rights, build_xci, test_keys_file};
use sak::keys::Keys;
use sak::select::{MergePlan, build_plan};
use std::fs;
use std::path::Path;

const BASE: u64 = 0x0100_0000_0000_0000;
const UPD: u64 = 0x0100_0000_0000_0800;
const DLC1: u64 = 0x0100_0000_0000_1001;
const DLC2: u64 = 0x0100_0000_0000_1002;

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

fn keys_in(_dir: &Path) -> Keys {
    let k = tempfile::tempdir().unwrap();
    Keys::load(&test_keys_file(k.path())).unwrap()
}

fn plan(dir: &Path) -> anyhow::Result<MergePlan> {
    build_plan(dir, &dir.join("out.nsp"), &keys_in(dir))
}
fn err(dir: &Path) -> String {
    format!("{:#}", plan(dir).unwrap_err())
}
fn ids(p: &MergePlan) -> Vec<u64> {
    p.titles.iter().map(|t| t.cnmt.title_id).collect()
}

#[test]
fn selects_highest_update_only() {
    let d = tempfile::tempdir().unwrap();
    build_nsp(&d.path().join("a.nsp"), &[base(), upd(0x10000)]);
    build_nsp(&d.path().join("b.nsp"), &[upd(0x20000)]);
    let p = plan(d.path()).unwrap();
    assert_eq!(p.base_title, BASE);
    assert_eq!(ids(&p), vec![BASE, UPD]);
    assert_eq!(p.titles[1].cnmt.version, 0x20000);
    assert_eq!(p.skipped.len(), 1);
    assert!(p.skipped[0].contains("a.nsp"), "{:?}", p.skipped);
    assert!(p.skipped[0].contains("0100000000000800"), "{:?}", p.skipped);
}

#[test]
fn dlc_and_update_all_selected() {
    let d = tempfile::tempdir().unwrap();
    build_nsp(&d.path().join("a.nsp"), &[spec(DLC2, TitleKind::AddOn, 0)]);
    build_nsp(&d.path().join("b.nsp"), &[spec(DLC1, TitleKind::AddOn, 0)]);
    build_nsp(&d.path().join("c.nsp"), &[upd(0x10000)]);
    build_xci(&d.path().join("d.xci"), &[base()]);
    let p = plan(d.path()).unwrap();
    assert_eq!(ids(&p), vec![BASE, UPD, DLC1, DLC2]);
    assert!(p.skipped.is_empty());
    for t in &p.titles {
        assert_eq!(t.ncas.len(), 1);
        assert!(t.meta.name.ends_with(".cnmt.nca"));
    }
}

#[test]
fn multi_title_file_contributes_all_titles() {
    let d = tempfile::tempdir().unwrap();
    build_nsp(
        &d.path().join("all.nsp"),
        &[base(), upd(0x10000), spec(DLC1, TitleKind::AddOn, 0)],
    );
    let p = plan(d.path()).unwrap();
    assert_eq!(ids(&p), vec![BASE, UPD, DLC1]);
}

#[test]
fn extension_match_ignores_case() {
    let d = tempfile::tempdir().unwrap();
    build_nsp(&d.path().join("A.NSP"), &[base()]);
    build_xci(&d.path().join("b.XcI"), &[upd(0x10000)]);
    assert_eq!(ids(&plan(d.path()).unwrap()), vec![BASE, UPD]);
}

#[test]
fn subfolders_are_ignored() {
    let d = tempfile::tempdir().unwrap();
    build_nsp(&d.path().join("a.nsp"), &[base()]);
    fs::create_dir(d.path().join("sub")).unwrap();
    build_nsp(&d.path().join("sub").join("b.nsp"), &[upd(0x10000)]);
    assert_eq!(ids(&plan(d.path()).unwrap()), vec![BASE]);
}

#[test]
fn appledouble_and_other_dotfiles_are_skipped() {
    let d = tempfile::tempdir().unwrap();
    build_nsp(&d.path().join("Game.nsp"), &[base()]);
    fs::write(d.path().join("._Game.nsp"), b"Mac resource fork, not PFS0").unwrap();
    fs::write(d.path().join("._Game.xci"), b"junk").unwrap();
    fs::write(d.path().join("._Game.nsz"), b"junk").unwrap();
    fs::write(d.path().join("._Game.ns0"), b"junk").unwrap();
    fs::create_dir(d.path().join(".Trash.nsp")).unwrap();
    assert_eq!(ids(&plan(d.path()).unwrap()), vec![BASE]);
}

#[test]
fn split_files_are_not_supported() {
    for name in ["Game.ns0", "Game.XC0"] {
        let d = tempfile::tempdir().unwrap();
        build_nsp(&d.path().join("a.nsp"), &[base()]);
        fs::write(d.path().join(name), b"x").unwrap();
        let e = err(d.path());
        assert!(e.contains("split files are not supported"), "{e}");
        assert!(e.contains(name), "{e}");
    }
}

#[test]
fn folder_named_like_an_input_is_a_split_file_error() {
    for name in ["Game.nsp", "Game.XCI"] {
        let d = tempfile::tempdir().unwrap();
        build_nsp(&d.path().join("a.nsp"), &[base()]);
        fs::create_dir(d.path().join(name)).unwrap();
        let e = err(d.path());
        assert!(e.contains("split files are not supported"), "{e}");
        assert!(e.contains(name), "{e}");
    }
}

#[test]
fn no_base_game_is_error() {
    let d = tempfile::tempdir().unwrap();
    build_nsp(&d.path().join("a.nsp"), &[upd(0x10000)]);
    assert!(err(d.path()).contains("no base game"));
}

#[test]
fn two_base_games_is_error() {
    let d = tempfile::tempdir().unwrap();
    let other = 0x0100_0000_0000_2000;
    build_nsp(&d.path().join("a.nsp"), &[base()]);
    build_nsp(
        &d.path().join("b.nsp"),
        &[spec(other, TitleKind::Application, 0)],
    );
    let e = err(d.path());
    assert!(e.contains("0100000000000000"), "{e}");
    assert!(e.contains("0100000000002000"), "{e}");
}

#[test]
fn foreign_update_is_error_listing_file() {
    let d = tempfile::tempdir().unwrap();
    build_nsp(&d.path().join("a.nsp"), &[base()]);
    let mut foreign = upd(0x10000);
    foreign.title_id = 0x0100_0000_0000_3800;
    foreign.base_id = 0x0100_0000_0000_3000;
    build_nsp(&d.path().join("other_update.nsp"), &[foreign]);
    let e = err(d.path());
    assert!(e.contains("other_update.nsp"), "{e}");
    assert!(e.contains("0100000000003800"), "{e}");
}

#[test]
fn missing_content_is_error_naming_nca() {
    // Meta from one file, content only in another: content must come from the same file.
    let d2 = tempfile::tempdir().unwrap();
    build_nsp(&d2.path().join("full.nsp"), &[base()]);
    let nca_name = sak::container::open_entries(&d2.path().join("full.nsp"))
        .unwrap()
        .into_iter()
        .find(|e| !e.name.ends_with(".cnmt.nca"))
        .unwrap()
        .name;
    // Rebuild the NSP without that NCA.
    let entries = sak::container::open_entries(&d2.path().join("full.nsp")).unwrap();
    let raw = fs::read(d2.path().join("full.nsp")).unwrap();
    let kept: Vec<(String, Vec<u8>)> = entries
        .iter()
        .filter(|e| e.name != nca_name)
        .map(|e| {
            (
                e.name.clone(),
                raw[e.offset as usize..(e.offset + e.size) as usize].to_vec(),
            )
        })
        .collect();
    let list: Vec<_> = kept
        .iter()
        .map(|(n, d)| (n.clone(), d.len() as u64))
        .collect();
    let mut out = sak::container::pfs0_header(&list);
    for (_, d) in &kept {
        out.extend_from_slice(d);
    }
    fs::write(d2.path().join("full.nsp"), out).unwrap();
    let e = err(d2.path());
    assert!(e.contains(nca_name.trim_end_matches(".nca")), "{e}");
    assert!(e.contains("full.nsp"), "{e}");
}

#[test]
fn content_size_differing_from_cnmt_is_error_naming_nca_and_file() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("full.nsp");
    build_nsp(&p, &[base()]);
    let nca = sak::container::open_entries(&p)
        .unwrap()
        .into_iter()
        .find(|e| !e.name.ends_with(".cnmt.nca"))
        .unwrap();
    let name = nca.name.clone();
    common::repack_nsp(&p, |n, data| {
        if n == name {
            data.truncate(data.len() - 0x200);
        }
    });
    let e = err(d.path());
    assert!(e.contains(name.trim_end_matches(".nca")), "{e}");
    assert!(e.contains("full.nsp"), "{e}");
    assert!(e.contains(&nca.size.to_string()), "{e}");
}

#[test]
fn compressed_input_is_skipped_and_reported() {
    let d = tempfile::tempdir().unwrap();
    build_nsp(&d.path().join("a.nsp"), &[base()]);
    fs::write(d.path().join("b.NSZ"), b"x").unwrap();
    fs::write(d.path().join("c.xcz"), b"x").unwrap();
    let p = plan(d.path()).unwrap();
    assert_eq!(p.titles.len(), 1);
    assert_eq!(p.skipped.len(), 2, "{:?}", p.skipped);
    assert!(p.skipped[0].contains("b.NSZ"), "{:?}", p.skipped);
    assert!(p.skipped[0].contains("compressed"), "{:?}", p.skipped);
    assert!(p.skipped[1].contains("c.xcz"), "{:?}", p.skipped);
}

#[test]
fn only_compressed_input_is_error_naming_compressed() {
    let d = tempfile::tempdir().unwrap();
    fs::write(d.path().join("b.nsz"), b"x").unwrap();
    let e = err(d.path());
    assert!(e.contains("compressed"), "{e}");
}

#[test]
fn delta_fragments_are_dropped() {
    let d = tempfile::tempdir().unwrap();
    let mut u = upd(0x10000);
    u.delta = true;
    build_nsp(&d.path().join("a.nsp"), &[base(), u]);
    let p = plan(d.path()).unwrap();
    // fixture adds one regular and one delta content to the update
    assert_eq!(p.titles[1].cnmt.contents.len(), 2);
    assert_eq!(p.titles[1].ncas.len(), 1);
}

#[test]
fn empty_folder_is_error() {
    let d = tempfile::tempdir().unwrap();
    assert!(err(d.path()).contains("no .nsp or .xci files"));
}

#[test]
fn output_and_stale_part_are_not_inputs() {
    let d = tempfile::tempdir().unwrap();
    build_nsp(&d.path().join("a.nsp"), &[base()]);
    // earlier output holds a duplicate base under another id, which would be an error if scanned
    build_nsp(
        &d.path().join("out.nsp"),
        &[spec(0x0100_0000_0000_9000, TitleKind::Application, 0)],
    );
    fs::write(d.path().join("out.nsp.part"), b"garbage").unwrap();
    let p = plan(d.path()).unwrap();
    assert_eq!(ids(&p), vec![BASE]);
}

#[test]
fn duplicate_title_across_files_is_deduplicated() {
    let d = tempfile::tempdir().unwrap();
    build_nsp(&d.path().join("a.nsp"), &[base(), upd(0x10000)]);
    build_xci(&d.path().join("b.xci"), &[base()]);
    build_nsp(&d.path().join("c.nsp"), &[upd(0x10000)]);
    let p = plan(d.path()).unwrap();
    assert_eq!(ids(&p), vec![BASE, UPD]);
    assert_eq!(p.skipped.len(), 2);
    assert!(p.skipped.iter().any(|s| s.contains("b.xci")));
    assert!(p.skipped.iter().any(|s| s.contains("c.nsp")));
    assert_eq!(p.titles[0].ncas[0].source, d.path().join("a.nsp"));
}

#[test]
fn tickets_are_matched_by_rights_id() {
    let d = tempfile::tempdir().unwrap();
    let mut b = base();
    b.rights_id = Some([0xAB; 16]);
    build_nsp(&d.path().join("a.nsp"), &[b, upd(0x10000)]);
    let p = plan(d.path()).unwrap();
    assert_eq!(p.titles[0].tickets.len(), 1);
    assert_eq!(
        p.titles[0].tickets[0].name,
        format!("{}.tik", "ab".repeat(16))
    );
    assert!(p.titles[1].tickets.is_empty());
}

#[test]
fn certs_are_attached_with_tickets() {
    let d = tempfile::tempdir().unwrap();
    let mut b = base();
    b.rights_id = Some([0xAB; 16]);
    build_nsp(&d.path().join("a.nsp"), &[b]);
    let t = &plan(d.path()).unwrap().titles[0];
    assert_eq!(t.tickets.len(), 1);
    assert_eq!(t.certs.len(), 1);
    assert_eq!(t.certs[0].name, format!("{}.cert", "ab".repeat(16)));
}

#[test]
fn two_rights_ids_give_both_tickets_and_certs() {
    let d = tempfile::tempdir().unwrap();
    let mut b = base();
    b.rights_id = Some([0xAB; 16]);
    build_nsp_two_rights(&d.path().join("a.nsp"), &b, [0xCD; 16]);
    let t = &plan(d.path()).unwrap().titles[0];
    let mut names: Vec<_> = t.tickets.iter().map(|e| e.name.clone()).collect();
    names.sort();
    assert_eq!(
        names,
        vec![
            format!("{}.tik", "ab".repeat(16)),
            format!("{}.tik", "cd".repeat(16))
        ]
    );
    assert_eq!(t.certs.len(), 2);
}

#[test]
fn titles_sharing_a_rights_id_each_list_the_ticket() {
    let d = tempfile::tempdir().unwrap();
    let mut b = base();
    b.rights_id = Some([0xAB; 16]);
    let mut u = upd(0x10000);
    u.rights_id = Some([0xAB; 16]);
    build_nsp(&d.path().join("a.nsp"), &[b, u]);
    let p = plan(d.path()).unwrap();
    for t in &p.titles {
        assert_eq!(t.tickets.len(), 1, "{:?}", t.cnmt.title_id);
        assert_eq!(t.certs.len(), 1);
    }
}

#[test]
fn corrupt_nca_in_any_input_stops_merge_naming_file() {
    let d = tempfile::tempdir().unwrap();
    build_nsp(&d.path().join("a.nsp"), &[base(), upd(0x20000)]);
    let bad = d.path().join("old_update.nsp");
    build_nsp(&bad, &[upd(0x10000)]);
    // corrupt the first entry's header (the content NCA) so it no longer decrypts
    let mut raw = fs::read(&bad).unwrap();
    let off = sak::container::open_entries(&bad).unwrap()[0].offset as usize;
    raw[off..off + 0xC00].fill(0x11);
    fs::write(&bad, raw).unwrap();
    let e = err(d.path());
    assert!(e.contains("old_update.nsp"), "{e}");
    assert!(!e.contains('\n'), "{e}");
}
