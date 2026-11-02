mod common;

use common::{HEADER_KEY, SECTION_KEY, TitleKind, TitleSpec, build_nsp, test_keys_file};
use sak::cnmt::read_cnmt;
use sak::container::{Entry, open_entries};
use sak::crypto::{ctr_apply, xts_decrypt, xts_encrypt};
use sak::keys::Keys;
use sak::nca::NcaHeader;
use std::path::Path;

fn spec(id: u64, kind: TitleKind) -> TitleSpec {
    TitleSpec {
        title_id: id,
        base_id: 0x0100_0000_0000_0000,
        version: 0x10000,
        kind,
        rights_id: None,
        delta: false,
    }
}

fn keys_in(dir: &Path) -> Keys {
    Keys::load(&test_keys_file(dir)).unwrap()
}

fn find<'a>(entries: &'a [Entry], suffix: &str) -> &'a Entry {
    entries.iter().find(|e| e.name.ends_with(suffix)).unwrap()
}

/// Build an NSP for one title; return its path and the meta NCA entry.
fn meta_nsp(dir: &Path, s: &TitleSpec) -> (std::path::PathBuf, Entry) {
    let p = dir.join("t.nsp");
    build_nsp(&p, std::slice::from_ref(s));
    let entries = open_entries(&p).unwrap();
    let meta = find(&entries, ".cnmt.nca").clone();
    (p, meta)
}

/// Decrypt the header of `e`, let `f` edit it, and write it back re-encrypted.
fn patch_header(path: &Path, e: &Entry, f: impl FnOnce(&mut [u8])) {
    let mut file = std::fs::read(path).unwrap();
    let range = e.offset as usize..e.offset as usize + 0xC00;
    xts_decrypt(&HEADER_KEY, &mut file[range.clone()], 0x200);
    f(&mut file[range.clone()]);
    xts_encrypt(&HEADER_KEY, &mut file[range], 0x200);
    std::fs::write(path, file).unwrap();
}

#[test]
fn reads_header_fields() {
    let dir = tempfile::tempdir().unwrap();
    let keys = keys_in(dir.path());
    let mut s = spec(0x0100_0000_0000_0800, TitleKind::Application);
    s.rights_id = None;
    let (p, meta) = meta_nsp(dir.path(), &s);
    let h = NcaHeader::read(&meta, &keys).unwrap();
    assert_eq!(h.content_type, 1);
    assert_eq!(h.master_index, 0);
    assert_eq!(h.kaek_index, 0);
    assert_eq!(h.rights_id, [0; 16]);
    assert_eq!(&h.plain[0x200..0x204], b"NCA3");

    let rid: [u8; 16] = core::array::from_fn(|i| 0xB0 + i as u8);
    patch_header(&p, &meta, |h| h[0x230..0x240].copy_from_slice(&rid));
    let h = NcaHeader::read(&meta, &keys).unwrap();
    assert_eq!(h.rights_id, rid);
}

#[test]
fn master_index_uses_higher_crypto_field() {
    let dir = tempfile::tempdir().unwrap();
    let keys = keys_in(dir.path());
    let (p, meta) = meta_nsp(
        dir.path(),
        &spec(0x0100_0000_0000_0800, TitleKind::Application),
    );
    for (c1, c2, expect) in [(2u8, 5u8, 4u8), (7, 3, 6), (0x0b, 0x0b, 0x0a)] {
        patch_header(&p, &meta, |h| {
            h[0x206] = c1;
            h[0x220] = c2;
        });
        assert_eq!(NcaHeader::read(&meta, &keys).unwrap().master_index, expect);
    }
}

#[test]
fn gen_zero_and_one_both_map_to_master_zero() {
    let dir = tempfile::tempdir().unwrap();
    let keys = keys_in(dir.path());
    let (p, meta) = meta_nsp(
        dir.path(),
        &spec(0x0100_0000_0000_0800, TitleKind::Application),
    );
    for gen_ in [0u8, 1] {
        patch_header(&p, &meta, |h| {
            h[0x206] = gen_;
            h[0x220] = 0;
        });
        assert_eq!(NcaHeader::read(&meta, &keys).unwrap().master_index, 0);
    }
}

#[test]
fn kaek_index_above_two_is_error() {
    let dir = tempfile::tempdir().unwrap();
    let keys = keys_in(dir.path());
    let (p, meta) = meta_nsp(
        dir.path(),
        &spec(0x0100_0000_0000_0800, TitleKind::Application),
    );
    patch_header(&p, &meta, |h| h[0x207] = 3);
    let err = format!("{:#}", NcaHeader::read(&meta, &keys).unwrap_err());
    assert!(err.contains("key area key index"), "{err}");
}

#[test]
fn reads_each_cnmt_type() {
    for (kind, id, base) in [
        (
            TitleKind::Application,
            0x0100_0000_0000_1000u64,
            0x0100_0000_0000_1000u64,
        ),
        (
            TitleKind::Patch,
            0x0100_0000_0000_1800,
            0x0100_0000_0000_1000,
        ),
        (
            TitleKind::AddOn,
            0x0100_0000_0000_1001,
            0x0100_0000_0000_1000,
        ),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let keys = keys_in(dir.path());
        let mut s = spec(id, kind);
        s.base_id = base;
        s.delta = true;
        let (_p, meta) = meta_nsp(dir.path(), &s);
        let header = NcaHeader::read(&meta, &keys).unwrap();
        let c = read_cnmt(&meta, &header, &keys).unwrap();
        assert_eq!(c.title_id, id);
        assert_eq!(c.version, 0x10000);
        assert_eq!(c.kind, kind);
        assert_eq!(c.base_id, base, "{kind:?}");
        assert_eq!(c.contents.len(), 2);
        assert_eq!(c.contents[0].kind, 1);
        assert_eq!(c.contents[1].kind, 6);
        assert_eq!(c.contents[0].nca_id.len(), 32);
        assert!(
            c.contents[0]
                .nca_id
                .chars()
                .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase())
        );
        assert!(c.contents[0].size > 0xC00);
    }
}

#[test]
fn wrong_header_key_gives_error_naming_file() {
    let dir = tempfile::tempdir().unwrap();
    let (_p, meta) = meta_nsp(
        dir.path(),
        &spec(0x0100_0000_0000_0800, TitleKind::Application),
    );
    let path = test_keys_file(dir.path());
    let text = std::fs::read_to_string(&path).unwrap();
    let wrong = text.replacen(&hex::encode(HEADER_KEY), &hex::encode([0x11u8; 32]), 1);
    assert_ne!(text, wrong);
    std::fs::write(&path, wrong).unwrap();
    let keys = Keys::load(&path).unwrap();
    let err = format!("{:#}", NcaHeader::read(&meta, &keys).unwrap_err());
    assert!(err.contains(&meta.name), "{err}");
    assert!(err.contains("keys"), "{err}");
    assert!(err.contains("NCA3"), "{err}");
}

#[test]
fn corrupt_cnmt_length_is_error_not_panic() {
    let dir = tempfile::tempdir().unwrap();
    let keys = keys_in(dir.path());
    let id = 0x0100_0000_0000_0800u64;
    let (p, meta) = meta_nsp(dir.path(), &spec(id, TitleKind::Application));
    // Body is CTR-encrypted from 0xC00; set the cnmt content count to 0xFFFF.
    let mut file = std::fs::read(&p).unwrap();
    let start = meta.offset as usize + 0xC00;
    let end = meta.offset as usize + meta.size as usize;
    let mut ctr_high = id.to_le_bytes();
    ctr_high.reverse();
    ctr_apply(&SECTION_KEY, ctr_high, 0xC00, &mut file[start..end]);
    let pos = file[start..end]
        .windows(8)
        .position(|w| w == id.to_le_bytes())
        .unwrap();
    file[start + pos + 0x10..start + pos + 0x12].copy_from_slice(&0xFFFFu16.to_le_bytes());
    ctr_apply(&SECTION_KEY, ctr_high, 0xC00, &mut file[start..end]);
    std::fs::write(&p, file).unwrap();

    let header = NcaHeader::read(&meta, &keys).unwrap();
    let err = format!("{:#}", read_cnmt(&meta, &header, &keys).unwrap_err());
    assert!(err.contains(&meta.name), "{err}");
}
