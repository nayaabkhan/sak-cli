mod common;

use common::{TitleKind, TitleSpec, build_nsp, build_xci};
use sak::container::{Entry, HfsFile, hfs0_header, open_entries, pfs0_header};
use sha2::{Digest, Sha256};
use std::fs;

fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
fn u64_at(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

fn read(e: &Entry) -> Vec<u8> {
    let d = fs::read(&e.source).unwrap();
    d[e.offset as usize..(e.offset + e.size) as usize].to_vec()
}

fn spec(id: u64, kind: TitleKind) -> TitleSpec {
    TitleSpec {
        title_id: id,
        base_id: id & !0xfff,
        version: 0,
        kind,
        rights_id: None,
        delta: false,
        key_gen: 3,
    }
}

#[test]
fn pfs0_header_matches_upstream_layout() {
    let h = pfs0_header(&[("a.bin".into(), 5), ("bb".into(), 0x10)]);
    // 0x10 + 2*0x18 + 9 bytes of names = 0x49, padded by 7 to 0x50
    assert_eq!(&h[..4], b"PFS0");
    assert_eq!(u32_at(&h, 4), 2);
    assert_eq!(u32_at(&h, 8), 16);
    assert_eq!(u32_at(&h, 12), 0);
    assert_eq!(h.len(), 0x50);
    assert_eq!(h.len() % 0x10, 0);
    assert_eq!((u64_at(&h, 0x10), u64_at(&h, 0x18)), (0, 5));
    assert_eq!(u32_at(&h, 0x20), 0);
    assert_eq!((u64_at(&h, 0x28), u64_at(&h, 0x30)), (5, 0x10));
    assert_eq!(u32_at(&h, 0x38), 6);
    assert_eq!(&h[0x40..0x49], b"a.bin\0bb\0");
    assert!(h[0x49..].iter().all(|&b| b == 0));

    // already aligned: 0x10 + 0x30 + 16 name bytes still gains 16 padding bytes
    let h = pfs0_header(&[("abcdefg".into(), 1), ("abcdefh".into(), 1)]);
    assert_eq!(u32_at(&h, 8), 32);
    assert_eq!(h.len(), 0x60);
}

#[test]
fn pfs0_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("x.nsp");
    let mut data = pfs0_header(&[("one.bin".into(), 3), ("two.bin".into(), 4)]);
    data.extend_from_slice(b"abcdefg");
    fs::write(&path, &data).unwrap();
    let es = open_entries(&path).unwrap();
    assert_eq!(es.len(), 2);
    assert_eq!(es[0].name, "one.bin");
    assert_eq!(es[0].source, path);
    assert_eq!(read(&es[0]), b"abc");
    assert_eq!(es[1].name, "two.bin");
    assert_eq!(read(&es[1]), b"defg");
}

#[test]
fn hfs0_round_trip_absolute_offsets() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("g.xci");
    let specs = [
        spec(0x0100_0000_0000_1000, TitleKind::Application),
        TitleSpec {
            delta: true,
            ..spec(0x0100_0000_0000_1800, TitleKind::Patch)
        },
    ];
    build_xci(&path, &specs);
    let es = open_entries(&path).unwrap();
    // 2 titles: (content + meta) and (content + delta + meta)
    assert_eq!(es.len(), 5);
    for e in &es {
        assert_eq!(e.source, path);
        let bytes = read(e);
        let id = hex::encode(&Sha256::digest(&bytes)[..16]);
        assert!(e.name.starts_with(&id), "{} not at its offset", e.name);
    }
    assert!(es.iter().any(|e| e.name.ends_with(".cnmt.nca")));

    // same through an NSP of the same titles
    let nsp = dir.path().join("g.nsp");
    build_nsp(&nsp, &specs);
    let mut a: Vec<_> = es.iter().map(|e| (e.name.clone(), read(e))).collect();
    let mut b: Vec<_> = open_entries(&nsp)
        .unwrap()
        .iter()
        .map(|e| (e.name.clone(), read(e)))
        .collect();
    a.sort();
    b.sort();
    assert_eq!(a, b);
}

#[test]
fn hfs0_header_is_0x200_aligned() {
    let f = |n: &str| HfsFile {
        name: n.into(),
        size: 9,
        hash_size: 0x200,
        hash: [7; 32],
    };
    for n in [0usize, 1, 3, 20] {
        let files: Vec<_> = (0..n).map(|i| f(&format!("file{i}.nca"))).collect();
        let h = hfs0_header(&files);
        assert_eq!(&h[..4], b"HFS0");
        assert_eq!(h.len() % 0x200, 0, "{n} files");
        assert_eq!(u32_at(&h, 4) as usize, n);
        assert_eq!(0x10 + 0x40 * n + u32_at(&h, 8) as usize, h.len());
    }
    let h = hfs0_header(&[f("a"), f("b")]);
    assert_eq!(u64_at(&h, 0x10), 0);
    assert_eq!(u64_at(&h, 0x18), 9);
    assert_eq!(u32_at(&h, 0x24), 0x200);
    assert_eq!(&h[0x30..0x50], &[7u8; 32]);
    assert_eq!(u64_at(&h, 0x50), 9);
    assert_eq!(u32_at(&h, 0x60), 2);
}

#[test]
fn truncated_pfs0_is_error_naming_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cut.nsp");
    let h = pfs0_header(&[("a".into(), 1), ("b".into(), 1), ("c".into(), 1)]);
    fs::write(&path, &h[..0x30]).unwrap();
    let err = open_entries(&path).unwrap_err();
    assert!(format!("{err:#}").contains("cut.nsp"), "{err:#}");
}

#[test]
fn bad_magic_is_error_naming_file() {
    let dir = tempfile::tempdir().unwrap();
    for name in ["junk.nsp", "junk.xci"] {
        let path = dir.path().join(name);
        fs::write(&path, vec![0x41u8; 0x10000]).unwrap();
        let err = open_entries(&path).unwrap_err();
        assert!(format!("{err:#}").contains(name), "{err:#}");
    }
}

#[test]
fn entry_past_end_of_file_is_error() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("short.nsp");
    let mut data = pfs0_header(&[("a.bin".into(), 100)]);
    data.extend_from_slice(&[0; 50]);
    fs::write(&path, &data).unwrap();
    let err = open_entries(&path).unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("short.nsp") && msg.contains("a.bin"), "{msg}");
}

#[test]
fn huge_table_is_rejected_without_allocating() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("huge.nsp");
    let mut data = b"PFS0".to_vec();
    data.extend_from_slice(&0x7fff_ffffu32.to_le_bytes());
    data.extend_from_slice(&0x7fff_ffffu32.to_le_bytes());
    data.extend_from_slice(&[0; 4]);
    fs::write(&path, &data).unwrap();
    let err = open_entries(&path).unwrap_err();
    assert!(format!("{err:#}").contains("huge.nsp"));
}

#[test]
fn unknown_extension_is_error() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("x.zip");
    fs::write(&path, b"").unwrap();
    assert!(open_entries(&path).is_err());
}

#[test]
fn fixture_meta_nca_has_decryptable_header_and_pfs0_section() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("f.nsp");
    build_nsp(
        &path,
        &[spec(0x0100_0000_0000_1000, TitleKind::Application)],
    );
    let e = open_entries(&path)
        .unwrap()
        .into_iter()
        .find(|e| e.name.ends_with(".cnmt.nca"))
        .unwrap();
    let mut b = read(&e);
    sak::crypto::xts_decrypt(&common::HEADER_KEY, &mut b[..0xC00], 0x200);
    assert_eq!(&b[0x200..0x204], b"NCA3");
    assert_eq!(b[0x205], 1);
    let mut ctr_high: [u8; 8] = b[0x540..0x548].try_into().unwrap();
    ctr_high.reverse();
    let mut section = b[0xC00..].to_vec();
    sak::crypto::ctr_apply(&common::SECTION_KEY, ctr_high, 0xC00, &mut section);
    assert_eq!(&section[0x200..0x204], b"PFS0");
}

#[test]
fn non_utf8_entry_name_is_error_naming_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("badname.nsp");
    let mut h = pfs0_header(&[("abc".into(), 0)]);
    h[0x28] = 0xff;
    fs::write(&path, &h).unwrap();
    let err = open_entries(&path).unwrap_err();
    assert!(format!("{err:#}").contains("badname.nsp"), "{err:#}");
}

#[test]
fn build_nsp_leaves_keys_file_intact() {
    let dir = tempfile::tempdir().unwrap();
    let keys = common::test_keys_file(dir.path());
    let before = fs::read(&keys).unwrap();
    build_nsp(
        &dir.path().join("a.nsp"),
        &[spec(0x0100_0000_0000_1000, TitleKind::Application)],
    );
    build_xci(
        &dir.path().join("a.xci"),
        &[spec(0x0100_0000_0000_1000, TitleKind::Application)],
    );
    assert_eq!(fs::read(&keys).unwrap(), before);
}

/// An XCI whose secure HFS0 is `secure`, with data after it.
fn xci_with_secure(path: &std::path::Path, secure: &[u8], data: &[u8]) {
    let root = hfs0_header(&[HfsFile {
        name: "secure".into(),
        size: (secure.len() + data.len()) as u64,
        hash_size: secure.len() as u32,
        hash: [0; 32],
    }]);
    let mut out = vec![0u8; 0xF000];
    out[0x100..0x104].copy_from_slice(b"HEAD");
    out.extend_from_slice(&root);
    out.extend_from_slice(secure);
    out.extend_from_slice(data);
    fs::write(path, out).unwrap();
}

/// A one-file HFS0 header with a string table of exactly `name` and no terminator.
fn hfs0_unterminated(name: &[u8], name_offset: u32, size: u64) -> Vec<u8> {
    let mut h = b"HFS0".to_vec();
    h.extend_from_slice(&1u32.to_le_bytes());
    h.extend_from_slice(&(name.len() as u32).to_le_bytes());
    h.extend_from_slice(&[0; 4]);
    h.extend_from_slice(&0u64.to_le_bytes());
    h.extend_from_slice(&size.to_le_bytes());
    h.extend_from_slice(&name_offset.to_le_bytes());
    h.extend_from_slice(&[0; 0x40 - 0x14]);
    h.extend_from_slice(name);
    h
}

#[test]
fn name_ending_exactly_at_end_of_string_table_is_accepted() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("exact.xci");
    // Upstream pads to 0x200 and adds no terminator when the names already end there.
    let name = vec![b'a'; 0x200 - 0x50];
    let secure = hfs0_unterminated(&name, 0, 3);
    assert_eq!(secure.len(), 0x200);
    xci_with_secure(&path, &secure, b"xyz");
    let es = open_entries(&path).unwrap();
    assert_eq!(es.len(), 1);
    assert_eq!(es[0].name.as_bytes(), name);
    assert_eq!(read(&es[0]), b"xyz");
}

#[test]
fn name_offset_at_end_of_string_table_is_error() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("empty.xci");
    let name = vec![b'a'; 0x200 - 0x50];
    let secure = hfs0_unterminated(&name, name.len() as u32, 0);
    xci_with_secure(&path, &secure, b"");
    let err = open_entries(&path).unwrap_err();
    assert!(format!("{err:#}").contains("empty.xci"), "{err:#}");
}
