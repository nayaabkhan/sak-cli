mod common;

use assert_cmd::Command;
use common::{
    HEADER_KEY, SECTION_KEY, TitleKind, TitleSpec, build_nsp, build_nsp_sharing,
    build_nsp_two_rights, build_xci, master_index, plain_titlekey, signed_ticket, test_keys_file,
};
use predicates::prelude::*;
use sak::container::{Entry, open_entries};
use sak::crypto::{ctr_apply, ecb_decrypt, xts_decrypt, xts_encrypt};
use sak::keys::Keys;
use sak::nca::{NcaHeader, standard_header, titlekey_from_ticket};
use sak::xci;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

const BASE: u64 = 0x0100_0000_0000_0000;
const UPD: u64 = 0x0100_0000_0000_0800;
const DLC: u64 = 0x0100_0000_0000_1001;
const RIGHTS: [u8; 16] = [0x12; 16];
/// Key generation of `spec` titles, and the master index it selects.
const GEN: u8 = 3;
const MASTER: u8 = 2;
const XCI_KEY: [u8; 16] = [0x9c; 16];
const GIB: u64 = 1024 * 1024 * 1024;

fn spec(id: u64, kind: TitleKind, rights: Option<[u8; 16]>) -> TitleSpec {
    TitleSpec {
        title_id: id,
        base_id: BASE,
        version: 0x10000,
        kind,
        rights_id: rights,
        delta: false,
        key_gen: GEN,
    }
}
fn titlekey_base() -> TitleSpec {
    spec(BASE, TitleKind::Application, Some(RIGHTS))
}

struct Work {
    dir: tempfile::TempDir,
    keys_dir: tempfile::TempDir,
}
impl Work {
    fn new() -> Work {
        Work {
            dir: tempfile::tempdir().unwrap(),
            keys_dir: tempfile::tempdir().unwrap(),
        }
    }
    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }
    fn keys_path(&self) -> PathBuf {
        test_keys_file(self.keys_dir.path())
    }
    fn keys(&self) -> Keys {
        Keys::load(&self.keys_path()).unwrap()
    }
    fn merge_with_keys(&self, out: &str, keys: &Path) -> Command {
        let mut c = Command::cargo_bin("sak").unwrap();
        c.current_dir(self.dir.path())
            .args(["merge", "-o", out, "--keys"])
            .arg(keys);
        c
    }
    fn merge(&self, out: &str) -> Command {
        self.merge_with_keys(out, &self.keys_path())
    }
    /// Keys file that also has `xci_header_key`.
    fn keys_with_xci_key(&self) -> PathBuf {
        let p = self.keys_path();
        let mut text = fs::read_to_string(&p).unwrap();
        text.push_str(&format!("xci_header_key = {}\n", hex::encode(XCI_KEY)));
        fs::write(&p, text).unwrap();
        p
    }
    /// Merge one input with the given titles into out.xci and return its bytes.
    fn merged(&self, specs: &[TitleSpec]) -> Vec<u8> {
        build_nsp(&self.path("in.nsp"), specs);
        self.merge("out.xci").assert().success();
        fs::read(self.path("out.xci")).unwrap()
    }
}

fn find<'a>(entries: &'a [Entry], suffix: &str) -> &'a Entry {
    entries.iter().find(|e| e.name.ends_with(suffix)).unwrap()
}

fn content_nca(entries: &[Entry]) -> &Entry {
    entries
        .iter()
        .find(|e| e.name.ends_with(".nca") && !e.name.ends_with(".cnmt.nca"))
        .unwrap()
}

fn read_entry(e: &Entry) -> Vec<u8> {
    let bytes = fs::read(&e.source).unwrap();
    bytes[e.offset as usize..(e.offset + e.size) as usize].to_vec()
}

fn le32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
fn le64(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

/// HFS0 entries as (name, offset, size, hash size, hash), plus the header's length.
type HfsRow = (String, u64, u64, u32, [u8; 32]);
fn hfs_rows(b: &[u8]) -> (Vec<HfsRow>, usize) {
    assert_eq!(&b[..4], b"HFS0");
    let count = le32(b, 4) as usize;
    let strtab = le32(b, 8) as usize;
    let names = &b[0x10 + 0x40 * count..];
    let rows = (0..count)
        .map(|n| {
            let e = &b[0x10 + 0x40 * n..];
            let name = &names[le32(e, 16) as usize..];
            let end = name.iter().position(|&c| c == 0).unwrap();
            (
                String::from_utf8(name[..end].to_vec()).unwrap(),
                le64(e, 0),
                le64(e, 8),
                le32(e, 20),
                e[0x20..0x40].try_into().unwrap(),
            )
        })
        .collect();
    (rows, 0x10 + 0x40 * count + strtab)
}

#[test]
fn titlekey_decrypts_with_titlekek() {
    let w = Work::new();
    let keys = w.keys();
    let p = w.path("in.nsp");
    build_nsp(&p, &[titlekey_base()]);
    let entries = open_entries(&p).unwrap();
    let key = titlekey_from_ticket(find(&entries, ".tik"), MASTER, &keys).unwrap();
    assert_eq!(key, plain_titlekey(&keys, RIGHTS, GEN));
}

/// Each signature type, in upstream's `TicketSignature`, with the offset of the ticket body.
const SIGNATURES: [(u32, usize); 6] = [
    (0x10000, 0x240),
    (0x10001, 0x140),
    (0x10002, 0x80),
    (0x10003, 0x240),
    (0x10004, 0x140),
    (0x10005, 0x80),
];

/// `bytes` as a one-file entry on disk.
fn ticket_entry(w: &Work, bytes: &[u8]) -> Entry {
    let path = w.path("t.tik");
    fs::write(&path, bytes).unwrap();
    Entry {
        source: path,
        name: "t.tik".into(),
        offset: 0,
        size: bytes.len() as u64,
    }
}

#[test]
fn ticket_fields_are_read_relative_to_signature_size() {
    let w = Work::new();
    let keys = w.keys();
    for (signature, body) in SIGNATURES {
        let ticket = ticket_entry(&w, &signed_ticket(signature, body, RIGHTS, 0));
        let key = titlekey_from_ticket(&ticket, MASTER, &keys).unwrap();
        assert_eq!(key, plain_titlekey(&keys, RIGHTS, GEN), "{signature:#x}");
        let personal = ticket_entry(&w, &signed_ticket(signature, body, RIGHTS, 1));
        let err = titlekey_from_ticket(&personal, MASTER, &keys).unwrap_err();
        assert!(format!("{err:#}").contains("personal"), "{signature:#x}");
    }
}

#[test]
fn unknown_ticket_signature_type_is_error_naming_file() {
    let w = Work::new();
    let keys = w.keys();
    let ticket = ticket_entry(&w, &signed_ticket(0x20004, 0x140, RIGHTS, 0));
    let msg = format!(
        "{:#}",
        titlekey_from_ticket(&ticket, MASTER, &keys).unwrap_err()
    );
    assert!(msg.contains("t.tik"), "{msg}");
    assert!(msg.contains("signature type"), "{msg}");
}

#[test]
fn truncated_ticket_is_error_naming_file() {
    let w = Work::new();
    let keys = w.keys();
    let whole = signed_ticket(0x10004, 0x140, RIGHTS, 0);
    let ticket = ticket_entry(&w, &whole[..0x200]);
    let msg = format!(
        "{:#}",
        titlekey_from_ticket(&ticket, MASTER, &keys).unwrap_err()
    );
    assert!(msg.contains("t.tik"), "{msg}");
}

fn make_personal(path: &Path) {
    let entries = open_entries(path).unwrap();
    let tik = find(&entries, ".tik");
    let mut bytes = fs::read(path).unwrap();
    bytes[tik.offset as usize + common::TICKET_KEY_TYPE] = 1;
    fs::write(path, bytes).unwrap();
}

#[test]
fn personal_ticket_is_error() {
    let w = Work::new();
    let keys = w.keys();
    let p = w.path("in.nsp");
    build_nsp(&p, &[titlekey_base()]);
    make_personal(&p);
    let entries = open_entries(&p).unwrap();
    let err = titlekey_from_ticket(find(&entries, ".tik"), MASTER, &keys).unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("personal"), "{msg}");
    assert!(msg.contains(".tik"), "{msg}");
}

#[test]
fn personal_ticket_writes_nothing() {
    let w = Work::new();
    let p = w.path("in.nsp");
    build_nsp(&p, &[titlekey_base()]);
    make_personal(&p);
    w.merge("out.xci")
        .assert()
        .failure()
        .stderr(predicate::str::contains("personal"));
    assert!(!w.path("out.xci").exists());
    assert!(!w.path("out.xci.part").exists());
}

#[test]
fn ticket_with_other_rights_id_inside_is_error() {
    let w = Work::new();
    let p = w.path("in.nsp");
    build_nsp(&p, &[titlekey_base()]);
    let entries = open_entries(&p).unwrap();
    let tik = find(&entries, ".tik");
    let mut bytes = fs::read(&p).unwrap();
    bytes[tik.offset as usize + 0x2A0..tik.offset as usize + 0x2B0].fill(0x77);
    fs::write(&p, bytes).unwrap();
    w.merge("out.xci").assert().failure().stderr(
        predicate::str::contains("77".repeat(16))
            .and(predicate::str::contains("12".repeat(16)))
            .and(predicate::str::contains("in.nsp")),
    );
    assert!(!w.path("out.xci").exists());
    assert!(!w.path("out.xci.part").exists());
}

/// Rewrite the titlekey content NCA of a fresh NSP, whose distribution byte is `distribution`;
/// returns source entry, new header and plain new header.
fn rewritten_with(w: &Work, distribution: u8) -> (Entry, Vec<u8>, Vec<u8>) {
    let keys = w.keys();
    let p = w.path("in.nsp");
    build_nsp(&p, &[titlekey_base()]);
    let entries = open_entries(&p).unwrap();
    let nca = content_nca(&entries).clone();
    set_distribution(&p, &nca, distribution);
    let header = NcaHeader::read(&nca, &keys).unwrap();
    let tk = plain_titlekey(&keys, RIGHTS, GEN);
    let new = standard_header(&header, Some(&tk), &keys).unwrap();
    let mut plain = new.to_vec();
    xts_decrypt(&HEADER_KEY, &mut plain, 0x200);
    (nca, new.to_vec(), plain)
}

fn rewritten(w: &Work) -> (Entry, Vec<u8>, Vec<u8>) {
    rewritten_with(w, 0)
}

/// Set the distribution byte at 0x204 of `e` in place, re-encrypting its header.
fn set_distribution(path: &Path, e: &Entry, value: u8) {
    let mut file = fs::read(path).unwrap();
    let range = e.offset as usize..e.offset as usize + 0xC00;
    xts_decrypt(&HEADER_KEY, &mut file[range.clone()], 0x200);
    file[e.offset as usize + 0x204] = value;
    xts_encrypt(&HEADER_KEY, &mut file[range], 0x200);
    fs::write(path, file).unwrap();
}

#[test]
fn standard_header_clears_rights_id_and_keeps_distribution_byte() {
    for value in [0, 1] {
        let w = Work::new();
        let (_, _, plain) = rewritten_with(&w, value);
        assert_eq!(&plain[0x200..0x204], b"NCA3");
        assert_eq!(plain[0x204], value);
        assert_eq!(plain[0x230..0x240], [0u8; 16]);
    }
}

#[test]
fn plain_nca_header_is_unchanged() {
    for value in [0, 1] {
        let w = Work::new();
        let keys = w.keys();
        let p = w.path("in.nsp");
        build_nsp(&p, &[spec(BASE, TitleKind::Application, None)]);
        let entries = open_entries(&p).unwrap();
        for e in entries.iter().filter(|e| e.name.ends_with(".nca")) {
            set_distribution(&p, e, value);
            let header = NcaHeader::read(e, &keys).unwrap();
            let new = standard_header(&header, None, &keys).unwrap();
            assert_eq!(new[..], read_entry(e)[..0xC00], "{}", e.name);
        }
    }
}

#[test]
fn standard_header_only_changes_expected_fields() {
    let w = Work::new();
    let keys = w.keys();
    let (nca, _, plain) = rewritten(&w);
    let old = NcaHeader::read(&nca, &keys).unwrap();
    for (i, (new, old)) in plain.iter().zip(old.plain.iter()).enumerate() {
        let changed = (0x230..0x240).contains(&i) || (0x300..0x340).contains(&i);
        if !changed {
            assert_eq!(new, old, "byte {i:#x}");
        }
    }
}

#[test]
fn standard_header_key_area_opens_section_body() {
    let w = Work::new();
    let keys = w.keys();
    let (nca, _, plain) = rewritten(&w);
    let kaek = keys.key_area_key(MASTER, 0).unwrap();
    let mut area: [u8; 0x40] = plain[0x300..0x340].try_into().unwrap();
    ecb_decrypt(&kaek, &mut area);
    for slot in area.chunks_exact(16) {
        assert_eq!(slot, plain_titlekey(&keys, RIGHTS, GEN));
    }
    let key: [u8; 16] = area[0x20..0x30].try_into().unwrap();
    let mut high: [u8; 8] = plain[0x540..0x548].try_into().unwrap();
    high.reverse();
    let mut body = read_entry(&nca)[0xC00..].to_vec();
    ctr_apply(&key, high, 0xC00, &mut body);
    assert_eq!(body[0x200..0x208], BASE.to_le_bytes());
    assert_eq!(body[0x210..0x400], [0xA1; 0x1F0]);
}

#[test]
fn standard_header_keeps_plain_nca_key_area() {
    let w = Work::new();
    let keys = w.keys();
    let p = w.path("in.nsp");
    build_nsp(&p, &[spec(BASE, TitleKind::Application, None)]);
    let entries = open_entries(&p).unwrap();
    let header = NcaHeader::read(find(&entries, ".cnmt.nca"), &keys).unwrap();
    let mut plain = standard_header(&header, None, &keys).unwrap();
    xts_decrypt(&HEADER_KEY, &mut plain, 0x200);
    assert_eq!(plain[0x300..0x340], header.plain[0x300..0x340]);
}

#[test]
fn standard_header_refuses_titlekey_nca_without_titlekey() {
    let w = Work::new();
    let keys = w.keys();
    let p = w.path("in.nsp");
    build_nsp(&p, &[titlekey_base()]);
    let entries = open_entries(&p).unwrap();
    let header = NcaHeader::read(content_nca(&entries), &keys).unwrap();
    assert!(standard_header(&header, None, &keys).is_err());
}

#[test]
fn signature_sector_is_unchanged_by_standard_header() {
    let w = Work::new();
    let (nca, new, plain) = rewritten(&w);
    assert_eq!(
        plain[0x230..0x240],
        [0u8; 16],
        "the rewrite did change the header"
    );
    assert_eq!(new[..0x200], read_entry(&nca)[..0x200]);
}

#[test]
fn xci_layout_offsets() {
    let w = Work::new();
    let xci = w.merged(&[titlekey_base()]);

    // 0x100 signature + 0x90 fields + 0x70 game info + 0x6E00 zeros + 0x8000 of 0xFF
    assert_eq!(0x100 + 0x90 + 0x70 + 0x6E00 + 0x8000, 0xF000);
    assert_eq!(&xci[0x100..0x104], b"HEAD");
    assert!(xci[0x200..0x7000].iter().all(|&b| b == 0));
    assert!(xci[0x7000..0xF000].iter().all(|&b| b == 0xFF));

    let (root, root_len) = hfs_rows(&xci[0xF000..]);
    assert_eq!(root_len, 0x200);
    let names: Vec<&str> = root.iter().map(|r| r.0.as_str()).collect();
    assert_eq!(names, ["update", "normal", "secure"]);
    let data = 0xF000 + root_len;
    for r in &root[..2] {
        assert_eq!((r.2, r.3), (0x200, 0x200));
    }
    let (sec, sec_len) = hfs_rows(&xci[data + root[2].1 as usize..]);
    assert_eq!(
        root[2].2 as usize,
        sec_len + sec.iter().map(|r| r.2 as usize).sum::<usize>()
    );
    assert_eq!(root[2].3 as usize, sec_len);
    assert_eq!(data + root[2].1 as usize + root[2].2 as usize, xci.len());
    for r in &root {
        let start = data + r.1 as usize;
        let hash: [u8; 32] = Sha256::digest(&xci[start..start + r.3 as usize]).into();
        assert_eq!(hash, r.4, "{}", r.0);
    }

    // secure offset and end of normal, in 0x200 units
    let sec_units = ((root[2].1 + 0xF000 + 0x200) / 0x200) as u32;
    assert_eq!(le32(&xci, 0x104), sec_units);
    assert_eq!(le32(&xci, 0x18C), sec_units);
    assert_eq!(le32(&xci, 0x108), 0xFFFF_FFFF);
    assert_eq!(xci[0x10C], 0);
    assert_eq!(xci[0x10D], 0xFA);
    assert_eq!(xci[0x10E..0x110], [0, 0]);
    assert_eq!(xci[0x110..0x118], hex::decode("8750f4c0a9c5a966").unwrap());
    assert_eq!(le64(&xci, 0x118), (xci.len() as u64 - 1) / 0x200);
    assert_eq!(le64(&xci, 0x130), 0xF000);
    assert_eq!(le64(&xci, 0x138), 0x200);
    assert_eq!(xci[0x140..0x160], Sha256::digest(&xci[0xF000..0xF200])[..]);
    assert_eq!(
        xci[0x160..0x180],
        hex::decode("1ab7c7b263e74e44cd3c68e40f7ef4a4d6571551d043fca8ecf5c489f2c66e7e").unwrap()
    );
    assert_eq!(le32(&xci, 0x180), 1);
    assert_eq!(le32(&xci, 0x184), 2);
    assert_eq!(le32(&xci, 0x188), 0);
}

#[test]
fn xci_signature_is_random() {
    let w = Work::new();
    let a = w.merged(&[titlekey_base()]);
    w.merge("second.xci").assert().success();
    let b = fs::read(w.path("second.xci")).unwrap();
    assert_ne!(a[..0x100], b[..0x100]);
}

#[test]
fn xci_card_size_byte_at_each_threshold() {
    const SMALL: [u8; 4] = [0x11, 0x00, 0xa1, 0x00];
    const LARGE: [u8; 4] = [0x10, 0x00, 0xa1, 0x00];
    for (total, byte, firm) in [
        (GIB / 2, 0xFA, SMALL),
        (GIB, 0xF8, SMALL),
        (2 * GIB, 0xF0, SMALL),
        (4 * GIB, 0xE0, LARGE),
        (8 * GIB, 0xE1, LARGE),
        (16 * GIB, 0xE2, LARGE),
        (32 * GIB, 0xE3, LARGE),
    ] {
        assert_eq!(xci::card_size(total), (byte, firm), "{total:#x}");
    }
}

#[test]
fn card_size_rounds_to_two_decimals_like_upstream() {
    // Upstream compares round(bytes / GiB, 2), so each step begins 0.005 GiB early.
    for (n, below, at) in [(1u64, 0xFA, 0xF8), (4, 0xF0, 0xE0), (32, 0xE2, 0xE3)] {
        let edge = ((n * 200 - 1) * GIB).div_ceil(200);
        assert_eq!(xci::card_size(edge - 1).0, below, "{n} GiB");
        assert_eq!(xci::card_size(edge).0, at, "{n} GiB");
    }
}

const BLOB_SMALL: &str = "9109ff82971ee9935011ca063f3c4d87a13d28a9928d74f149919eb782e1f0cfe4a5a3bdf978295cd52639a4991bdb1fed841779a3f85d23aa4242135616f5187c03cf0d97e5d218fdb245381fd1cf8dfb796fbeda4bf7f7d6b128ce89bc9eaa8552d42f597c5db866c67bb0dd8eea11";
const BLOB_LARGE: &str = "9298f35088f09f7da89a60d4cba6f96fa45bb6acabc751f95d3987426b38c3f210da0b700e5ece29a13cbe1da6d052cbf2087ce9af590538570d78b9cdd27fbeb4a0ac2adff9ba77754dd6675ac76223506b3bdabcb2e212fa465111ab7d51afc8b5b2b21c4b3f40654598620282add6";

#[test]
fn xci_without_xci_header_key_uses_fallback_blob() {
    let w = Work::new();
    let xci = w.merged(&[titlekey_base()]);
    assert_eq!(
        xci[0x120..0x130],
        hex::decode("5b408b145e277e81e5bf677c94888d7b").unwrap()
    );
    assert_eq!(xci[0x190..0x200], hex::decode(BLOB_SMALL).unwrap());
}

#[test]
fn fallback_blob_switches_at_four_gib() {
    assert_eq!(
        xci::fallback_game_info(2 * GIB)[..],
        hex::decode(BLOB_SMALL).unwrap()
    );
    assert_eq!(
        xci::fallback_game_info(4 * GIB)[..],
        hex::decode(BLOB_LARGE).unwrap()
    );
    assert_eq!(
        xci::fallback_game_info(40 * GIB)[..],
        hex::decode(BLOB_LARGE).unwrap()
    );
}

#[test]
fn xci_with_xci_header_key_encrypts_game_info() {
    let w = Work::new();
    build_nsp(&w.path("in.nsp"), &[titlekey_base()]);
    let keys = w.keys_with_xci_key();
    w.merge_with_keys("out.xci", &keys).assert().success();
    let xci = fs::read(w.path("out.xci")).unwrap();

    let iv: [u8; 16] = xci[0x120..0x130].try_into().unwrap();
    assert_ne!(
        iv.to_vec(),
        hex::decode("5b408b145e277e81e5bf677c94888d7b").unwrap()
    );
    // CBC decrypt with the reversed IV
    let mut prev = iv;
    prev.reverse();
    let mut info = Vec::new();
    for block in xci[0x190..0x200].chunks_exact(16) {
        let mut b: [u8; 16] = block.try_into().unwrap();
        ecb_decrypt(&XCI_KEY, &mut b);
        for (x, p) in b.iter_mut().zip(prev) {
            *x ^= p;
        }
        info.extend_from_slice(&b);
        prev = block.try_into().unwrap();
    }
    let mut expected = hex::decode(concat!(
        "0100000000000000",
        "1100a100",
        "88130000",
        "00000000",
        "00000000",
        "00000000",
        "00110c00",
        "5a000200",
        "00000000",
        "9bfb03ddbb7c5fca",
        "1608000000000001",
    ))
    .unwrap();
    expected.resize(0x70, 0);
    assert_eq!(info, expected);
}

#[test]
fn xci_output_reads_back_through_open_entries() {
    let w = Work::new();
    let keys = w.keys();
    let specs = [
        titlekey_base(),
        spec(UPD, TitleKind::Patch, Some([0x34; 16])),
        spec(DLC, TitleKind::AddOn, None),
    ];
    let source = {
        build_nsp(&w.path("in.nsp"), &specs);
        open_entries(&w.path("in.nsp")).unwrap()
    };
    w.merge("out.xci").assert().success();
    let out = open_entries(&w.path("out.xci")).unwrap();

    let want: Vec<&Entry> = source.iter().filter(|e| e.name.ends_with(".nca")).collect();
    assert_eq!(want.len(), 6);
    assert_eq!(out.len(), want.len(), "only NCAs, no tickets or certs");
    let meta = out.iter().filter(|e| e.name.ends_with(".cnmt.nca")).count();
    assert_eq!(meta, 3);
    for src in want {
        let e = find(&out, &src.name);
        let (old, new) = (read_entry(src), read_entry(e));
        assert_eq!(old.len(), new.len(), "{}", e.name);
        assert_eq!(old[0xC00..], new[0xC00..], "body of {}", e.name);
        assert_eq!(old[..0x200], new[..0x200], "signature of {}", e.name);
        let header = NcaHeader::read(e, &keys).unwrap();
        assert_eq!(header.rights_id, [0; 16], "{}", e.name);
        assert_eq!(header.plain[0x204], 0, "{}", e.name);
    }
}

/// Check one output NCA end to end: its header opens, its key area holds `want`, and that key
/// turns its section back into `plain` at the fixture's section offset.
fn assert_nca_opens(keys: &Keys, out: &Entry, master: u8, want: &[u8; 16], plain: &[u8]) {
    let bytes = read_entry(out);
    let mut header = bytes[..0xC00].to_vec();
    xts_decrypt(&HEADER_KEY, &mut header, 0x200);
    assert_eq!(&header[0x200..0x204], b"NCA3", "{}", out.name);
    assert_eq!(header[0x230..0x240], [0; 16], "{}", out.name);
    let mut area: [u8; 0x40] = header[0x300..0x340].try_into().unwrap();
    ecb_decrypt(&keys.key_area_key(master, 0).unwrap(), &mut area);
    assert_eq!(area[0x20..0x30], want[..], "key area of {}", out.name);
    let mut high: [u8; 8] = header[0x540..0x548].try_into().unwrap();
    high.reverse();
    let mut body = bytes[0xC00..].to_vec();
    ctr_apply(want, high, 0xC00, &mut body);
    assert_eq!(
        body[0x200..0x200 + plain.len()],
        plain[..],
        "section of {}",
        out.name
    );
}

#[test]
fn every_output_nca_opens_with_its_own_key() {
    const SECOND: [u8; 16] = [0x56; 16];
    const UPDATE: [u8; 16] = [0x34; 16];
    let w = Work::new();
    let keys = w.keys();
    let update = TitleSpec {
        key_gen: 5,
        ..spec(UPD, TitleKind::Patch, Some(UPDATE))
    };
    let dlc = TitleSpec {
        key_gen: 4,
        ..spec(DLC, TitleKind::AddOn, None)
    };
    build_nsp_two_rights(&w.path("base.nsp"), &titlekey_base(), SECOND);
    build_nsp(&w.path("more.nsp"), &[update.clone(), dlc.clone()]);
    w.merge("out.xci").assert().success();

    let mut source = open_entries(&w.path("base.nsp")).unwrap();
    source.extend(open_entries(&w.path("more.nsp")).unwrap());
    let out = open_entries(&w.path("out.xci")).unwrap();
    assert_eq!(out.len(), 7);
    let mut titlekeys = Vec::new();
    for e in &out {
        let src = NcaHeader::read(find(&source, &e.name), &keys).unwrap();
        let title = u64::from_le_bytes(src.plain[0x210..0x218].try_into().unwrap());
        let key_gen = match title {
            UPD => update.key_gen,
            DLC => dlc.key_gen,
            _ => GEN,
        };
        assert_eq!(src.master_index, master_index(key_gen), "{}", e.name);
        let want = if src.rights_id == [0; 16] {
            SECTION_KEY
        } else {
            let key = plain_titlekey(&keys, src.rights_id, key_gen);
            titlekeys.push(key);
            key
        };
        // The second rights ID belongs to the fixture's extra content, salted 0xB2.
        let plain: Vec<u8> = if e.name.ends_with(".cnmt.nca") {
            b"PFS0".to_vec()
        } else {
            let salt = if src.rights_id == SECOND { 0xB2 } else { 0xA1 };
            let mut p = title.to_le_bytes().to_vec();
            p.extend_from_slice(&0x10000u32.to_le_bytes());
            p.resize(0x200, salt);
            p
        };
        assert_nca_opens(&keys, e, src.master_index, &want, &plain);
    }
    titlekeys.sort();
    titlekeys.dedup();
    assert_eq!(titlekeys.len(), 3, "each rights ID has its own titlekey");
}

#[test]
fn xci_secure_hashes_cover_first_sector_of_source() {
    let w = Work::new();
    let xci = w.merged(&[titlekey_base()]);
    let source = open_entries(&w.path("in.nsp")).unwrap();
    let (root, root_len) = hfs_rows(&xci[0xF000..]);
    let (sec, _) = hfs_rows(&xci[0xF000 + root_len + root[2].1 as usize..]);
    assert!(!sec.is_empty());
    for (name, _, _, hash_size, hash) in sec {
        assert_eq!(hash_size, 0x200);
        let data = read_entry(find(&source, &name));
        let want: [u8; 32] = Sha256::digest(&data[..0x200]).into();
        assert_eq!(hash, want, "{name}");
    }
}

#[test]
fn xci_size_matches_output() {
    let w = Work::new();
    let keys = w.keys();
    build_nsp(&w.path("in.nsp"), &[titlekey_base()]);
    let plan = sak::select::build_plan(w.dir.path(), &w.path("out.xci"), &keys).unwrap();
    let prepared = xci::prepare(&plan, &keys).unwrap();
    let size = xci::size(&plan).unwrap();
    assert_eq!(prepared.size(), size);
    w.merge("out.xci").assert().success();
    assert_eq!(fs::metadata(w.path("out.xci")).unwrap().len(), size);
}

#[test]
fn xci_size_matches_output_for_several_titles() {
    let w = Work::new();
    let keys = w.keys();
    build_nsp(
        &w.path("in.nsp"),
        &[
            titlekey_base(),
            spec(UPD, TitleKind::Patch, Some([0x34; 16])),
            spec(DLC, TitleKind::AddOn, None),
        ],
    );
    let plan = sak::select::build_plan(w.dir.path(), &w.path("out.xci"), &keys).unwrap();
    let size = xci::size(&plan).unwrap();
    w.merge("out.xci").assert().success();
    assert_eq!(fs::metadata(w.path("out.xci")).unwrap().len(), size);
}

#[test]
fn cart_xci_plus_update_nsp_merges_to_xci() {
    let w = Work::new();
    let keys = w.keys();
    let update = [0x34; 16];
    build_xci(
        &w.path("cart.xci"),
        &[spec(BASE, TitleKind::Application, None)],
    );
    build_nsp(
        &w.path("update.nsp"),
        &[spec(UPD, TitleKind::Patch, Some(update))],
    );
    w.merge("out.xci").assert().success();

    let cart = open_entries(&w.path("cart.xci")).unwrap();
    let upd_files = open_entries(&w.path("update.nsp")).unwrap();
    let out = open_entries(&w.path("out.xci")).unwrap();
    assert_eq!(out.len(), 4);
    for src in &cart {
        // Standard crypto already, so nothing in it changes.
        assert_eq!(
            read_entry(find(&out, &src.name)),
            read_entry(src),
            "{}",
            src.name
        );
    }
    let src = content_nca(&upd_files);
    let plain = {
        let mut p = UPD.to_le_bytes().to_vec();
        p.extend_from_slice(&0x10000u32.to_le_bytes());
        p.resize(0x200, 0xA1);
        p
    };
    let key = plain_titlekey(&keys, update, GEN);
    assert_nca_opens(&keys, find(&out, &src.name), MASTER, &key, &plain);
}

#[test]
fn nca_listed_by_two_titles_appears_once_in_xci() {
    let w = Work::new();
    let keys = w.keys();
    let base_path = w.path("base.nsp");
    build_nsp(&base_path, &[titlekey_base()]);
    let source = open_entries(&base_path).unwrap();
    let shared = content_nca(&source).clone();
    let bytes = read_entry(&shared);
    build_nsp_sharing(
        &w.path("dlc.nsp"),
        &spec(DLC, TitleKind::AddOn, Some(RIGHTS)),
        (shared.name.clone(), bytes),
    );
    w.merge("out.xci").assert().success();

    let out = open_entries(&w.path("out.xci")).unwrap();
    assert_eq!(out.iter().filter(|e| e.name == shared.name).count(), 1);
    // base content and meta, DLC content and meta
    assert_eq!(out.len(), 4);
    let mut plain = BASE.to_le_bytes().to_vec();
    plain.extend_from_slice(&0x10000u32.to_le_bytes());
    plain.resize(0x200, 0xA1);
    let key = plain_titlekey(&keys, RIGHTS, GEN);
    assert_nca_opens(&keys, find(&out, &shared.name), MASTER, &key, &plain);
}

#[test]
fn xci_write_takes_plan_and_keys() {
    let w = Work::new();
    let keys = w.keys();
    build_nsp(&w.path("in.nsp"), &[titlekey_base()]);
    let plan = sak::select::build_plan(w.dir.path(), &w.path("out.xci"), &keys).unwrap();
    let path = w.path("direct.xci");
    let mut out = fs::File::create(&path).unwrap();
    xci::write(&plan, &keys, &mut out, &indicatif::ProgressBar::hidden()).unwrap();
    drop(out);
    assert_eq!(
        fs::metadata(&path).unwrap().len(),
        xci::size(&plan).unwrap()
    );
    assert_eq!(open_entries(&path).unwrap().len(), 2);
}

#[test]
fn xci_output_merges_again() {
    let w = Work::new();
    w.merged(&[titlekey_base()]);
    w.merge("out.xci").arg("--force").assert().success();
    fs::remove_file(w.path("in.nsp")).unwrap();
    w.merge("again.nsp").assert().success();
    assert_eq!(open_entries(&w.path("again.nsp")).unwrap().len(), 2);
}

#[test]
fn prints_signature_warning() {
    let w = Work::new();
    build_nsp(&w.path("in.nsp"), &[titlekey_base()]);
    w.merge("out.xci")
        .assert()
        .success()
        .stdout(predicate::str::contains("ignores the signature"));
}

#[test]
fn nsp_run_has_no_signature_warning() {
    let w = Work::new();
    build_nsp(&w.path("in.nsp"), &[titlekey_base()]);
    w.merge("out.nsp")
        .assert()
        .success()
        .stdout(predicate::str::contains("ignores the signature").not());
}
