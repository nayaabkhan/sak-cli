//! Test fixtures: made-up keys and small, structurally valid NSP/XCI files.
//! Everything here is built with `sak::crypto`; no real keys or game data.
#![allow(dead_code)]

use sak::container::{HfsFile, hfs0_header, pfs0_header};
use sak::crypto::{ctr_apply, ecb_decrypt, ecb_encrypt, xts_encrypt};
use sak::keys::Keys;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

pub const HEADER_KEY: [u8; 32] = {
    let mut k = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        k[i] = (i as u8).wrapping_mul(5).wrapping_add(0x11);
        i += 1;
    }
    k
};
const fn seq(seed: u8) -> [u8; 16] {
    let mut k = [0u8; 16];
    let mut i = 0;
    while i < 16 {
        k[i] = seed.wrapping_add((i as u8).wrapping_mul(3));
        i += 1;
    }
    k
}
pub const MASTER_KEY_00: [u8; 16] = seq(0x21);
pub const AES_KEK_GEN_SOURCE: [u8; 16] = seq(0x32);
pub const AES_KEY_GEN_SOURCE: [u8; 16] = seq(0x43);
pub const KAEK_APP_SOURCE: [u8; 16] = seq(0x54);
pub const TITLEKEK_SOURCE: [u8; 16] = seq(0x65);
/// Section CTR key placed (encrypted) in key area slot 2 of every fixture NCA.
pub const SECTION_KEY: [u8; 16] = seq(0x76);

/// Encrypted titlekey every fixture ticket carries.
pub const TICKET_TITLEKEY: [u8; 16] = [0x5a; 16];

/// Decrypted titlekey matching `TICKET_TITLEKEY`, using the titlekek for master index 0.
pub fn plain_titlekey(keys: &Keys) -> [u8; 16] {
    let mut k = TICKET_TITLEKEY;
    ecb_decrypt(&keys.titlekek(0).unwrap(), &mut k);
    k
}

pub fn test_keys_file(dir: &Path) -> PathBuf {
    let path = dir.join("prod.keys");
    let text = format!(
        "header_key = {}\nmaster_key_00 = {}\naes_kek_generation_source = {}\n\
         aes_key_generation_source = {}\nkey_area_key_application_source = {}\n\
         titlekek_source = {}\n",
        hex::encode(HEADER_KEY),
        hex::encode(MASTER_KEY_00),
        hex::encode(AES_KEK_GEN_SOURCE),
        hex::encode(AES_KEY_GEN_SOURCE),
        hex::encode(KAEK_APP_SOURCE),
        hex::encode(TITLEKEK_SOURCE),
    );
    std::fs::write(&path, text).unwrap();
    path
}

pub use sak::cnmt::TitleKind;

fn cnmt_type(kind: TitleKind) -> u8 {
    match kind {
        TitleKind::Application => 0x80,
        TitleKind::Patch => 0x81,
        TitleKind::AddOn => 0x82,
    }
}

fn ext_size(kind: TitleKind) -> u16 {
    match kind {
        TitleKind::Patch => 0x18,
        _ => 0x10,
    }
}

#[derive(Clone, Debug)]
pub struct TitleSpec {
    pub title_id: u64,
    pub base_id: u64,
    pub version: u32,
    pub kind: TitleKind,
    pub rights_id: Option<[u8; 16]>,
    pub delta: bool,
}

fn sha(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// Build an encrypted NCA: XTS header plus one CTR section holding `section`
/// (a PFS0 at section offset 0x200 when `pfs0` is true). With a rights ID the section uses
/// the ticket's titlekey, as a real titlekey NCA does; otherwise `SECTION_KEY`.
fn build_nca(
    keys: &Keys,
    title_id: u64,
    is_meta: bool,
    rights_id: Option<[u8; 16]>,
    section: &[u8],
    pfs0: bool,
) -> Vec<u8> {
    let mut body = vec![0u8; 0x200];
    body.extend_from_slice(section);
    body.resize(body.len().next_multiple_of(0x200), 0);
    let total = 0xC00 + body.len();

    let mut h = vec![0u8; 0xC00];
    h[0x200..0x204].copy_from_slice(b"NCA3");
    h[0x205] = is_meta as u8;
    h[0x208..0x210].copy_from_slice(&(total as u64).to_le_bytes());
    h[0x210..0x218].copy_from_slice(&title_id.to_le_bytes());
    h[0x230..0x240].copy_from_slice(&rights_id.unwrap_or([0; 16]));
    h[0x240..0x244].copy_from_slice(&((0xC00 / 0x200) as u32).to_le_bytes());
    h[0x244..0x248].copy_from_slice(&((total / 0x200) as u32).to_le_bytes());
    // key area slot 2: section key, ECB-encrypted with key area key (master index 0)
    let kaek = keys.key_area_key(0, 0).unwrap();
    let mut slot = SECTION_KEY;
    ecb_encrypt(&kaek, &mut slot);
    h[0x320..0x330].copy_from_slice(&slot);
    // section header 0
    let ctr_raw = title_id.to_le_bytes();
    h[0x404] = 3;
    if pfs0 {
        h[0x440..0x448].copy_from_slice(&0x200u64.to_le_bytes());
        h[0x448..0x450].copy_from_slice(&(section.len() as u64).to_le_bytes());
    }
    h[0x540..0x548].copy_from_slice(&ctr_raw);

    let mut ctr_high = ctr_raw;
    ctr_high.reverse();
    let section_key = match rights_id {
        Some(_) => plain_titlekey(keys),
        None => SECTION_KEY,
    };
    ctr_apply(&section_key, ctr_high, 0xC00, &mut body);
    xts_encrypt(&HEADER_KEY, &mut h, 0x200);
    h.extend_from_slice(&body);
    h
}

fn nca_id(nca: &[u8]) -> [u8; 16] {
    sha(nca)[..16].try_into().unwrap()
}

fn build_cnmt(spec: &TitleSpec, records: &[([u8; 32], [u8; 16], u64, u8)]) -> Vec<u8> {
    let ext = ext_size(spec.kind) as usize;
    let mut c = vec![0u8; 0x20 + ext];
    c[0..8].copy_from_slice(&spec.title_id.to_le_bytes());
    c[8..12].copy_from_slice(&spec.version.to_le_bytes());
    c[0xC] = cnmt_type(spec.kind);
    c[0xE..0x10].copy_from_slice(&(ext as u16).to_le_bytes());
    c[0x10..0x12].copy_from_slice(&(records.len() as u16).to_le_bytes());
    if spec.kind != TitleKind::Application {
        c[0x20..0x28].copy_from_slice(&spec.base_id.to_le_bytes());
    }
    for (hash, id, size, ty) in records {
        let mut r = vec![0u8; 0x38];
        r[..0x20].copy_from_slice(hash);
        r[0x20..0x30].copy_from_slice(id);
        r[0x30..0x36].copy_from_slice(&size.to_le_bytes()[..6]);
        r[0x36] = *ty;
        c.extend_from_slice(&r);
    }
    c
}

/// RSA-2048 with SHA-256, the signature type of eShop tickets.
pub const RSA_2048_SHA256: u32 = 0x10004;
/// Absolute offset of the key type byte in an RSA-2048 ticket.
pub const TICKET_KEY_TYPE: usize = 0x140 + 0x141;
pub const TICKET_ISSUER: &[u8] = b"Root-CA00000003-XS00000020";

/// A ticket laid out as on real media: u32 signature type, signature and padding up to
/// `body`, then issuer, titlekey block, key type and rights ID relative to `body`.
pub fn signed_ticket(
    signature_type: u32,
    body: usize,
    rights_id: [u8; 16],
    key_type: u8,
) -> Vec<u8> {
    let mut t = vec![0u8; body + 0x180];
    t[..4].copy_from_slice(&signature_type.to_le_bytes());
    t[4..body].fill(0xEE);
    t[body..body + TICKET_ISSUER.len()].copy_from_slice(TICKET_ISSUER);
    t[body + 0x40..body + 0x50].copy_from_slice(&TICKET_TITLEKEY);
    t[body + 0x140] = 2; // format version, as upstream's generated tickets
    t[body + 0x141] = key_type;
    t[body + 0x160..body + 0x170].copy_from_slice(&rights_id);
    t
}

fn build_ticket(rights_id: [u8; 16]) -> Vec<u8> {
    signed_ticket(RSA_2048_SHA256, 0x140, rights_id, 0)
}

/// Files (name, bytes) a title contributes to an NSP or the secure partition.
pub fn title_files(keys: &Keys, spec: &TitleSpec) -> Vec<(String, Vec<u8>)> {
    title_files_with(keys, spec, None)
}

/// Like `title_files`, plus a second content NCA under the rights ID `extra`.
pub fn title_files_with(
    keys: &Keys,
    spec: &TitleSpec,
    extra: Option<[u8; 16]>,
) -> Vec<(String, Vec<u8>)> {
    let mut files = Vec::new();
    let mut records = Vec::new();
    let mut add_content =
        |files: &mut Vec<(String, Vec<u8>)>, ty: u8, salt: u8, rights: Option<[u8; 16]>| {
            let mut payload = vec![salt; 0x200];
            payload[..8].copy_from_slice(&spec.title_id.to_le_bytes());
            payload[8..12].copy_from_slice(&spec.version.to_le_bytes());
            let nca = build_nca(keys, spec.title_id, false, rights, &payload, false);
            let id = nca_id(&nca);
            records.push((sha(&nca), id, nca.len() as u64, ty));
            files.push((format!("{}.nca", hex::encode(id)), nca));
        };
    add_content(&mut files, 1, 0xA1, spec.rights_id);
    if spec.delta {
        add_content(&mut files, 6, 0xD7, spec.rights_id);
    }
    if extra.is_some() {
        add_content(&mut files, 3, 0xB2, extra);
    }
    let cnmt = build_cnmt(spec, &records);
    let cnmt_name = format!("{:?}_{:016x}.cnmt", spec.kind, spec.title_id);
    let mut pfs = pfs0_header(&[(cnmt_name.clone(), cnmt.len() as u64)]);
    pfs.extend_from_slice(&cnmt);
    let meta = build_nca(keys, spec.title_id, true, None, &pfs, true);
    files.push((format!("{}.cnmt.nca", hex::encode(nca_id(&meta))), meta));
    for r in spec.rights_id.into_iter().chain(extra) {
        files.push((format!("{}.tik", hex::encode(r)), build_ticket(r)));
        files.push((format!("{}.cert", hex::encode(r)), vec![0xCE; 0x40]));
    }
    files
}

fn concat(files: &[(String, Vec<u8>)]) -> Vec<u8> {
    let list: Vec<_> = files
        .iter()
        .map(|(n, d)| (n.clone(), d.len() as u64))
        .collect();
    let mut out = pfs0_header(&list);
    for (_, d) in files {
        out.extend_from_slice(d);
    }
    out
}

fn load_keys(_path: &Path) -> Keys {
    // private temp dir, so the caller's folder is never touched
    let tmp = tempfile::tempdir().unwrap();
    let kp = test_keys_file(tmp.path());
    Keys::load(&kp).unwrap()
}

/// NSP holding one title whose content uses two rights IDs.
pub fn build_nsp_two_rights(path: &Path, spec: &TitleSpec, extra: [u8; 16]) {
    let keys = load_keys(path);
    std::fs::write(path, concat(&title_files_with(&keys, spec, Some(extra)))).unwrap();
}

pub fn build_nsp(path: &Path, specs: &[TitleSpec]) {
    let keys = load_keys(path);
    let files: Vec<_> = specs.iter().flat_map(|s| title_files(&keys, s)).collect();
    std::fs::write(path, concat(&files)).unwrap();
}

fn hfs_file(name: &str, data: &[u8]) -> HfsFile {
    let hash_size = data.len().min(0x200);
    HfsFile {
        name: name.to_string(),
        size: data.len() as u64,
        hash_size: hash_size as u32,
        hash: sha(&data[..hash_size]),
    }
}

fn hfs0(files: &[(String, Vec<u8>)]) -> Vec<u8> {
    let list: Vec<_> = files.iter().map(|(n, d)| hfs_file(n, d)).collect();
    let mut out = hfs0_header(&list);
    for (_, d) in files {
        out.extend_from_slice(d);
    }
    out
}

pub fn build_xci(path: &Path, specs: &[TitleSpec]) {
    let keys = load_keys(path);
    let files: Vec<_> = specs.iter().flat_map(|s| title_files(&keys, s)).collect();
    let root = hfs0(&[
        ("update".into(), hfs0(&[])),
        ("normal".into(), hfs0(&[])),
        ("secure".into(), hfs0(&files)),
    ]);
    let mut out = vec![0u8; 0xF000];
    out[0x100..0x104].copy_from_slice(b"HEAD");
    out[0x104..0x108].copy_from_slice(&0x1000u32.to_le_bytes());
    out[0x130..0x138].copy_from_slice(&0xF000u64.to_le_bytes());
    out[0x138..0x140].copy_from_slice(&(root.len() as u64).to_le_bytes());
    out.extend_from_slice(&root);
    std::fs::write(path, out).unwrap();
}
