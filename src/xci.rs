//! Write the merged plan as an XCI. Header values are ported from upstream's `get_xciheader`,
//! `get_enc_gameinfo`, `getGCsize` and `gen_rhfs0_head`.

use crate::container::{Entry, HfsFile, hfs0_header};
use crate::crypto::cbc_encrypt;
use crate::keys::Keys;
use crate::nca::{
    HEADER_SIZE, NcaHeader, Ticket, read_range, standard_header, titlekey_from_ticket,
};
use crate::nsp::copy_entry;
use crate::select::MergePlan;
use anyhow::{Context, Result, anyhow, bail};
use indicatif::ProgressBar;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Write;

const BUF_SIZE: usize = 1024 * 1024;
const GAME_INFO_SIZE: usize = 0x70;
/// Offset of the root HFS0: 0x100 signature, 0x90 header fields, 0x70 game info, 0x6E00 of
/// zeros and 0x8000 of 0xFF.
const ROOT_OFFSET: usize = 0xF000;
const PADDING_END: usize = 0x7000;
/// Bytes of each NCA covered by its HFS0 hash: the signature sector, which `standard_header`
/// leaves as it was.
const NCA_HASH_SIZE: u32 = 0x200;

const FALLBACK_IV: &str = "5b408b145e277e81e5bf677c94888d7b";
const PACKAGE_ID: &str = "8750f4c0a9c5a966";
const INITIAL_DATA_HASH: &str = "1ab7c7b263e74e44cd3c68e40f7ef4a4d6571551d043fca8ecf5c489f2c66e7e";
/// Fallback encrypted game info for totals up to 4 GiB (see `reaches_gib`).
const FALLBACK_INFO_SMALL: &str = "9109ff82971ee9935011ca063f3c4d87a13d28a9928d74f149919eb782e1f0cfe4a5a3bdf978295cd52639a4991bdb1fed841779a3f85d23aa4242135616f5187c03cf0d97e5d218fdb245381fd1cf8dfb796fbeda4bf7f7d6b128ce89bc9eaa8552d42f597c5db866c67bb0dd8eea11";
/// Fallback encrypted game info for totals of 4 GiB and over.
const FALLBACK_INFO_LARGE: &str = "9298f35088f09f7da89a60d4cba6f96fa45bb6acabc751f95d3987426b38c3f210da0b700e5ece29a13cbe1da6d052cbf2087ce9af590538570d78b9cdd27fbeb4a0ac2adff9ba77754dd6675ac76223506b3bdabcb2e212fa465111ab7d51afc8b5b2b21c4b3f40654598620282add6";

/// Decode a hex constant of this file.
fn hx(s: &str) -> Vec<u8> {
    hex::decode(s).expect("hex constant")
}

/// Upstream's `round(total / GiB, 2) >= n`, in integers: the rounded value reaches `n` from
/// `n - 0.005` GiB, which can never be an exact tie.
fn reaches_gib(total: u64, n: u128) -> bool {
    u128::from(total) * 200 >= (n * 200 - 1) << 30
}

/// Card size byte and firmware speed bytes for an XCI of `total` bytes.
pub fn card_size(total: u64) -> (u8, [u8; 4]) {
    const SMALL: [u8; 4] = [0x11, 0x00, 0xa1, 0x00];
    const LARGE: [u8; 4] = [0x10, 0x00, 0xa1, 0x00];
    let table = [
        (32, 0xE3, LARGE),
        (16, 0xE2, LARGE),
        (8, 0xE1, LARGE),
        (4, 0xE0, LARGE),
        (2, 0xF0, SMALL),
        (1, 0xF8, SMALL),
    ];
    table
        .into_iter()
        .find(|&(gib, _, _)| reaches_gib(total, gib))
        .map_or((0xFA, SMALL), |(_, byte, speed)| (byte, speed))
}

/// Upstream's fixed encrypted game info, for keys files without `xci_header_key`.
pub fn fallback_game_info(total: u64) -> [u8; GAME_INFO_SIZE] {
    let blob = if reaches_gib(total, 4) {
        FALLBACK_INFO_LARGE
    } else {
        FALLBACK_INFO_SMALL
    };
    hx(blob).try_into().expect("game info size")
}

fn encrypted_game_info(key: &[u8; 16], iv: &[u8; 16], total: u64) -> [u8; GAME_INFO_SIZE] {
    let mut info = [0u8; GAME_INFO_SIZE];
    let fields: [&[u8]; 11] = [
        &hx("0100000000000000"), // firmware version
        &card_size(total).1,     // access control
        &hx("88130000"),         // read wait time
        &hx("00000000"),         // read wait time 2
        &hx("00000000"),         // write wait time
        &hx("00000000"),         // write wait time 2
        &hx("00110c00"),         // firmware mode
        &hx("5a000200"),         // CUP version
        &hx("00000000"),         // empty
        &hx("9bfb03ddbb7c5fca"), // update partition hash
        &hx("1608000000000001"), // CUP ID
    ];
    let mut at = 0;
    for f in fields {
        info[at..at + f.len()].copy_from_slice(f);
        at += f.len();
    }
    let mut reversed = *iv;
    reversed.reverse();
    cbc_encrypt(key, &reversed, &mut info);
    info
}

/// The root HFS0 and its three partition headers, ready to write in this order.
struct Partitions {
    root: Vec<u8>,
    update: Vec<u8>,
    normal: Vec<u8>,
    secure: Vec<u8>,
}

impl Partitions {
    /// All content goes in `secure`; `update` and `normal` are empty, as upstream.
    fn new(files: &[HfsFile]) -> Partitions {
        let update = hfs0_header(&[]);
        let normal = hfs0_header(&[]);
        let secure = hfs0_header(files);
        let data: u64 = files.iter().map(|f| f.size).sum();
        let part = |name: &str, header: &[u8], data: u64| HfsFile {
            name: name.to_string(),
            size: header.len() as u64 + data,
            hash_size: header.len() as u32,
            hash: Sha256::digest(header).into(),
        };
        let root = hfs0_header(&[
            part("update", &update, 0),
            part("normal", &normal, 0),
            part("secure", &secure, data),
        ]);
        Partitions {
            root,
            update,
            normal,
            secure,
        }
    }

    fn headers_len(&self) -> u64 {
        (self.root.len() + self.update.len() + self.normal.len() + self.secure.len()) as u64
    }

    /// Everything before the first NCA. The signature can't be genuine, so it is random.
    fn prefix(&self, total: u64, xci_key: Option<[u8; 16]>) -> Vec<u8> {
        let (iv, info): ([u8; 16], _) = match xci_key {
            Some(key) => {
                let iv = rand::random();
                (iv, encrypted_game_info(&key, &iv, total))
            }
            None => (
                hx(FALLBACK_IV).try_into().expect("IV size"),
                fallback_game_info(total),
            ),
        };
        let mut signature = [0u8; 0x100];
        rand::fill(&mut signature);
        let secure_at = ROOT_OFFSET + self.root.len() + self.update.len() + self.normal.len();
        let secure_units = (secure_at as u32 / 0x200).to_le_bytes();

        let mut out = Vec::with_capacity(ROOT_OFFSET + self.headers_len() as usize);
        out.extend_from_slice(&signature);
        out.extend_from_slice(b"HEAD");
        out.extend_from_slice(&secure_units);
        out.extend_from_slice(&u32::MAX.to_le_bytes()); // backup offset
        out.push(0); // key index
        out.push(card_size(total).0);
        out.push(0); // header version
        out.push(0); // flags
        out.extend_from_slice(&hx(PACKAGE_ID));
        out.extend_from_slice(&((total - 1) / 0x200).to_le_bytes()); // valid data end
        out.extend_from_slice(&iv);
        out.extend_from_slice(&(ROOT_OFFSET as u64).to_le_bytes());
        out.extend_from_slice(&(self.root.len() as u64).to_le_bytes());
        out.extend_from_slice(&Sha256::digest(&self.root[..0x200]));
        out.extend_from_slice(&hx(INITIAL_DATA_HASH));
        out.extend_from_slice(&1u32.to_le_bytes()); // secure mode
        out.extend_from_slice(&2u32.to_le_bytes()); // title key dec
        out.extend_from_slice(&0u32.to_le_bytes()); // key flag
        out.extend_from_slice(&secure_units); // normal area end
        out.extend_from_slice(&info);
        out.resize(PADDING_END, 0);
        out.resize(ROOT_OFFSET, 0xFF); // fake certificate
        for part in [&self.root, &self.update, &self.normal, &self.secure] {
            out.extend_from_slice(part);
        }
        out
    }
}

/// The NCAs for `secure`: `output_entries` without its tickets and certs.
fn nca_entries(plan: &MergePlan) -> Result<Vec<&Entry>> {
    let ncas: Vec<&Entry> = plan
        .output_entries()
        .into_iter()
        .filter(|e| e.name.to_ascii_lowercase().ends_with(".nca"))
        .collect();
    if ncas.is_empty() {
        bail!("nothing to write");
    }
    Ok(ncas)
}

/// The ticket for `rights_id` among those of the titles holding `nca`.
fn find_ticket<'a>(plan: &'a MergePlan, nca: &Entry, rights_id: &[u8; 16]) -> Result<&'a Entry> {
    let rid = hex::encode(rights_id);
    let ticket = plan
        .titles
        .iter()
        .filter(|t| t.meta == *nca || t.ncas.contains(nca))
        .flat_map(|t| &t.tickets)
        .find(|e| e.name.to_ascii_lowercase().starts_with(&rid))
        .ok_or_else(|| anyhow!("no ticket for rights ID {rid} needed by {}", nca.name))?;
    // The name only suggests a match; a wrong titlekey would write an unreadable NCA.
    let inside = Ticket::read(ticket)?.rights_id;
    if inside != *rights_id {
        bail!(
            "{}: {} holds rights ID {}, not the {rid} needed by {}",
            ticket.source.display(),
            ticket.name,
            hex::encode(inside),
            nca.name
        );
    }
    Ok(ticket)
}

/// Total size in bytes of the XCI for `plan`.
pub fn size(plan: &MergePlan) -> Result<u64> {
    // Header sizes depend on the names only, so no NCA is read here.
    let files: Vec<HfsFile> = nca_entries(plan)?
        .into_iter()
        .map(|e| HfsFile {
            name: e.name.clone(),
            size: e.size,
            hash_size: NCA_HASH_SIZE,
            hash: [0; 32],
        })
        .collect();
    Ok(total_size(&Partitions::new(&files), &files))
}

fn total_size(parts: &Partitions, files: &[HfsFile]) -> u64 {
    ROOT_OFFSET as u64 + parts.headers_len() + files.iter().map(|f| f.size).sum::<u64>()
}

struct Nca<'a> {
    entry: &'a Entry,
    /// New header, re-encrypted; only this much of each NCA is held.
    header: Box<[u8; HEADER_SIZE]>,
}

/// An XCI ready to write: every header is converted, so tickets can no longer fail.
pub struct Prepared<'a> {
    prefix: Vec<u8>,
    ncas: Vec<Nca<'a>>,
    total: u64,
}

/// Convert every NCA header and build the XCI headers, writing nothing.
pub fn prepare<'a>(plan: &'a MergePlan, keys: &Keys) -> Result<Prepared<'a>> {
    let entries = nca_entries(plan)?;
    let mut ncas = Vec::with_capacity(entries.len());
    let mut files = Vec::with_capacity(entries.len());
    for entry in entries {
        let header = NcaHeader::read(entry, keys)?;
        let titlekey = if header.rights_id == [0u8; 16] {
            None
        } else {
            let ticket = find_ticket(plan, entry, &header.rights_id)?;
            Some(titlekey_from_ticket(ticket, header.master_index, keys)?)
        };
        let new = standard_header(&header, titlekey.as_ref(), keys)
            .with_context(|| format!("{}: {}", entry.source.display(), entry.name))?;
        let sector = read_range(entry, 0, NCA_HASH_SIZE.into(), "NCA signature")?;
        files.push(HfsFile {
            name: entry.name.clone(),
            size: entry.size,
            hash_size: NCA_HASH_SIZE,
            hash: Sha256::digest(&sector).into(),
        });
        ncas.push(Nca {
            entry,
            header: Box::new(new),
        });
    }
    let parts = Partitions::new(&files);
    let total = total_size(&parts, &files);
    Ok(Prepared {
        prefix: parts.prefix(total, keys.xci_header_key()),
        ncas,
        total,
    })
}

impl Prepared<'_> {
    pub fn size(&self) -> u64 {
        self.total
    }

    pub fn write(&self, out: &mut File, progress: &ProgressBar) -> Result<()> {
        out.write_all(&self.prefix)?;
        progress.inc(self.prefix.len() as u64);
        let mut buf = vec![0u8; BUF_SIZE];
        let mut src = None;
        for nca in &self.ncas {
            out.write_all(&nca.header[..])?;
            progress.inc(HEADER_SIZE as u64);
            let head = HEADER_SIZE as u64;
            let body = Entry {
                offset: nca.entry.offset + head,
                size: nca.entry.size - head,
                ..nca.entry.clone()
            };
            copy_entry(&body, &mut src, out, &mut buf, progress)?;
        }
        Ok(())
    }
}

pub fn write(plan: &MergePlan, keys: &Keys, out: &mut File, progress: &ProgressBar) -> Result<()> {
    prepare(plan, keys)?.write(out, progress)
}
