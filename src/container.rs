//! Readers and header generators for the PFS0 (NSP) and HFS0 (XCI) containers.

use anyhow::{Context, Result, anyhow, bail};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

/// A file inside a container. `offset` is absolute within `source`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub source: PathBuf,
    pub name: String,
    pub offset: u64,
    pub size: u64,
}

pub struct HfsFile {
    pub name: String,
    pub size: u64,
    pub hash_size: u32,
    pub hash: [u8; 32],
}

/// Largest table (entries plus string table) we will read.
const MAX_TABLE: u64 = 64 * 1024 * 1024;
/// Offset of the root HFS0 in an XCI.
const XCI_ROOT_HFS0: u64 = 0xF000;

/// PFS0 header for files with the given names and sizes, laid out back to back.
pub fn pfs0_header(files: &[(String, u64)]) -> Vec<u8> {
    let mut strtab = Vec::new();
    let mut name_offsets = Vec::new();
    for (name, _) in files {
        name_offsets.push(strtab.len() as u32);
        strtab.extend_from_slice(name.as_bytes());
        strtab.push(0);
    }
    let header_size = 0x10 + 0x18 * files.len() + strtab.len();
    let pad = 0x10 - header_size % 0x10;
    strtab.resize(strtab.len() + pad, 0);

    let mut out = Vec::with_capacity(header_size + pad);
    out.extend_from_slice(b"PFS0");
    out.extend_from_slice(&(files.len() as u32).to_le_bytes());
    out.extend_from_slice(&(strtab.len() as u32).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    let mut offset = 0u64;
    for ((_, size), name_off) in files.iter().zip(name_offsets) {
        out.extend_from_slice(&offset.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&name_off.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        offset += size;
    }
    out.extend_from_slice(&strtab);
    out
}

/// HFS0 header, zero padded to a multiple of 0x200; files are laid out back to back.
pub fn hfs0_header(files: &[HfsFile]) -> Vec<u8> {
    let mut strtab = Vec::new();
    let mut name_offsets = Vec::new();
    for f in files {
        name_offsets.push(strtab.len() as u32);
        strtab.extend_from_slice(f.name.as_bytes());
        strtab.push(0);
    }
    let header_size = 0x10 + 0x40 * files.len() + strtab.len();
    strtab.resize(
        strtab.len() + (header_size.next_multiple_of(0x200) - header_size),
        0,
    );

    let mut out = Vec::with_capacity(0x10 + 0x40 * files.len() + strtab.len());
    out.extend_from_slice(b"HFS0");
    out.extend_from_slice(&(files.len() as u32).to_le_bytes());
    out.extend_from_slice(&(strtab.len() as u32).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    let mut offset = 0u64;
    for (f, name_off) in files.iter().zip(name_offsets) {
        out.extend_from_slice(&offset.to_le_bytes());
        out.extend_from_slice(&f.size.to_le_bytes());
        out.extend_from_slice(&name_off.to_le_bytes());
        out.extend_from_slice(&f.hash_size.to_le_bytes());
        out.extend_from_slice(&0u64.to_le_bytes());
        out.extend_from_slice(&f.hash);
        offset += f.size;
    }
    out.extend_from_slice(&strtab);
    out
}

/// List the files in an NSP (PFS0) or the `secure` partition of an XCI, by extension.
pub fn open_entries(path: &Path) -> Result<Vec<Entry>> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase);
    let mut file = File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
    let len = file
        .metadata()
        .with_context(|| format!("cannot read {}", path.display()))?
        .len();
    let result = match ext.as_deref() {
        Some("nsp") => read_table(&mut file, path, 0, len, Kind::Pfs0),
        Some("xci") => read_xci(&mut file, path, len),
        _ => bail!("unsupported file type (expected .nsp or .xci)"),
    };
    result.with_context(|| format!("{}", path.display()))
}

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Pfs0,
    Hfs0,
}

impl Kind {
    fn magic(self) -> &'static [u8; 4] {
        match self {
            Kind::Pfs0 => b"PFS0",
            Kind::Hfs0 => b"HFS0",
        }
    }
    fn entry_size(self) -> u64 {
        match self {
            Kind::Pfs0 => 0x18,
            Kind::Hfs0 => 0x40,
        }
    }
}

fn read_at(file: &mut File, offset: u64, len: u64, what: &str) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; len as usize];
    file.seek(SeekFrom::Start(offset))?;
    file.read_exact(&mut buf)
        .map_err(|_| anyhow!("truncated: cannot read {what}"))?;
    Ok(buf)
}

fn le32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
fn le64(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

/// Parse the table at `base`; returned entries have absolute offsets and are checked
/// against `file_len`. `base + header size` is where data begins.
fn read_table(
    file: &mut File,
    path: &Path,
    base: u64,
    file_len: u64,
    kind: Kind,
) -> Result<Vec<Entry>> {
    let name = |k: Kind| String::from_utf8_lossy(k.magic()).into_owned();
    let head = read_at(file, base, 0x10, "header")
        .map_err(|e| anyhow!("{e} (expected a {} container)", name(kind)))?;
    if &head[..4] != kind.magic() {
        bail!("not a valid {} container (bad magic)", name(kind));
    }
    let count = le32(&head, 4) as u64;
    let strtab = le32(&head, 8) as u64;
    let table = count
        .checked_mul(kind.entry_size())
        .and_then(|t| t.checked_add(strtab))
        .filter(|&t| t <= MAX_TABLE)
        .ok_or_else(|| anyhow!("header claims an implausibly large file table"))?;
    let data_start = base
        .checked_add(0x10 + table)
        .filter(|&d| d <= file_len)
        .ok_or_else(|| anyhow!("truncated: file table runs past end of file"))?;
    let raw = read_at(file, base + 0x10, table, "file table")?;
    let (entries, strings) = raw.split_at((count * kind.entry_size()) as usize);

    let mut out = Vec::with_capacity(count as usize);
    for e in entries.chunks_exact(kind.entry_size() as usize) {
        let rel = le64(e, 0);
        let size = le64(e, 8);
        let name_off = le32(e, 16) as usize;
        let bytes = strings
            .get(name_off..)
            .ok_or_else(|| anyhow!("entry name offset is outside the string table"))?;
        let end = bytes
            .iter()
            .position(|&b| b == 0)
            .ok_or_else(|| anyhow!("unterminated entry name"))?;
        let name = std::str::from_utf8(&bytes[..end])
            .map_err(|_| anyhow!("corrupt file table: entry name is not valid UTF-8"))?
            .to_owned();
        let offset = data_start
            .checked_add(rel)
            .filter(|o| o.checked_add(size).is_some_and(|end| end <= file_len))
            .ok_or_else(|| anyhow!("entry {name} extends past the end of the file"))?;
        out.push(Entry {
            source: path.to_path_buf(),
            name,
            offset,
            size,
        });
    }
    Ok(out)
}

fn read_xci(file: &mut File, path: &Path, len: u64) -> Result<Vec<Entry>> {
    let head = read_at(file, 0x100, 4, "XCI header")?;
    if &head != b"HEAD" {
        bail!("not a valid XCI (bad magic)");
    }
    let root = read_table(file, path, XCI_ROOT_HFS0, len, Kind::Hfs0)?;
    let secure = root
        .iter()
        .find(|e| e.name == "secure")
        .ok_or_else(|| anyhow!("XCI has no secure partition"))?;
    read_table(
        file,
        path,
        secure.offset,
        secure.offset + secure.size,
        Kind::Hfs0,
    )
}
