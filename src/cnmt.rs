//! Content meta (cnmt) parsing: finds and decrypts the cnmt inside a meta NCA.

use crate::container::Entry;
use crate::crypto::{ctr_apply, ecb_decrypt};
use crate::keys::Keys;
use crate::nca::{NcaHeader, read_range};
use anyhow::{Context, Result, anyhow, bail};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TitleKind {
    Application,
    Patch,
    AddOn,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Content {
    /// Lowercase hex NCA ID.
    pub nca_id: String,
    pub size: u64,
    pub kind: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cnmt {
    pub title_id: u64,
    pub version: u32,
    pub kind: TitleKind,
    /// Equal to `title_id` for an Application.
    pub base_id: u64,
    pub contents: Vec<Content>,
}

/// Largest PFS0 region of the meta section we will read into memory.
const MAX_PFS0: u64 = 16 * 1024 * 1024;

fn le<const N: usize>(b: &[u8], o: usize) -> Result<[u8; N]> {
    o.checked_add(N)
        .and_then(|e| b.get(o..e))
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| anyhow!("truncated data"))
}
fn u16_at(b: &[u8], o: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(le(b, o)?))
}
fn u32_at(b: &[u8], o: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(le(b, o)?))
}
fn u64_at(b: &[u8], o: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(le(b, o)?))
}

pub fn read_cnmt(entry: &Entry, header: &NcaHeader, keys: &Keys) -> Result<Cnmt> {
    read_cnmt_inner(entry, header, keys)
        .with_context(|| format!("{}: {}", entry.source.display(), entry.name))
}

fn read_cnmt_inner(entry: &Entry, header: &NcaHeader, keys: &Keys) -> Result<Cnmt> {
    let p = &header.plain[..];
    let sec_start = (u32_at(p, 0x240)? as u64) * 0x200;
    let sec_end = (u32_at(p, 0x244)? as u64) * 0x200;
    if sec_end <= sec_start {
        bail!("corrupt NCA header: section 0 is empty");
    }
    let sh = 0x400;
    let crypto_type = p[sh + 4];
    if crypto_type != 3 {
        bail!("unsupported section encryption type {crypto_type} in meta NCA (expected CTR)");
    }
    let pfs_off = u64_at(p, sh + 0x38 + 8)?;
    let pfs_size = u64_at(p, sh + 0x38 + 0x10)?;
    let avail = (sec_end - sec_start)
        .checked_sub(pfs_off)
        .ok_or_else(|| anyhow!("corrupt NCA header: PFS0 offset past end of section"))?;
    if pfs_size > avail || pfs_size > MAX_PFS0 {
        bail!("corrupt NCA header: PFS0 size {pfs_size:#x} out of range");
    }
    let abs = sec_start
        .checked_add(pfs_off)
        .ok_or_else(|| anyhow!("corrupt NCA header: PFS0 offset overflows"))?;

    let kaek = keys.key_area_key(header.master_index, header.kaek_index)?;
    let mut key: [u8; 16] = p[0x320..0x330].try_into().unwrap();
    ecb_decrypt(&kaek, &mut key);
    let mut ctr_high: [u8; 8] = p[sh + 0x140..sh + 0x148].try_into().unwrap();
    ctr_high.reverse();

    let mut data = read_range(entry, abs, pfs_size, "cnmt section")?;
    ctr_apply(&key, ctr_high, abs, &mut data);
    let cnmt = find_cnmt(&data)?;
    parse_cnmt(cnmt)
}

/// Find the `*.cnmt` file in an in-memory PFS0.
fn find_cnmt(pfs: &[u8]) -> Result<&[u8]> {
    if pfs.get(..4) != Some(b"PFS0") {
        bail!("meta section is not a PFS0 (wrong key or corrupt file)");
    }
    let count = u32_at(pfs, 4)? as usize;
    let strtab_size = u32_at(pfs, 8)? as usize;
    let entries_end = count
        .checked_mul(0x18)
        .and_then(|n| n.checked_add(0x10))
        .ok_or_else(|| anyhow!("corrupt PFS0"))?;
    let data_start = entries_end
        .checked_add(strtab_size)
        .ok_or_else(|| anyhow!("corrupt PFS0"))?;
    let strtab = pfs
        .get(entries_end..data_start)
        .ok_or_else(|| anyhow!("truncated PFS0 header"))?;
    for i in 0..count {
        let e = 0x10 + i * 0x18;
        let name_off = u32_at(pfs, e + 16)? as usize;
        let name_bytes = strtab
            .get(name_off..)
            .ok_or_else(|| anyhow!("corrupt PFS0 name offset"))?;
        let name_bytes = &name_bytes[..name_bytes
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(name_bytes.len())];
        if name_bytes.ends_with(b".cnmt") {
            let off = usize::try_from(u64_at(pfs, e)?).ok();
            let size = usize::try_from(u64_at(pfs, e + 8)?).ok();
            return off
                .zip(size)
                .and_then(|(o, s)| Some((data_start.checked_add(o)?, s)))
                .and_then(|(st, s)| pfs.get(st..st.checked_add(s)?))
                .ok_or_else(|| anyhow!("corrupt cnmt: file extends past the meta section"));
        }
    }
    bail!("no .cnmt file in meta NCA")
}

fn parse_cnmt(c: &[u8]) -> Result<Cnmt> {
    let title_id = u64_at(c, 0)?;
    let version = u32_at(c, 8)?;
    let kind = match c
        .get(0xC)
        .copied()
        .ok_or_else(|| anyhow!("truncated cnmt"))?
    {
        0x80 => TitleKind::Application,
        0x81 => TitleKind::Patch,
        0x82 => TitleKind::AddOn,
        t => bail!("unsupported cnmt type {t:#x}"),
    };
    let ext = u16_at(c, 0xE)? as usize;
    let count = u16_at(c, 0x10)? as usize;
    let base_id = if kind == TitleKind::Application {
        title_id
    } else {
        if ext < 8 {
            bail!("corrupt cnmt: extended header too small ({ext:#x})");
        }
        u64_at(c, 0x20)?
    };
    let first = 0x20usize + ext;
    let mut contents = Vec::with_capacity(count.min(1024));
    for i in 0..count {
        let r = i
            .checked_mul(0x38)
            .and_then(|n| n.checked_add(first))
            .ok_or_else(|| anyhow!("corrupt cnmt"))?;
        let rec = r
            .checked_add(0x38)
            .and_then(|e| c.get(r..e))
            .ok_or_else(|| anyhow!("corrupt cnmt: {count} content records do not fit"))?;
        let mut size = [0u8; 8];
        size[..6].copy_from_slice(&rec[0x30..0x36]);
        contents.push(Content {
            nca_id: hex::encode(&rec[0x20..0x30]),
            size: u64::from_le_bytes(size),
            kind: rec[0x36],
        });
    }
    Ok(Cnmt {
        title_id,
        version,
        kind,
        base_id,
        contents,
    })
}
