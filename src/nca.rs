//! NCA header parsing and bounded reads of NCA contents.

use crate::container::Entry;
use crate::crypto::{ecb_decrypt, ecb_encrypt, xts_decrypt, xts_encrypt};
use crate::keys::Keys;
use anyhow::{Context, Result, anyhow, bail};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

pub const HEADER_SIZE: usize = 0xC00;

#[derive(Debug)]
pub struct NcaHeader {
    /// Decrypted first 0xC00 bytes.
    pub plain: Box<[u8; HEADER_SIZE]>,
    pub content_type: u8,
    pub master_index: u8,
    pub kaek_index: u8,
    pub rights_id: [u8; 16],
}

impl NcaHeader {
    pub fn read(entry: &Entry, keys: &Keys) -> Result<NcaHeader> {
        Self::read_inner(entry, keys)
            .with_context(|| format!("{}: {}", entry.source.display(), entry.name))
    }

    fn read_inner(entry: &Entry, keys: &Keys) -> Result<NcaHeader> {
        let key = keys.header_key()?;
        let raw = read_range(entry, 0, HEADER_SIZE as u64, "NCA header")?;
        let mut plain: Box<[u8; HEADER_SIZE]> = raw
            .into_boxed_slice()
            .try_into()
            .map_err(|_| anyhow!("internal: header size"))?;
        xts_decrypt(&key, &mut plain[..], 0x200);
        if &plain[0x200..0x204] != b"NCA3" {
            bail!(
                "header did not decrypt to NCA3 (found bytes {}): the header_key in your keys file may be wrong, or this is an older NCA format that is not supported",
                hex::encode(&plain[0x200..0x204])
            );
        }
        let kaek_index = plain[0x207];
        if kaek_index > 2 {
            bail!("corrupt NCA header: invalid key area key index {kaek_index}");
        }
        let generation = plain[0x206].max(plain[0x220]);
        let mut rights_id = [0u8; 16];
        rights_id.copy_from_slice(&plain[0x230..0x240]);
        Ok(NcaHeader {
            content_type: plain[0x205],
            master_index: generation.saturating_sub(1),
            kaek_index,
            rights_id,
            plain,
        })
    }
}

/// The fields of a ticket that matter here. A ticket starts with a u32 signature type, then
/// the signature and padding; everything else sits at a fixed offset from the end of those.
pub struct Ticket {
    pub rights_id: [u8; 16],
    pub key_type: u8,
    titlekey: [u8; 16],
}

/// Size of the signature type, signature and padding, as in upstream's `Fs/Ticket.py`.
fn ticket_body_offset(signature_type: u32) -> Result<u64> {
    Ok(match signature_type {
        0x10000 | 0x10003 => 0x240, // RSA-4096
        0x10001 | 0x10004 => 0x140, // RSA-2048
        0x10002 | 0x10005 => 0x80,  // ECDSA
        n => bail!("unknown ticket signature type {n:#x}"),
    })
}

impl Ticket {
    pub fn read(entry: &Entry) -> Result<Ticket> {
        Self::read_inner(entry)
            .with_context(|| format!("{}: {}", entry.source.display(), entry.name))
    }

    fn read_inner(entry: &Entry) -> Result<Ticket> {
        let signature_type = read_range(entry, 0, 4, "ticket")?;
        let body = ticket_body_offset(u32::from_le_bytes(
            signature_type
                .try_into()
                .map_err(|_| anyhow!("internal: ticket read"))?,
        ))?;
        let raw = read_range(entry, body, 0x170, "ticket")?;
        let mut ticket = Ticket {
            rights_id: [0; 16],
            key_type: raw[0x141],
            titlekey: [0; 16],
        };
        ticket.titlekey.copy_from_slice(&raw[0x40..0x50]);
        ticket.rights_id.copy_from_slice(&raw[0x160..0x170]);
        Ok(ticket)
    }

    pub fn is_personalised(&self) -> bool {
        self.key_type == 1
    }
}

/// Decrypt the common titlekey in `ticket`. `master_index` comes from the NCA that uses it.
pub fn titlekey_from_ticket(ticket: &Entry, master_index: u8, keys: &Keys) -> Result<[u8; 16]> {
    let parsed = Ticket::read(ticket)?;
    let inner = || -> Result<[u8; 16]> {
        match parsed.key_type {
            0 => {}
            1 => bail!("personalised tickets are not supported"),
            n => bail!("unknown ticket type {n}"),
        }
        let mut key = parsed.titlekey;
        ecb_decrypt(&keys.titlekek(master_index)?, &mut key);
        Ok(key)
    };
    inner().with_context(|| format!("{}: {}", ticket.source.display(), ticket.name))
}

/// The header as standard crypto, re-encrypted: rights ID cleared and, for a titlekey NCA, the
/// titlekey in all four key area slots. The distribution byte at 0x204 keeps its source value,
/// as upstream does, so a header with no rights ID comes out byte-identical to the source.
pub fn standard_header(
    header: &NcaHeader,
    titlekey: Option<&[u8; 16]>,
    keys: &Keys,
) -> Result<[u8; HEADER_SIZE]> {
    let mut out = *header.plain;
    match titlekey {
        Some(key) => {
            let area = &mut out[0x300..0x340];
            for slot in area.chunks_exact_mut(16) {
                slot.copy_from_slice(key);
            }
            let kaek = keys.key_area_key(header.master_index, header.kaek_index)?;
            ecb_encrypt(&kaek, area);
        }
        None if header.rights_id != [0u8; 16] => {
            bail!(
                "NCA with rights ID {} needs a titlekey",
                hex::encode(header.rights_id)
            );
        }
        None => {}
    }
    out[0x230..0x240].fill(0);
    xts_encrypt(&keys.header_key()?, &mut out, 0x200);
    Ok(out)
}

/// Read `len` bytes at `offset` within the entry, failing if it runs past the entry or file.
pub fn read_range(entry: &Entry, offset: u64, len: u64, what: &str) -> Result<Vec<u8>> {
    let end = offset
        .checked_add(len)
        .filter(|&e| e <= entry.size)
        .ok_or_else(|| anyhow!("truncated: {what} lies past the end of the file entry"))?;
    let abs = entry
        .offset
        .checked_add(offset)
        .ok_or_else(|| anyhow!("corrupt: {what} offset overflows"))?;
    let mut buf = vec![0u8; (end - offset) as usize];
    let mut f = File::open(&entry.source)
        .with_context(|| format!("cannot open {}", entry.source.display()))?;
    f.seek(SeekFrom::Start(abs))?;
    f.read_exact(&mut buf)
        .map_err(|_| anyhow!("truncated: cannot read {what}"))?;
    Ok(buf)
}
