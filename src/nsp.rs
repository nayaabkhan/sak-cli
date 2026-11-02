//! Write the merged plan as an NSP (a PFS0 container).

use crate::container::{Entry, pfs0_header};
use crate::select::MergePlan;
use anyhow::{Context, Result, bail};
use indicatif::ProgressBar;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};

const BUF_SIZE: usize = 1024 * 1024;

fn header(entries: &[&Entry]) -> Vec<u8> {
    let list: Vec<(String, u64)> = entries.iter().map(|e| (e.name.clone(), e.size)).collect();
    pfs0_header(&list)
}

/// Total size in bytes of the NSP for `plan`.
pub fn size(plan: &MergePlan) -> u64 {
    let entries = plan.output_entries();
    header(&entries).len() as u64 + entries.iter().map(|e| e.size).sum::<u64>()
}

/// Copy `e` to `out` through a 1 MiB buffer, advancing `progress` as bytes go.
pub fn copy_entry(
    e: &Entry,
    src: &mut Option<(std::path::PathBuf, File)>,
    out: &mut impl Write,
    buf: &mut [u8],
    progress: &ProgressBar,
) -> Result<()> {
    if src.as_ref().map(|(p, _)| p != &e.source).unwrap_or(true) {
        let f =
            File::open(&e.source).with_context(|| format!("cannot open {}", e.source.display()))?;
        *src = Some((e.source.clone(), f));
    }
    let f = &mut src.as_mut().unwrap().1;
    f.seek(SeekFrom::Start(e.offset))
        .with_context(|| format!("cannot read {} in {}", e.name, e.source.display()))?;
    let mut left = e.size;
    while left > 0 {
        let n = left.min(buf.len() as u64) as usize;
        f.read_exact(&mut buf[..n])
            .with_context(|| format!("cannot read {} in {}", e.name, e.source.display()))?;
        out.write_all(&buf[..n])?;
        progress.inc(n as u64);
        left -= n as u64;
    }
    Ok(())
}

pub fn write(plan: &MergePlan, out: &mut File, progress: &ProgressBar) -> Result<()> {
    let entries = plan.output_entries();
    if entries.is_empty() {
        bail!("nothing to write");
    }
    let head = header(&entries);
    out.write_all(&head)?;
    progress.inc(head.len() as u64);
    let mut buf = vec![0u8; BUF_SIZE];
    let mut src = None;
    for e in entries {
        copy_entry(e, &mut src, out, &mut buf, progress)?;
    }
    Ok(())
}
