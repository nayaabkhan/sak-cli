//! Scan a folder of NSP/XCI files, validate them and select what to merge.

use crate::cnmt::{Cnmt, TitleKind, read_cnmt};
use crate::container::{Entry, open_entries};
use crate::keys::Keys;
use crate::nca::NcaHeader;
use anyhow::{Context, Result, anyhow, bail};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// One title to write: its cnmt plus the entries (all from one input file).
#[derive(Debug)]
pub struct Title {
    pub cnmt: Cnmt,
    /// Content NCAs, excluding delta fragments.
    pub ncas: Vec<Entry>,
    pub meta: Entry,
    pub tickets: Vec<Entry>,
    pub certs: Vec<Entry>,
}

#[derive(Debug)]
pub struct MergePlan {
    pub base_title: u64,
    /// Base first, then updates, then DLC; each group by title ID.
    pub titles: Vec<Title>,
    /// Human-readable notes about titles left out.
    pub skipped: Vec<String>,
}

impl MergePlan {
    /// Files to write, in order: for each title its NCAs, meta NCA, tickets, certs.
    /// Titles may share a ticket or cert; each name appears once, first one kept.
    pub fn output_entries(&self) -> Vec<&Entry> {
        let mut seen = std::collections::HashSet::new();
        let mut out = Vec::new();
        for t in &self.titles {
            let all = t
                .ncas
                .iter()
                .chain(std::iter::once(&t.meta))
                .chain(&t.tickets)
                .chain(&t.certs);
            for e in all {
                if seen.insert(e.name.as_str()) {
                    out.push(e);
                }
            }
        }
        out
    }
}

const DELTA_FRAGMENT: u8 = 6;

struct Candidate {
    cnmt: Cnmt,
    file: PathBuf,
    entries: Vec<Entry>,
    meta: Entry,
}

fn canon(p: &Path) -> PathBuf {
    if let Ok(c) = p.canonicalize() {
        return c;
    }
    match (
        p.parent().and_then(|d| d.canonicalize().ok()),
        p.file_name(),
    ) {
        (Some(d), Some(n)) => d.join(n),
        _ => p.to_path_buf(),
    }
}

fn ext_lower(p: &Path) -> Option<String> {
    p.extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase)
}

fn is_hidden(p: &Path) -> bool {
    p.file_name()
        .is_some_and(|n| n.as_encoded_bytes().starts_with(b"."))
}

pub fn describe(c: &Cnmt) -> String {
    let what = match c.kind {
        TitleKind::Application => "base game",
        TitleKind::Patch => "update",
        TitleKind::AddOn => "DLC",
    };
    format!("{what} {:016x} version {}", c.title_id, c.version)
}

fn scan_files(dir: &Path, output: &Path) -> Result<Vec<PathBuf>> {
    let mut part = output.as_os_str().to_owned();
    part.push(OsString::from(".part"));
    let skip = [canon(output), canon(Path::new(&part))];
    let mut files = Vec::new();
    let rd =
        std::fs::read_dir(dir).with_context(|| format!("cannot read folder {}", dir.display()))?;
    for ent in rd {
        let path = ent
            .with_context(|| format!("cannot read folder {}", dir.display()))?
            .path();
        // macOS writes `._Game.nsp` AppleDouble files beside the real ones on some disks.
        if is_hidden(&path) || skip.contains(&canon(&path)) {
            continue;
        }
        let ext = ext_lower(&path);
        match std::fs::metadata(&path) {
            Ok(m) if m.is_file() => {}
            // A split NSP or XCI is a folder of parts on FAT32 disks.
            Ok(m) if m.is_dir() && matches!(ext.as_deref(), Some("nsp" | "xci")) => {
                bail!("split files are not supported: {}", path.display())
            }
            _ => continue,
        }
        match ext.as_deref() {
            Some("nsp" | "xci") => files.push(path),
            Some("nsz" | "xcz") => {
                bail!("compressed files are not supported yet: {}", path.display())
            }
            Some("ns0" | "xc0") => bail!("split files are not supported: {}", path.display()),
            _ => {}
        }
    }
    files.sort();
    Ok(files)
}

pub fn build_plan(dir: &Path, output: &Path, keys: &Keys) -> Result<MergePlan> {
    let files = scan_files(dir, output)?;
    if files.is_empty() {
        bail!("no .nsp or .xci files found in {}", dir.display());
    }

    // Highest version per title ID; ties go to the first file by sorted path.
    let mut chosen: BTreeMap<u64, Candidate> = BTreeMap::new();
    let mut skipped = Vec::new();
    for file in &files {
        // Strict on purpose: an unreadable NCA or cnmt in any input stops the merge, so a
        // corrupt newest update can never be silently dropped. The errors already name
        // the file and entry.
        let entries = open_entries(file)?;
        for e in entries
            .iter()
            .filter(|e| e.name.to_ascii_lowercase().ends_with(".nca"))
        {
            let header = NcaHeader::read(e, keys)?;
            if header.content_type != 1 {
                continue;
            }
            let cnmt = read_cnmt(e, &header, keys)?;
            let cand = Candidate {
                cnmt,
                file: file.clone(),
                entries: entries.clone(),
                meta: e.clone(),
            };
            let id = cand.cnmt.title_id;
            match chosen.get(&id) {
                Some(cur) if cur.cnmt.version >= cand.cnmt.version => {
                    skipped.push(format!(
                        "{}: {} (already have version {} from {})",
                        file.display(),
                        describe(&cand.cnmt),
                        cur.cnmt.version,
                        cur.file.display()
                    ));
                }
                Some(cur) => {
                    skipped.push(format!(
                        "{}: {} (superseded by version {} from {})",
                        cur.file.display(),
                        describe(&cur.cnmt),
                        cand.cnmt.version,
                        file.display()
                    ));
                    chosen.insert(id, cand);
                }
                None => {
                    chosen.insert(id, cand);
                }
            }
        }
    }

    let bases: Vec<&Candidate> = chosen
        .values()
        .filter(|c| c.cnmt.kind == TitleKind::Application)
        .collect();
    let base_title = match bases.as_slice() {
        [] => bail!("no base game found in {}", dir.display()),
        [b] => b.cnmt.title_id,
        many => {
            let list: Vec<String> = many
                .iter()
                .map(|b| format!("{:016x} ({})", b.cnmt.title_id, b.file.display()))
                .collect();
            bail!("found more than one base game: {}", list.join(", "));
        }
    };
    let foreign: Vec<String> = chosen
        .values()
        .filter(|c| c.cnmt.kind != TitleKind::Application && c.cnmt.base_id != base_title)
        .map(|c| {
            format!(
                "{} in {} belongs to base game {:016x}",
                describe(&c.cnmt),
                c.file.display(),
                c.cnmt.base_id
            )
        })
        .collect();
    if !foreign.is_empty() {
        bail!(
            "files do not belong to base game {base_title:016x}: {}",
            foreign.join("; ")
        );
    }

    let mut titles = Vec::new();
    for cand in chosen.into_values() {
        titles.push(finish(cand, keys)?);
    }
    let rank = |t: &Title| match t.cnmt.kind {
        TitleKind::Application => 0,
        TitleKind::Patch => 1,
        TitleKind::AddOn => 2,
    };
    titles.sort_by_key(|t| (rank(t), t.cnmt.title_id));
    Ok(MergePlan {
        base_title,
        titles,
        skipped,
    })
}

fn find_entry<'a>(entries: &'a [Entry], name: &str) -> Option<&'a Entry> {
    entries.iter().find(|e| e.name.eq_ignore_ascii_case(name))
}

/// Resolve a selected title's content, tickets and certs, all from its own file.
fn finish(cand: Candidate, keys: &Keys) -> Result<Title> {
    let mut ncas = Vec::new();
    let mut tickets: Vec<Entry> = Vec::new();
    let mut certs: Vec<Entry> = Vec::new();
    for c in cand
        .cnmt
        .contents
        .iter()
        .filter(|c| c.kind != DELTA_FRAGMENT)
    {
        let nca = find_entry(&cand.entries, &format!("{}.nca", c.nca_id)).ok_or_else(|| {
            if find_entry(&cand.entries, &format!("{}.ncz", c.nca_id)).is_some() {
                anyhow!(
                    "compressed NCA {}.ncz in {} is not supported yet",
                    c.nca_id,
                    cand.file.display()
                )
            } else {
                anyhow!(
                    "{} needs NCA {} but it is missing from {}",
                    describe(&cand.cnmt),
                    c.nca_id,
                    cand.file.display()
                )
            }
        })?;
        let header = NcaHeader::read(nca, keys)?;
        if header.rights_id != [0u8; 16] {
            let rid = hex::encode(header.rights_id);
            if find_entry(&cand.entries, &format!("{rid}.tik")).is_none() {
                bail!(
                    "{} needs a ticket for rights ID {rid} but none is in {}",
                    describe(&cand.cnmt),
                    cand.file.display()
                );
            }
            for (ext, list) in [("tik", &mut tickets), ("cert", &mut certs)] {
                if let Some(e) = find_entry(&cand.entries, &format!("{rid}.{ext}"))
                    && !list.contains(e)
                {
                    list.push(e.clone());
                }
            }
        }
        ncas.push(nca.clone());
    }
    Ok(Title {
        cnmt: cand.cnmt,
        ncas,
        meta: cand.meta,
        tickets,
        certs,
    })
}
