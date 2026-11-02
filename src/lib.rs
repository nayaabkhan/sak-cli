pub mod cnmt;
pub mod container;
pub mod crypto;
pub mod keys;
pub mod nca;
pub mod nsp;
pub mod select;
pub mod xci;

use anyhow::{Context, Result, bail};
use clap::Args;
use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};
use std::ffi::OsString;
use std::fs::File;
use std::path::{Path, PathBuf};

#[derive(Args, Debug)]
pub struct MergeArgs {
    /// Output file, .nsp or .xci
    #[arg(short, long)]
    pub output: PathBuf,
    /// Keys file (default: ~/.switch/prod.keys)
    #[arg(long)]
    pub keys: Option<PathBuf>,
    /// Overwrite the output file if it exists
    #[arg(long)]
    pub force: bool,
}

pub fn run_merge(args: &MergeArgs) -> Result<()> {
    let ext = args
        .output
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase);
    if !matches!(ext.as_deref(), Some("nsp" | "xci")) {
        bail!(
            "output file must end in .nsp or .xci: {}",
            args.output.display()
        );
    }
    check_output(&args.output, args.force)?;
    let keys_path = match &args.keys {
        Some(p) => p.clone(),
        None => match dirs::home_dir() {
            Some(h) => h.join(".switch").join("prod.keys"),
            None => bail!("cannot find home folder; pass the keys file with --keys"),
        },
    };
    if !keys_path.is_file() {
        bail!(
            "keys file not found at {}; pass its location with --keys",
            keys_path.display()
        );
    }
    let keys = keys::Keys::load(&keys_path)?;

    let dir = std::env::current_dir().context("cannot find current folder")?;
    let plan = select::build_plan(&dir, &args.output, &keys)?;

    println!("Found {} title(s):", plan.titles.len());
    for t in &plan.titles {
        println!("  {}", select::describe(&t.cnmt));
    }
    if !plan.skipped.is_empty() {
        println!("Skipped:");
        for s in &plan.skipped {
            println!("  {s}");
        }
    }

    if ext.as_deref() == Some("xci") {
        println!(
            "warning: an XCI header signature cannot be genuine; this file only runs where the loader or emulator ignores the signature"
        );
        // Before write_atomic, so a bad ticket writes nothing.
        let prepared = xci::prepare(&plan, &keys)?;
        write_output(args, prepared.size(), |f, progress| {
            prepared.write(f, progress)
        })
    } else {
        for warning in nsp::personal_ticket_warnings(&plan)? {
            println!("warning: {warning}");
        }
        write_output(args, nsp::size(&plan), |f, progress| {
            nsp::write(&plan, f, progress)
        })
    }
}

fn write_output(
    args: &MergeArgs,
    size: u64,
    write: impl FnOnce(&mut File, &ProgressBar) -> Result<()>,
) -> Result<()> {
    let progress = ProgressBar::with_draw_target(Some(size), ProgressDrawTarget::stderr());
    progress.set_style(
        ProgressStyle::with_template("{bar:40} {bytes}/{total_bytes} ({eta})")
            .unwrap_or_else(|_| ProgressStyle::default_bar()),
    );
    let result = write_atomic(&args.output, args.force, size, |f| write(f, &progress));
    progress.finish_and_clear();
    result?;
    println!("Wrote {}", args.output.display());
    Ok(())
}

fn part_path(output: &Path) -> PathBuf {
    let mut p: OsString = output.as_os_str().to_owned();
    p.push(".part");
    PathBuf::from(p)
}

fn output_folder(output: &Path) -> &Path {
    match output.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    }
}

/// Checks that need no scanning: the output folder exists and nothing is overwritten
/// without `--force`.
fn check_output(output: &Path, force: bool) -> Result<()> {
    let folder = output_folder(output);
    if !folder.is_dir() {
        bail!("output folder does not exist: {}", folder.display());
    }
    if output.exists() && !force {
        bail!(
            "{} already exists; use --force to overwrite it",
            output.display()
        );
    }
    Ok(())
}

/// Write `size` bytes through `f` into `<output>.part`, then rename over `output`.
/// The `.part` file is removed on any error; a stale one is overwritten.
pub fn write_atomic(
    output: &Path,
    force: bool,
    size: u64,
    f: impl FnOnce(&mut File) -> Result<()>,
) -> Result<()> {
    check_output(output, force)?;
    let folder = output_folder(output);
    let free = fs2::available_space(folder)
        .with_context(|| format!("cannot check free space in {}", folder.display()))?;
    if free < size {
        bail!(
            "not enough free space in {}: need {size} bytes, have {free}",
            folder.display()
        );
    }
    let part = part_path(output);
    let mut file =
        File::create(&part).with_context(|| format!("cannot create {}", part.display()))?;
    let result = f(&mut file)
        .with_context(|| format!("cannot write {}", part.display()))
        .and_then(|()| {
            file.sync_all()
                .with_context(|| format!("cannot write {}", part.display()))
        })
        .and_then(|()| {
            drop(file);
            std::fs::rename(&part, output)
                .with_context(|| format!("cannot move {} to {}", part.display(), output.display()))
        });
    if result.is_err() {
        let _ = std::fs::remove_file(&part);
    }
    result
}
