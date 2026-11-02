pub mod crypto;
pub mod keys;

use anyhow::{Result, bail};
use clap::Args;
use std::path::PathBuf;

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
    let _keys = keys::Keys::load(&keys_path)?;
    bail!("not implemented")
}
