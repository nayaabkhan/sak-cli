use clap::{Parser, Subcommand};
use sak::MergeArgs;
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    name = "sak",
    version,
    about = "Merge Nintendo Switch game, update and DLC files"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Merge the .nsp/.xci files in the current folder into one file
    Merge(MergeArgs),
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Merge(args) => sak::run_merge(&args),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}
