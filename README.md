# sak

A small command line tool for macOS and Linux that merges a Nintendo Switch
game, its update and its DLC into one file.

Status: early. It has not yet been tested against a real game, update and DLC.
Treat the output as unproven until you have tried it on your own setup.

## Install

There is no published release yet. From a checkout:

    cargo install --path .

## Use

Put the game, update and DLC files in one folder, then run from that folder:

    sak merge -o game.nsp

| Option | Meaning |
| --- | --- |
| `-o`, `--output` | Required. Output file; the extension (`.nsp` or `.xci`) picks the format. |
| `--keys <path>` | Keys file. Default: `~/.switch/prod.keys`. |
| `--force` | Overwrite the output file if it exists. |

Only `.nsp` and `.xci` files in the current folder are read, not subfolders.
Exactly one base game is required; every update and DLC must belong to it. The
highest version of each title is used.

## Keys

You supply your own `prod.keys`. sak ships no keys and never prints key values.
If a key is missing, the error names it.

## What merging means

Files are bundled, not patched. The update stays a separate title inside the
output, and the console or emulator applies it as usual.

### `.nsp` output

Every selected NCA is copied byte for byte, with each title's tickets and
certs. Keys are only used to read the content metadata.

### `.xci` output

An XCI cannot carry tickets, so titlekey-encrypted NCAs are converted to
standard crypto. The XCI header signature cannot be genuine, so it is random
bytes. The file runs only where the loader or emulator ignores that signature.
sak prints this warning on every `.xci` run.

## Not supported

- `.nsz` and `.xcz` input or output (sak stops with a "not supported yet" error)
- Personalised tickets
- Several games in one run, or subfolders
- FAT32 file splitting, title databases, renaming, firmware or keygen patching
- Windows

## License

MIT. XCI values are ported from NSC_BUILDER; see `LICENSE`.
