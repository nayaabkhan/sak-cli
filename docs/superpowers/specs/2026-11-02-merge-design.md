# sak: Switch merge CLI design

Date: 2026-11-02
Upstream reference: NSC_BUILDER (MIT), commit e9083e8, `--direct_multi` path in
`py/ztools/squirrel.py`, `Fs/Nsp.py`, `Fs/Xci.py`, `lib/sq_tools.py`.

## Intent

NSC_BUILDER is Windows-only and does far more than most people need. `sak` is a
small macOS and Linux CLI that does one job first: combine a Switch game with
its update and DLC into a single file.

Decided by the user:

- Switch files only.
- Merging base game + update + DLC is the only feature for now.
- Options stay simple.
- All input files sit in the folder the CLI is run from.
- The output goes wherever `-o` says.
- Accepted from the proposal: one game per folder, `.nsp` and `.xci` input first,
  newest update only, user-supplied `prod.keys`, single Rust binary, macOS and
  Linux builds for Intel and ARM.

## What "merge" means

Same as upstream: this is bundling, not patching. The update stays a separate
title inside the output file, and the console or emulator applies it as usual.
Upstream calls this a "multi" file.

## Command

```
sak merge -o <output.nsp|output.xci> [--keys <path>] [--force]
```

| Option | Meaning |
| --- | --- |
| `-o`, `--output` | Required. The extension picks the format. Anything else is an error. |
| `--keys` | Path to the keys file. Default: `~/.switch/prod.keys`. |
| `--force` | Overwrite an existing output file. Without it, stop with an error. |

Prints what was found, a progress bar, and the final path. Exit 0 on success,
non-zero with a one-line reason on failure.

## Behaviour

1. **Scan** the current folder, not subfolders, for `.nsp` and `.xci`, ignoring
   case. The output file is excluded if it lands in the same folder. `.nsz` and
   `.xcz` files cause a clear "not supported yet" error, not a silent skip.
2. **Identify** each content meta NCA (`*.cnmt.nca`): decrypt it, read the cnmt,
   and get title ID, version, type (Application, Patch, AddOnContent), the base
   title ID, and its content list. One file may hold several titles.
3. **Validate**
   - Exactly one base game is required. No base, or more than one, is an error.
   - Every update and DLC must belong to that base. Otherwise, stop and list the
     files that don't belong.
   - Every content listed in a cnmt must exist in the file. Otherwise, name what
     is missing.
4. **Select** the highest version per title ID, as upstream does. Older versions
   are reported as skipped. Delta fragments (cnmt content type 6) are dropped,
   because they only matter when upgrading an installed older version.
5. **Check free space** on the destination, using the computed output size.
6. **Write** to `<output>.part` next to the output, then rename, so a failed run
   never leaves something that looks finished.

## Output formats

### NSP (build first)

A PFS0 archive containing every selected NCA byte-for-byte, plus each title's
`.tik` and `.cert`. Tickets and certs are matched by rights ID, as upstream does
in `get_content`. `.cnmt.xml` files are not included; they aren't needed to
install. No game content is re-encrypted, so this is fast and low risk. Keys are
only used to read the cnmt.

### XCI (build second)

An XCI can't carry tickets, so this is much more than a different container.

- Titlekey-encrypted NCAs must be converted to standard crypto: decrypt the
  titlekey from the ticket, write it into the NCA key area, clear the rights ID,
  and re-encrypt the header (`append_clean_content`). The gamecard flag keeps its
  source value, which matches upstream for eShop and cartridge inputs and leaves
  NCAs without a rights ID byte-identical.
- As upstream does, NCA file names and cnmt content records stay as they are,
  even though the whole-file hash of a rewritten NCA no longer matches them.
  Upstream's rename code is commented out and it only patches a cnmt for keygen
  or RSV changes, neither of which is in scope. The real-game test must confirm
  this still boots.
- Layout: 0x200 header, game info, padding, 0x8000 of `0xFF` as a fake cert, then
  a root HFS0 at 0xF000 with `update`, `normal` and `secure` partitions. All
  content goes in `secure`, as upstream does.
- Card size byte and `valid_data` come from total size (`getGCsize`,
  `get_xciheader`).
- The header signature can't be genuine, so upstream uses random bytes. The XCI
  will only run where the loader or emulator ignores that signature. `sak` must
  print this once, on every XCI run.
- The game info block is encrypted with `xci_header_key` if it's in the keys
  file. Otherwise, upstream falls back to fixed encrypted blobs by size; port
  those from `get_enc_gameinfo`.
- Reuses the same scan, validate and select steps as NSP.
- If XCI proves unreliable, `sak` still ships with NSP alone and `.xci` output
  gives a "not supported yet" error.

## Keys

Parse the standard `prod.keys` text format (`name = hex`). Needed: `header_key`,
`key_area_key_application_XX`, and `titlekek_XX` for XCI, or the values to derive
them if absent. If a key for a file's generation is missing, name that key in
the error. `sak` ships no keys and never prints key values.

## Goals

- One static binary, no runtime to install.
- Streams data, so a 30 GB output doesn't need 30 GB of memory or an extra copy.
- Errors say what to do next.

## Non-goals

- Compressed input or output (`.nsz`, `.xcz`).
- FAT32 file splitting, title databases, renaming, firmware or keygen patching,
  network features, Windows builds.
- Picking older update versions or a subset of DLC.
- Processing several games in one run, or scanning subfolders.

## Anti-goals

- A file that looks finished but won't install or boot, without warning.
- Shipping keys or game data, including in the repo's test fixtures.
- Growing NSC_BUILDER's wall of options.

## Testing

- Unit tests per format: PFS0, HFS0, cnmt, NCA header, keys parsing.
- End-to-end tests against synthetic files built by the test suite with made-up
  test keys. These cover selection, validation and output structure.
- Upstream as a cross-check: parse `sak` output with its layout rules.
- **Limit:** synthetic tests can't prove a real game boots. Sign-off needs a real
  game, update and DLC, plus `prod.keys`, tested on the user's own setup.

## Left to the builder

Crate choices, module layout, progress bar style, exact wording of messages,
release packaging (static musl for Linux, universal or per-arch for macOS).

## Builder's calls, for the user to check

- Binary name `sak`, command `sak merge`.
- `--force` and `.part` behaviour.
- A missing base game is an error, although upstream allows it.
- Delta fragments are dropped.
- NSP is built before XCI, and XCI can be cut if unreliable.
- Output format comes only from the `-o` extension; no `--type` flag.
