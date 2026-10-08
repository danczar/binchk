# TODO: archive support (.zip, .tar.gz, …)

Status: **proposed, not started**

## Problem

Much software, and much malware, arrives as an archive. Today binchk only acts
when the executable itself lands in a watched folder:

- If the user extracts the archive into a watched folder, the binaries or
  `.app` are caught at that point. That's too late for the archive itself, and
  it misses extraction into unwatched folders.
- A malicious archive sitting in Downloads isn't flagged at all.
- Archives are a favourite way to get past scanners: password-protected zips
  ("password: infected"), nested archives, and double extensions inside
  (`invoice.pdf.exe` in `invoice.zip`).

Goal: treat archives like `.dmg` / `.pkg`. Analyse the archive where it is,
look inside without extracting it to the user's disk and without running
anything, and report on the contents within the same < 15 s budget.

## Formats

| Format | Detection (magic) | Reader | Priority |
|---|---|---|---|
| zip (+ `.jar`, `.apk`, `.ipa`, `.xpi`, `.crx` payload) | `PK\x03\x04` at 0, or end-of-central-directory near EOF (self-extracting / appended) | stdlib `archive/zip` | P0 |
| tar, tar.gz / tgz, tar.bz2, tar.xz, tar.zst | `ustar` at offset 257; gzip `1f 8b`, bzip2 `BZh`, xz `fd 37 7a 58 5a 00`, zstd `28 b5 2f fd` | stdlib `archive/tar` + `compress/*`; xz via `ulikunitz/xz` (already a dependency); zstd needs `klauspost/compress` | P0 (zip, tgz), P1 (rest) |
| bare .gz / .bz2 / .xz of a single file | as above, no tar header after decompression | same | P1 |
| 7z | `37 7a bc af 27 1c` | `bodgit/sevenzip` (pure Go) | P2 |
| rar (v4/v5) | `Rar!\x1a\x07` | `nwaples/rardecode` (pure Go) | P2 |
| cab, iso, msi | various | none yet; maybe via a pure-Go reader later | out of scope |

Keep to **pure Go**, following the choice made for `.pkg`. Archives must work
on every OS (they're cross-platform threats) and must never be handed to OS
extraction tools.

## Design

### Detection & watcher

- Add `detect.Archive` formats to `Sniff`. Magic comes first; the extension is only a hint (`.docx`, `.xlsx`, `.jar`, `.apk` are zips too, so see open questions).
- Browser partial files (`.crdownload`, `.part`, …) are already ignored, and the existing settle logic covers archives being written.
- **Interaction with bundle detection:** when Archive Utility extracts `Foo.zip` → `Foo.app`, binchk will now see the zip first and then the app. A flagged zip carries its Finder tag and notification before the user extracts it; the extracted `.app` is then analysed as it is today. Consider linking the two reports by provenance.

### Inspection (new `internal/archive`, reusing `container.inspector`)

1. **Enumerate entries from the index first; don't extract anything yet.** Zip's central directory, 7z and rar headers give names, sizes and modes cheaply. Tar has no index, so it has to be streamed.
2. **Pick candidates** the way `bundleCode` does: executables by magic (read only the first 64 bytes of each entry), scripts (shebang, `.command`, `.sh`, `.ps1`, `.bat`, `.vbs`, `.js`, `.lnk`, `.hta`), `.app` directory trees, nested archives, `.dmg` / `.pkg`.
3. **Extract only candidates** into a private temp directory, using the hardened extraction in `internal/xar` (`safeJoin`, confined symlinks, no setuid, byte and entry caps). Generalise it into a shared `internal/safeextract`.
4. **Analyse with the existing engine and container code.** Executables and scripts go through `analyzeFile`. An `.app` found inside goes through `inspectApp` (so Gatekeeper and deep verify run on the extracted bundle), a `.pkg` through `inspectPkg`, and a `.dmg` through `inspectDMG` (macOS).
5. **Nested archives:** recurse to depth 2, sharing one byte, entry and time budget. Report any deeper nesting as a finding instead of opening it.
6. **Streaming formats (tar.*)** only reach an entry by reading everything before it. Use a stricter byte budget, and stop once the file cap is reached.

### Archive-level findings

| ID | Severity | Trigger |
|---|---|---|
| `archive-encrypted` | Medium | Password-protected entries (zip encryption flag, 7z/rar headers). Contents can't be inspected. This is the classic "password: infected" delivery. |
| `archive-bomb` | Medium | Compression ratio > 100:1 or declared size > cap; stop without extracting |
| `archive-traversal` | High | Entry names with `..`, absolute paths, or symlinks pointing outside (Zip Slip) |
| `archive-single-exec` | Low | The archive holds a single executable and nothing else (a common dropper wrapper) |
| `archive-double-ext` | High | Reuse `filenameFindings` on every entry name (`invoice.pdf.exe`, RTLO characters) |
| `archive-lnk` / `archive-script` | Medium | Windows shortcuts / script files at the archive root |
| `archive-nested-deep` | Low | Nesting deeper than the recursion limit |
| `archive-sfx` | Info | Self-extracting archive: an executable with an appended zip. Analyse both halves |

Scoring follows `FinalizeContainer`: archive findings plus the worst contained file.

### Budget & safety

- The deadline is shared with the rest of the container code (context-aware readers; stop between entries).
- Default caps: 64 analysed files, 1 GiB total extracted, 200k entries enumerated, nesting depth 2.
- Decompression happens inside binchk. Readers must be context-aware and memory-bounded: never read a whole entry into memory, and use `io.LimitReader` everywhere.
- Fuzz the new readers (`go test -fuzz`) on malformed archives. Parser panics are already recovered and turned into findings by the engine, and the archive layer needs the same.

### Reporting & UX

- The archive file is indexed and tagged like any other file; the Quick Look card shows the archive's verdict and its top findings.
- The report gets an "Archive contents" section: an entry table (name, size, compressed size, type, and verdict for analysed entries) plus notes on anything skipped.
- Mark as safe behaves as it does for any file.

### Config

- `inspect_archives` (default true), plus `archive_formats` to limit which formats are intercepted.
- Probably exclude Office documents (`.docx`, `.xlsx`, `.pptx`) by default. They're zips, but macro and malicious-document analysis is a different feature.

## Open questions

- **Office documents & other zip-based formats:** skip entirely, or at least look for embedded executables and OLE objects? (Leaning towards skipping for v1.)
- **Archives without executable content** are extremely common in Downloads. Analysing them is cheap, but should they be indexed at all, or skipped once enumeration finds nothing executable?
- **Tar streaming cost** for large `.tar.xz` source tarballs (single-threaded xz). Cap them, or only enumerate?
- **Encrypted zips with a password in the filename or next to them.** Try "infected" / "malware" / a password taken from the filename? That's useful for analysts but surprising for end users; maybe behind a flag.
- **Windows** has no Gatekeeper analogue for extracted content. We could add Mark-of-the-Web propagation checks (does the archive carry `Zone.Identifier`, and did the extractor propagate it?).

## Work breakdown

1. `internal/safeextract`: move the hardened extraction out of `internal/xar` and add tests for Zip Slip and bombs.
2. zip + tar/gzip readers, detection, `container.Analyze` dispatch, findings, report section.
3. Watcher / config / tray wiring, `scan` CLI support, tests with crafted malicious archives.
4. P1 formats (bz2, xz, zstd, bare compressed files), then P2 (7z, rar).
5. Fuzzing, and benchmarks against real archives in a Downloads folder (target: typical zip < 1 s).
