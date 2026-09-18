# GoPBS API guide

This document describes the GoPBS librarys public API and how to use it.

We mainly explore the inner workings of the library, the examples are a better starting point for just regular usage of the library.

For more details, you can have a look at the godoc documentation: https://pkg.go.dev/github.com/osshield/gopbs

## Package map

```
gopbs        Backup(): gives a one-call method to backup a directory tree to a PBS server
├── archive  tree walking, planning + generation of pxar streams (v1, v2, catalog)
│   ├── scan     walk the filesystem tree(s) and capture metadata, sizes
│   ├── pxar     Encodes the PXAR archive stream for v1 and v2
│   └── catalog  .pcat1 catalog encoder/decoder
├── pbs      the PBS client: sessions, chunked+deduplicated index uploads
│   └── chunker  buzhash content-defined chunker (as used by PBS)
```

## Backup(): A full backup in one method call

```go
result, err := gopbs.Backup(ctx, gopbs.BackupOptions{
    Client:  pbs.Config{...},          // server, auth, datastore, workers
    Archive: archive.Options{...},     // name, generation workers, scan policy
    Ref:     pbs.SnapshotRef{...},     // type/id/time (defaults: host/hostname/now)
    Format:  gopbs.FormatV1,           // or FormatV2
    Paths:   []string{"/etc"},         // and/or Streams
})
```

Backup() scans, plans, generates, chunks, deduplicates against the previous
snapshot, uploads, writes the catalog (v1 or v2 depending on the settings) 
and commits the manifest. Fully streamed, no temporary files. 
`BackupResult` carries the resolved snapshot ref, per-index
`UploadStats`, and all warnings that happened along the way.

**Roots.** One directory in `Paths` becomes the archive root. Multiple directories, 
bare files, or `Streams` entries are placed under a virtual root directory named 
`Archive.Name` (required in that case).

**Streams** are virtual files backed by an `io.Reader` with a predeclared size,
the archive layout commits to the size up front, and a reader yielding a
different byte count is padded/truncated to it (with a warning). Readers are
consumed during the backup, so a `BackupOptions` with streams is good for one
call. **THIS MEANS THAT IF THE STREAM DATA SIZE INCREASES AFTER THE BACKUP OPTIONS ARE CREATED AND THE BACKUP HAS STARTED, THE BACKUP WILL NOT INCLUDE ALL OF THE DATA**

**Excluding entries.** Exclusions are configured on `Archive.Scan`:

- `Exclude` — patterns in `proxmox-backup-client --exclude` syntax, matched
  against archive-relative paths (under a virtual root, the roots' archive
  names are the first component). A leading `/` anchors the pattern to the
  archive root; otherwise it matches at any depth (`*.tmp` by basename,
  `foo/bar` any `…/foo/bar`). A trailing `/` matches directories only. `!`
  turns a pattern into a re-include. The body is an fnmatch-style glob:
  `*`, `?` and `[…]` never cross `/` (`[^…]` negates a class, `\` escapes),
  and `**` as a whole component matches any number of components (at least
  one at the end: `a/**` matches a's contents, not `a`). The **last**
  matching pattern wins; an excluded directory is not descended. Invalid
  patterns fail `archive.New` / `Backup` before any connection is made.
- `PxarExcludeFiles` — honour `.pxarexclude` files found in the tree, like
  the official client: one pattern per line, `#` comments, patterns scoped
  to that directory's subtree with anchored lines relative to the file's
  directory. Unparsable lines are reported as `WarnBadPattern` and ignored;
  the file itself is archived. Off by default — a library should not
  silently obey control files found inside the data it backs up.
- `Filter func(path, archivePath string, st scan.Stat) bool` — arbitrary
  logic (size, age, device boundaries); `false` omits the entry and its
  subtree. Runs after the patterns, so it can veto a re-include.
- `OnExclude` — audit hook receiving every omitted entry.

`Exclude` patterns are recorded in the archive exactly as the official
client records its `--exclude` options: v1 archives get a `.pxarexclude-cli`
file emitted last in the root (mode 0600, owned by the process uid/gid,
mtime 0, one pattern per line, also listed in the catalog), v2 archives
carry them in the prelude record (`{"exclude-patterns":"…"}`). A real root
entry named `.pxarexclude-cli` is dropped with a warning, as upstream does.
`.pxarexclude` contents and `Filter` decisions are never recorded. The
archive root itself is never excluded. Semantics were verified byte-for-byte
against `pxar create --exclude`; one deliberate divergence: the official
client ignores anchored lines in *subdirectory* `.pxarexclude` files (it
prefixes them with the directory path but then matches without the leading
slash), while gopbs honours them as documented.

**Formats.** `FormatV1` = single `.pxar` index plus a `.pcat1` catalog;
works everywhere. `FormatV2` = split `.mpxar`/`.ppxar` indexes, no catalog;
metadata-only changes leave the payload stream fully deduplicated, but
restoring requires proxmox-backup-client ≥ 3.2.

**Blobs.** `Blobs` uploads named metadata files alongside the archive,
stored in the snapshot and listed in the manifest, but not part of the
archive. Use them for backup metadata PBS has no native place for
(application state, retention hints, tool versions). Names get `.blob`
appended when missing (`index.json` is reserved for the manifest); contents
are zstd-compressed and can be downloaded through the UI or
`proxmox-backup-client restore <snapshot> <name>.blob <target>`. Blobs are
held in memory — bulk data belongs in the archive or a `Stream`.

**Progress.** `OnProgress` receives one call per committed chunk and a final
`Done` call per index, with `Total` filled from the size estimate. V2 uploads
run two indexes concurrently, so calls can arrive from two goroutines.

**Warnings vs errors.** I/O failures, protocol errors and scan failures
(without `SkipOnError`) abort the backup. Non-fatal events are reported as
`archive.Warning` values (collected in the result and via `OnWarn`):

- `WarnSkipped` — an entry could not be scanned and was omitted
  (`scan.Options.SkipOnError`).
- `WarnSizeChanged` — a payload yielded a different byte count than the
  committed size and was padded/truncated.
- `WarnTorn` — a file's size or mtime changed *while* its content was read;
  the archived bytes may interleave old and new content.
- `WarnBadPattern` — a `.pxarexclude` line failed to parse and was ignored
  (`Err` is a `*scan.PatternError`, `Path` the file).

## Archive generation without a server

```go
a, _ := archive.New(archive.Options{Name: "root", Workers: 0})
a.AddDirectory("/etc")               // also: AddDirectoryAs(path, as), AddFile, AddStream, plural forms
stream, _ := a.GenerateV1(ctx)       // io.ReadCloser; Close aborts generation
```

- Scanning happens at generation time, not when the data is added with Add*()
- `Workers: 1` is fully synchronous; any other value reads payloads in
  parallel and reassembles them in the right order. Output is byte-identical
  in both modes, we test for this.
- `GenerateV2` returns two streams that must be consumed **concurrently**
  (metadata emission can await payload dispatch progress) and both closed.
- `GenerateCatalog` produces the matching `.pcat1` for the V1 format;
  `CatalogEntryName` the index name the catalog references.
- `EstimatedSizeV1`/`EstimatedSizeV2` return exact sizes for unchanged trees
  (payload sizes can vary at packing time, so concurrent modification shifts the
  real total).

Late offset binding is what makes generation safe on a live filesystem: the
plan fixes structure and order only; each payload's size is bound by
open+fstat when its read is dispatched, and goodbye-table/hardlink offsets
are computed from actually-emitted positions. This is still not 100%, you 
should always back up a snapshot or VSS shadow copy of a live filesystem.

## The PBS client on its own

```go
client, _ := pbs.NewClient(pbs.Config{...})
sess, _ := client.StartBackup(ctx, pbs.SnapshotRef{Type: "host", ID: "myhost"})
defer sess.Abort()                       // no-op after a successful Finish

stats, _ := sess.UploadPXARv1(ctx, "root.pxar", anyReader)
stats, _ = sess.UploadCatalog(ctx, catalogReader)
// v2: sess.UploadPXARv2(ctx, "root", metaReader, payloadReader)
err := sess.Finish(ctx)
```

- One session = one snapshot = one HTTP/2 connection.
- The `Upload*` helpers chunk, hash, compress and upload with
  `Config.Workers` concurrency, deduplicating against the previous snapshot
  (`/previous` is fetched automatically; its absence is the normal
  first-backup case) and across everything uploaded in the session.
- Index and blob methods are safe for concurrent use; `Finish`/`Abort` are
  not and must come last (preferrably a well-placed `defer`)
- For custom flows the following primitives are exported:
  `CreateDynamicIndex`, `UploadDynamicChunk`, `AppendDynamicIndex`,
  `CloseDynamicIndex`, `UploadBlob`, `DownloadPrevious`,
  `ParseDynamicIndex`, `SplitIndexNames`, `BlobEncoder`, `ChunkDigest`.

### Encryption

```go
info, _ := pbs.LoadKeyFile(keyJSON, []byte("passphrase")) // proxmox key.json
cfg := pbs.Config{
    // ...
    Crypt: info.CryptConfig(pbs.CryptModeEncrypt),
}
```

- `Config.Crypt` enables client-side encryption, fully compatible with
  `proxmox-backup-client`: AES-256-GCM chunks and blobs, keyed chunk digests
  (dedup keeps working per key, including against snapshots the official
  client wrote with the same key), and a signed manifest carrying the key
  fingerprint. `CryptModeSignOnly` uploads plaintext but still signs the
  manifest. A nil `Crypt` is the plaintext "none" mode.
- Key management: `GenerateEncryptionKey` (fresh random key),
  `LoadKeyFile`/`CreateKeyFile` (proxmox `key.json`, scrypt- or
  PBKDF2-protected or plain; created files should be written with mode
  0600), `KeyInfo.CryptConfig` to plug a loaded key in.
- `CryptConfig.MasterPublicKey` (RSA PEM) makes every backup include
  `rsa-encrypted.key.blob` — the encryption key wrapped for the master-key
  holder, so data survives a lost key file. Requires encrypt mode.
- Low-level users: `UploadDynamicChunk`'s digest must be
  `sess.ChunkDigest(plain)`, which applies the mode's digest rule.
- Restore-side decryption is not part of the library (backup-only scope).


### Sessions through a proxy or tunnel

`pbs.Config.DialSession` replaces the client's own TLS dial and HTTP/1.1
`101 Switching Protocols` handshake. `StartBackup` calls it once per session
and uses the returned `net.Conn` directly as the HTTP/2 transport, so the peer
must already have completed the upgrade — typically a proxy that authenticates
the client its own way, adds the PBS API token, opens the session against the
real server and then pipes bytes. `BaseURL`, `Auth` and `Datastore` may be
omitted in that configuration:

```go
client, err := pbs.NewClient(pbs.Config{
    DialSession: func(ctx context.Context, ref pbs.SnapshotRef) (net.Conn, error) {
        return tunnel.Open(ctx, ref) // returns the upgraded connection
    },
})
```

`gopbs.Backup` honours the setting through `BackupOptions.Client`.

## Lower layers

- **`chunker`**: `Split(r, avg)` iterates content-defined chunks;
  `Chunker.Scan` is the incremental form. Boundaries match what PBS-Client produces bit for bit.
- **`pxar`**: append-style record encoders (`AppendEntry`, `AppendGoodbye`,
  …) with matching `Size*` functions, `Hash` (goodbye-table SipHash) and
  `ValidateFilename`. No I/O.
- **`catalog`**: `Writer` (streaming, bottom-up) and `Decode`.
- **`scan`**: `Scanner` walks trees into `Node`s; the `MetadataReader`
  interface is the platform seam (full implementation: Linux). `StreamNode`
  and `VirtualRoot` build virtual entries. `ParsePattern`/`PatternList`
  implement the exclude-pattern syntax (usable standalone, e.g. to validate
  user input or dry-run a pattern set with `PatternList.Match`).

## Concurrency and resource notes

- `Archive` is not safe for concurrent use; `pbs.Client` is.
- Async generation memory is bounded by `Archive.Options.Buffer`
  (reorder-buffer budget, default 64 MiB) plus the dispatch window of open
  file descriptors (`max(8, 2×workers)`).
- Upload memory is roughly `Workers × ChunkSizeAvg` of in-flight chunks.
- Everything takes a `context.Context`; cancellation aborts generation and
  uploads promptly, and abandoned generator streams must still be `Close`d
  to release their goroutines.
