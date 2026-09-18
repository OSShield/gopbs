# The PXAR archive format (v1 and v2)

Reference for the on-disk format gopbs emits, as implemented by the `pxar`,
`archive` and `catalog` packages. The authority is the Rust `proxmox/pxar`
crate (`src/format/mod.rs`, `src/encoder/mod.rs`); gopbs output is verified
byte-identical to `pxar create` in the integration harness. All integers are
**little-endian**.

## 1. Record framing

Every item in a pxar stream is a 16-byte header followed by a body:

```
u64  type       (constant identifying the record)
u64  length     (total record length, INCLUDING the 16-byte header)
[length-16]     body
```

Record type constants:

| Record | Value | Body |
|---|---|---|
| `ENTRY` | `0xd5956474e588acef` | stat data, 40 bytes (§2) |
| `ENTRY_V1` | `0x11da850a1c1cceff` | obsolete stat layout; decode-only, never emitted |
| `FILENAME` | `0x16701121063917b3` | name bytes + NUL |
| `SYMLINK` | `0x27f971e7dbf5dc5f` | target bytes + NUL |
| `DEVICE` | `0x9fc9e906586d5ce9` | `major u64, minor u64` |
| `XATTR` | `0x0dab0229b57dcd03` | name + NUL + value |
| `ACL_USER` | `0x2ce8540a457d55b8` | `uid u64, permissions u64` |
| `ACL_GROUP` | `0x136e3eceb04c03ab` | `gid u64, permissions u64` |
| `ACL_GROUP_OBJ` | `0x10868031e9582876` | `permissions u64` |
| `ACL_DEFAULT` | `0xbbbb13415a6896f5` | `user_obj, group_obj, other, mask` (4 × u64) |
| `ACL_DEFAULT_USER` | `0xc89357b40532cd1f` | `uid u64, permissions u64` |
| `ACL_DEFAULT_GROUP` | `0xf90a8a5816038ffe` | `gid u64, permissions u64` |
| `FCAPS` | `0x2da9dd9db5f7fb67` | raw `security.capability` xattr value |
| `QUOTA_PROJID` | `0xe07540e82f7d1cbb` | `projid u64` |
| `HARDLINK` | `0x51269c8422bd7275` | `offset u64` + target path + NUL |
| `PAYLOAD` | `0x28147a1b0b7c1a25` | raw file content |
| `GOODBYE` | `0x2fec4fa642d5731d` | BST of 24-byte items (§4) |
| goodbye tail marker | `0xef5eed5b753e1555` | hash value of the final goodbye item |

v2 additions:

| Record | Value | Body |
|---|---|---|
| `FORMAT_VERSION` | `0x730f6c75df16a40d` | version as u64 (`2`) |
| `PRELUDE` | `0xe309d79d9f7b771b` | opaque bytes (client exclude patterns) |
| `PAYLOAD_REF` | `0x419d3d6bc4ba977e` | `offset u64, size u64` (§5) |
| `PAYLOAD_START_MARKER` | `0x834c68c2194a4ed2` | none (length = 16) |
| `PAYLOAD_TAIL_MARKER` | `0x6c72b78b984c81b5` | none (length = 16) |

ACL permission bits: read = 4, write = 2, execute = 1. `NO_MASK`
(`0xffff_ffff_ffff_ffff`) marks an absent mask in `ACL_DEFAULT`.

## 2. Per-entry encoding (v1)

Each node is encoded as:

```
FILENAME            (omitted for the archive root)
ENTRY
[metadata records]  (fixed order, §3)
[type-specific]     PAYLOAD | SYMLINK | DEVICE | children+GOODBYE | nothing
```

The `ENTRY` body (40 bytes):

```
u64  mode     full st_mode: type bits (S_IFMT) + permission bits
u64  flags    feature flags of the metadata that follows
u32  uid
u32  gid
u64  mtime seconds   (two's complement; may be negative)
u32  mtime nanoseconds
u32  padding (zero)
```

Type-specific bodies:

- **Regular file**: one `PAYLOAD` record; `length = 16 + content size`.
- **Symlink**: `SYMLINK` with the NUL-terminated target.
- **Block/char device**: `DEVICE` with major/minor.
- **FIFO / socket**: nothing — the mode's type bits say it all.
- **Hardlink**: `HARDLINK` *instead of* an `ENTRY`: `offset` is the distance
  **backwards** from the start of this hardlink's `FILENAME` record to the
  start of the link target's `FILENAME` record, plus the target's
  archive-relative path, NUL-terminated. Only regular files with `nlink > 1`
  are candidates; the first occurrence is encoded in full, later ones as
  hardlinks pointing back at it.
- **Directory**: each child in **byte-order of name** (`FILENAME` first),
  then the directory's `GOODBYE` table (§4).

## 3. Metadata record order

After `ENTRY`, optional metadata records appear in exactly this order:

1. `XATTR` — one record per attribute, sorted by name. Excludes attributes
   with dedicated records (`system.posix_acl_*`, `security.capability`).
2. `ACL_USER` — named users of the access ACL.
3. `ACL_GROUP` — named groups of the access ACL.
4. `ACL_GROUP_OBJ` — owning-group permissions, present only when the ACL has
   a mask entry (the mode's group bits then carry the mask instead).
5. `ACL_DEFAULT` — default-ACL object permissions (directories).
6. `ACL_DEFAULT_USER`, then `ACL_DEFAULT_GROUP`.
7. `FCAPS` — raw file capabilities.
8. `QUOTA_PROJID` — only when a nonzero project id is set.

A trivial ACL that only mirrors the mode bits is not encoded at all.

## 4. Goodbye tables

A directory ends with a `GOODBYE` record enabling random access: one 24-byte
item per child plus a tail marker.

```
u64  hash     SipHash-2-4 of the child's basename
u64  offset   distance backwards from the START of the GOODBYE record
              to the child's FILENAME record
u64  size     total encoded length of the child
```

- The hash keys are `k1 = 0x83ac3f1cfbb450db`, `k2 = 0xaa4f1b6879369fbd`
  (derived from `sha1("PROXMOX ARCHIVE FORMAT")`).
- Items are sorted by hash, then permuted into the **casync implicit binary
  search tree**: the array encodes a balanced BST in breadth-first layout
  (children of slot `i` at `2i+1`, `2i+2`) whose in-order traversal yields
  the hash-sorted sequence.
- The **final item** is the tail marker: `hash` = the tail marker constant,
  `offset` = distance backwards to the directory's own `ENTRY` record,
  `size` = the length of the GOODBYE record itself.
- For the **archive root**, v1 and v2 differ — see §5.

`goodbye_start - item.offset` gives the child's start; adding `item.size`
gives its end (see the v2 exception below).

## 5. v2 split archives

Format version 2 splits an archive into a **metadata stream** (`.mpxar`) and
a **payload stream** (`.ppxar`). Metadata-only changes then leave the payload
stream's chunks untouched, so re-uploads deduplicate almost entirely.

**Metadata stream** (`.mpxar`):

1. A `FORMAT_VERSION` record, body `2` as u64 (version 1 is expressed by the
   record's absence).
2. Optionally a `PRELUDE` record, present only when exclude patterns were
   given (`scan.Options.Exclude`). Its body is the JSON object
   `{"exclude-patterns":"<lines>"}` where `<lines>` is the `.pxarexclude-cli`
   content described in §7, escaped the way serde_json does (`"`, `\` and
   control characters only). Identical to what `pxar create --exclude` writes.
3. The v1 structure (§2–4), except each regular file's `PAYLOAD` record is
   replaced by a fixed 32-byte `PAYLOAD_REF`:
   - `offset` — absolute position of the payload record's **header** in the
     payload stream (not its body);
   - `size` — the content byte count (the referenced record's length − 16).
   Refs are strictly increasing and contiguous: each ref's offset equals the
   previous ref's `offset + 16 + size` (the first is 16, right after the
   start marker).

**Payload stream** (`.ppxar`):

```
PAYLOAD_START_MARKER              (bare header, length 16)
PAYLOAD record for file 1         (16 + size bytes)
PAYLOAD record for file 2
...
PAYLOAD_TAIL_MARKER               (bare header, length 16)
```

Three deliberate quirks, matching the upstream encoder exactly:

- **Goodbye size inflation**: a regular file's goodbye item records its
  metadata-stream span **plus** its content size — as if the payload were
  inline — even though the mpxar only holds the 32-byte ref. Directory,
  symlink, device and hardlink items record real metadata-stream spans.
- **Root tail marker**: the root goodbye's tail `offset` points back to the
  very **start of the stream** (position 0, the `FORMAT_VERSION` record),
  not to the root's `ENTRY`. In v1 the two coincide (the root `ENTRY` is at
  position 0); non-root directories point at their `ENTRY` in both versions.
- **Hardlink offsets** use real (uninflated) metadata-stream positions.

## 6. The .pcat1 catalog (v1 only)

v1 snapshots carry a `catalog.pcat1.didx` that makes them browsable without
reading the archive; v2 needs none — the metadata stream serves that role.

```
8-byte magic: 91 fd 60 f9 c4 67 58 d5
[directory tables, written bottom-up]
u64  absolute position of the root table (fixed-size little-endian trailer)
```

Each table:

```
uvarint  table length (bytes that follow, up to the end of the entries)
uvarint  entry count
entries...
```

Each entry starts with a type byte (`d`, `f`, `l`, `h`, `b`, `c`, `p`, `s`)
followed by `uvarint name-length + name`, then per type:

- `d` (directory): `uvarint delta` — the child's table starts `delta` bytes
  **before** this table's start (tables are bottom-up, so children always
  precede parents; a delta of 0 is invalid).
- `f` (file): `uvarint size`, then the mtime as a **special i64 varint**:
  non-negative values use plain uvarint; negative values encode the
  magnitude with a forced continuation bit on every byte, terminated by an
  explicit `0x00` byte.
- All others: name only.

The top-level "directory" conventionally carries the archive's index name
(e.g. `root.pxar.didx`); one catalog may hold several archives.

## 7. Size arithmetic

Every encoder in the `pxar` package has a matching `Size*` function, and the
planner uses those — plan and emission share one source of truth, and the
tests enforce that `EstimatedSizeV1`/`V2` equal the emitted byte counts
exactly for unchanged trees.

Payload sizes are **bound late**: the size written into a payload header (or
ref) comes from `fstat` on the already-opened file at dispatch time, not from
the scan. Content that still changes between open and read is padded or
truncated to the bound size (and reported as a warning), so structural
offsets never break.

## 7. Recorded exclude patterns

Patterns supplied on the command line (`scan.Options.Exclude` in gopbs) are
recorded in the archive exactly as the official client records `--exclude`:

- **v1**: a synthetic regular file `.pxarexclude-cli` in the archive root —
  mode `S_IFREG|0600`, uid/gid of the archiving process, mtime 0 — whose
  content is one pattern per line in source form (`!` prefix for
  re-includes, `/` prefix for anchored patterns, `/` suffix for
  directory-only patterns), newline-terminated. It is appended to the root's
  child list *after* sorting, so it is the last entry emitted (the goodbye
  table is hash-ordered, so the position is a pure encoder quirk). The
  catalog lists it with mtime 0. A real root entry of that name is dropped
  by both encoders, patterns or not.
- **v2**: the same lines wrapped in the `PRELUDE` record (§5); no synthetic
  file.

`.pxarexclude` files found in the tree are archived as ordinary files; their
patterns and the `Filter` callback leave no trace.
