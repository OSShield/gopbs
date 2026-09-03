# The integration harness (tests/)

The `tests/` directory validates gopbs against the official Proxmox tooling, proxmoxbackupclient_go, pmoxs3proxy and a real PBS-protocol server.

```bash
cd tests
go test -tags integration .            # full run (needs docker + compose plugin)
go test -tags integration -v -run TestBackupOrchestrator .
```

Everything here behind the `integration` build tag. 
CI compile-checks the module with `go vet -tags integration` and runs the test suite.

## What a run does

`TestMain` (main_test.go):

1. Wipes and regenerates the work directories `.test-source` (a randomized
   tree: nested dirs, mixed-size files), `.test-pxar`, `.test-restore`.
2. `docker compose build`, then creates archives of the source tree with
   three implementations, one one-off container each:
   - `pbs` — the official `pxar` CLI (v1),
   - `tizbac` — tizbac's Go client,
   - `gopbs` — `cmd/gopbs-pxar` (v1 + catalog),
   - `pbssplit` / `gopbssplit` — the same pair again for v2 split archives.

Then the tests:

| Test | What it proves |
|---|---|
| `TestComparison` | All archives extract (official `pxar` CLI, incl. split via `--payload-input`) to trees identical to each other and to the source. |
| `TestSplitComparison` | gopbs's `.mpxar`/`.ppxar` are **byte-identical** to the official CLI's. |
| `TestCatalogComparison` | The gopbs catalog describes the source tree exactly and is semantically identical to tizbac's reference catalog. |
| `TestPBSBackupSession` | The raw `pbs` protocol client against pmoxs3: manual chunked backup, then a second snapshot deduplicating everything via `/previous`. |
| `TestBackupOrchestrator` | End-to-end `gopbs.Backup` (v1): upload to pmoxs3, restore with the official `proxmox-backup-client`, tree comparison, full second-run dedup. |
| `TestBackupOrchestratorEncrypted` | Client-side encrypted `gopbs.Backup`, restored and decrypted by the official client using a key file gopbs created (written to `.test-keys/`, passed via `KEYFILE`) — key-file, chunk-format and manifest interop in one round trip; second run deduplicates fully against the previous snapshot's keyed digests. |
| `TestBackupOrchestratorV2` | The same in `FormatV2`, restored as `root.pxar` to exercise the official client's split-name fallback; full dedup on both indexes. |
| `TestPerformance` | Opt-in throughput comparison (below). |

## The compose stack

| Service | Role |
|---|---|
| `garage` | S3 store backing the PBS-protocol proxy. |
| `pmoxs3` | [pmoxs3backuproxy](https://github.com/tizbac/pmoxs3backuproxy) — speaks the PBS backup protocol on `localhost:8007`, stores to garage. Credentials: user `garagegarage@pbs`, password `garagegaragegarage`, datastore `pbs` (fingerprint pinned in the tests). |
| `pbs` / `pbssplit` | Official `pxar` CLI (from the `pbs-client` Debian repo) creating reference archives. |
| `tizbac` | Reference Go implementation creating `tizbac.pxar`. |
| `gopbs` / `gopbssplit` | `cmd/gopbs-pxar` built from the working tree. |
| `restore` | Extracts all archives with the official `pxar` CLI. |
| `pbsrestore` | One-off `proxmox-backup-client restore` from the pmoxs3 stack (`SNAPSHOT`/`ARCHIVE`/`TARGET` via env; optional `KEYFILE` decrypts with a key file from the read-only `.test-keys/` mount). Runs as root — restoring ownership needs it — and chmods the result so the host user can clean up. |
| `pbsbackup` | One-off `proxmox-backup-client backup` to the pmoxs3 stack (`SUBDIR`/`BACKUPID`/`MODE` via env; `MODE` is the change-detection mode: `legacy` = v1, `metadata` = v2 split). Used by the performance test. |

The pmoxs3 stack is started on demand by the tests that need it and torn
down afterwards; set `GOPBS_KEEP_PBS=1` to keep it running for debugging.
Note pmoxs3 resolves "previous snapshot" at whole-second granularity, so
consecutive snapshots in tests are spaced ≥1 s apart.

## Performance comparison

```bash
GOPBS_PERF=1 GOPBS_PERF_MB=512 go test -tags integration -run TestPerformance -v .
```

Builds a deterministic mixed tree (default 512 MiB: half large random blobs,
a quarter 1 MiB text files, a quarter 16 KiB small files), then times:

- **generation to file**: gopbs v1 sync / v1 async / v2 async vs the
  official `pxar` CLI (v1 and split) — with byte-equality sanity checks;
- **upload to pmoxs3**: `gopbs.Backup` (v1, v2) vs `proxmox-backup-client`
  (`legacy`, `metadata`), each as a fresh backup and as a fully-deduplicated
  rerun.

Container-based runs include ~1 s of docker startup; use larger trees for
meaningful throughput numbers.

## Conventions

- Compose one-off containers run with the host UID/GID (forwarded by the
  `compose()` helper) so work-directory files stay host-owned.
- Test work dirs (`.test-*`) are gitignored except their `.gitkeep`s and are
  reset at the start of every run.
- Snapshots use unique backup ids (`gopbs-e2e-<nanotime>`) so runs never
  inherit stale server state.
