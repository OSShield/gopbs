# Integration tests

This harness generates a random file tree in `.test-source`, archives it with
three implementations — the official `pxar` CLI, tizbac's
proxmoxbackupclient_go, and gopbs (`cmd/gopbs-pxar`) — extracts all three
archives with the official `pxar` CLI, and requires the restored trees to be
identical to each other and to the source.

## Requirements

Docker with the compose plugin. Everything else runs in containers.

## Running

```sh
go test -tags integration .
```

The `integration` build tag keeps these tests out of plain `go test ./...`
runs. Add `-v` to see the docker compose output of successful steps.

The work directories (`.test-source`, `.test-pxar`, `.test-restore`) are
cleaned at the start of each run.

## Server backends

Two PBS-protocol servers run in containers: `pmoxs3` + `garage` (a protocol
emulator over S3, used by the `TestPBS*`/`TestBackupOrchestrator*` tests) and
`epbs`, a real Proxmox Backup Server from
[ephemeral-pbs](https://github.com/osshield/ephemeral-pbs), used by
`TestEphemeralPBS`. The latter checks every gopbs snapshot through the REST
API (listing, notes, owner, server-side verify, single-file download), the
official `proxmox-backup-client` (restore, catalog dump, notes, protection)
and gopbs's own reader.

`GOPBS_KEEP_PBS=1` leaves the servers running after the tests; the real PBS
web UI is then at https://localhost:8017 (`root@pam` / `demo`).
