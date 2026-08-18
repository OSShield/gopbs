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
