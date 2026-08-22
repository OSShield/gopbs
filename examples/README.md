# Examples

Two examples of implementations for backing up two directories to a PBS instance: 

  1. Generate Archive
  2. Chunk the data
  

Runnable backups wiring the gopbs building blocks together: archive
generation -> content-defined chunking -> PBS backup session. 
TODO: Once we have the full backup method in place, we can adjust these

| Example | What it shows |
|---|---|
| [backup-sync](backup-sync/) | Fully synchronous generation (`Workers: 1`); the minimal end-to-end flow. |
| [backup-async](backup-async/) | Asynchronous generation (the default): parallel payload reads reassembled in order, plus deduplication against the previous snapshot. |

Both default to backing up `/tmp` against the docker test stack from
[tests/compose.yml](../tests/compose.yml):

```sh
cd tests && docker compose up -d garage pmoxs3 && cd ..
go run ./examples/backup-sync
go run ./examples/backup-async     # run twice to see dedup at work
```

Point them at a real server with `-url`, `-username`, `-realm`, `-password`,
`-fingerprint`, `-datastore`, `-source` and `-id`.
