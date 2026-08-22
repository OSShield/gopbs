# Examples

Complete backups with a single `gopbs.Backup` call: scan -> plan -> generate ->
chunk -> deduplicate -> upload -> catalog -> manifest -> finish, fully streamed.

| Example | What it shows |
|---|---|
| [backup-sync](backup-sync/) | Fully synchronous generation (`Archive.Workers: 1`). |
| [backup-async](backup-async/) | Asynchronous generation (the default): parallel payload reads reassembled in order — byte-identical output, much faster on many-file trees. |
| [backup-streams](backup-streams/) | Multiple streams of data — virtual files that exist nowhere on disk — under a virtual root: buffered generated content, file-backed streams, and pure readers of pre-known size. |

Both default to backing up `/tmp` against the docker test stack from
[tests/compose.yml](../tests/compose.yml):

```sh
cd tests && docker compose up -d garage pmoxs3 && cd ..
go run ./examples/backup-sync
go run ./examples/backup-async     # run twice (a couple of seconds apart) to see dedup at work
```

Point them at a real server with `-url`, `-username`, `-realm`, `-password`,
`-fingerprint`, `-datastore`, `-source` and `-id`. For the lower-level
building blocks (sessions, manual chunk uploads, custom dedup) see the
`pbs` package documentation and `tests/pbs_test.go`.
