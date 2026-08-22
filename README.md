# go-pbs
GoPBS is a Go library meant to make it easier to backup and restore data to and from PBS (Proxmox Backup Server). It provides a number of interfaces for various types of tasks, including PXAR, PCAT generation (v1 and v2) and full backup creation + upload to PBS.

## Credit
Credit where credit is due - I did not figure most of this process out by myself. 

A large part of the initial work regarding finding the specification, optimizing the backup process, etc. was done by [@tizbac](https://github.com/tizbac), go support his work if you are able. 

## Feature Status
- [/] PXAR Archive generation
  - [ ] PXAR Version 1
  - [x] PCAT generation
  - [x] Synchronous and asynchronous archive generation
  - [ ] Compression (zstd)
  - [ ] Encryption (AES-256)
  
- [x] Backup to PBS and [@tizbac/pmoxs3backuproxy](https://github.com/tizbac/pmoxs3backuproxy) (S3-compatible proxy for PBS)
  - [x] Directories (single or multiple)
  - [x] Files (single file or multiple files per archive)
  - [x] Data stream (stdin, writers)
  - [x] Synchronous and parallel backup uploads
  - [x] Deduplication and change-only uploads

- [ ] Restore data from PBS
  - [ ] Restore to disk
  - [ ] Restore to stream (stdout, writers)
  - [ ] Synchronous and parallel restore

- [ ] Backup and restore sources
  - [x] Linux filesystem
    - [x] Plain Filesystem (ext4, xfs, btrfs, etc.)
	- [ ] Snapshot-based (LVM, ZFS, BTRFS, etc.)
	- [ ] Remote filesystems (via rclone)
	- [ ] Block devices

  - [ ]  Windows filesystem
	- [ ] Plain Filesystem (NTFS, FAT32, exFAT, etc.)
	- [ ] Snapshot-based (VSS)

  - [ ] Backup and restore databases
    - [ ] MySQL
	- [ ] PostgreSQL
	- [ ] MongoDB
	- [ ] SQL Server

  - [ ] Backup and restore kubernetes
    - [ ] Backup PVCs (non-snapshot)
	- [ ] Backup snapshots (via CSI and Snapshot API)
	- [ ] Backup cluster resources/state


## Installation
### Module
```bash
go get github.com/scheiblingco/gopbs
```

### CLI
```bash
go install github.com/scheiblingco/gopbs/cmd/gopbs@latest
```

## Usage
### Create a backup and upload to PBS
```go
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/scheiblingco/gopbs"
	"github.com/scheiblingco/gopbs/archive"
	"github.com/scheiblingco/gopbs/pbs"
	"github.com/scheiblingco/gopbs/scan"
)

func main() {
	started := time.Now()

	result, err := gopbs.Backup(context.Background(), gopbs.BackupOptions{
		Client: pbs.Config{
			// The URL of the PBS instance, including https and port
			BaseURL: "https://my-pbs.instance.localhost:8007",

			// Authenticate with AuthID and Secret (token-based)
			Auth: pbs.TokenAuth{
				AuthID: "root@pbs!token",
				Secret: "12345678-1234-1234-1234-1234567890ab",
			},

			// You can also authenticate with username/password
			// Auth: pbs.PasswordAuth{
			//     Username: "root",
			//     Realm: "pbs",
			//     Password: "my-secure-password"
			// },

			// The datastore to use for the backup
			Datastore: "SRV-TESTS",

			// Optionally, you can specify a different namespace
			// Namespace:       "my-namespace",

			// The fingerprint of the PBS server's TLS certificate (SHA256)
			Fingerprint: "2F:6B:30:B8:B4:8B:5C:95:40:B9:F0:06:4B:5F:62:6A:47:E9:8B:27:EE:09:96:0C:30:F1:22:AE:58:B9:A5:24",

			// Alternatively, you can skip TLS verification (not recommended for production)
			// InsecureSkipAll: true,

			// Number of concurrent workers for uploading chunks to PBS.
			// Default: 4
			Workers: 6,

			// Set the average chunk size, must be a power of two
			// Generally, this does not need to be changed, but can be adjusted for performance tuning
			// in some specific scenarios. The default value is 4MiB, which balances speed and efficiency for deduplication.
			// Default: 4MiB
			// ChunkSizeAvg: 4 * 1024 * 1024,

			// If you want to follow the upload progress, you can use the OnProgress callback.
			// OnUploadProgress: func(archiveName string, stats pbs.UploadStats, done bool) {}
		},

		Archive: archive.Options{
			// The archive ID (name)
			Name: "my-archive-name",

			// Number of concurrent workers for scanning and generating the archive.
			Workers: 5,

			// Settings for scanning and creating the archive
			Scan: scan.Options{
				// Skip files on error instead of failing the entire backup
				SkipOnError: true,

				// Replaces the metadata reader with a custom implementation instead of the linux stat reader.
				// This is useful for testing environments or to add metadata to a stream-based backup
				// Reader: scan.MetadataReader{},

				// This function is called for each warning encountered during scanning. You can log or handle warnings as needed.
				// OnWarn: func(w scan.Warning) {},

				// If true, skip reading quota project IDs from the filesystem
				// This can improve performance, and saves one ioctl call per directory and file,
				// but it means that the backup will not be able to restore quota project IDs.
				// SkipQuotaProjIDs: false,

			},

			// This function is called for each warning encountered during archive generation. You can log or handle warnings as needed.
			OnWarn: func(w archive.Warning) {
				fmt.Fprintf(os.Stderr, "warning: %s (kind %d, err %v)\n", w.Path, w.Kind, w.Err)
			},

			// The buffer size used for the archive generation. This can be tuned for performance.
			// Default: 16MiB
			// Buffer: 16 * 1024 * 1024,
		},
		Ref: pbs.SnapshotRef{
			// Set the snapshot/backup type. Valid values are "host", "vm", or "ct". Default is "host".
			Type: "ct",

			// Set the ID for the snapshot. If empty, it defaults to the hostname of the machine running the backup.
			ID: "my-container-name",

			// Manually set the timestamp for the backup snapshot.
			// Default: time.Now()
			// Time: time.Now(),
		},

		// Set the archive format for uploads.
		// Older versions of PBS and pmoxs3backuproxy only support FormatV1, which is the classic single-stream pxar plus a .pcat1 catalog.
		// The V2 format is supported by newer PBS versions and is more efficient at deduplication.
		Format: gopbs.FormatV1,

		// Filesystem paths to include in the backup.
		// If more than one is selected, a virtual top-level directory will be created with the name of the archive.
		// If a single directory is selected, it will become the root of the archive.
		Paths: []string{"/srv", "/var"},

		// Callback for live progress updates during the backup process.
		// OnProgress: func(p gopbs.Progress) {},

		// Skip the PCAT catalogue upload. This means the snapshot will not be browsable in the PBS UI.
		// SkipCatalog: false,
	})
	if err != nil {
		log.Fatalf("%v", err)
	}

	fmt.Printf("backed up %s/%s/%s: %d bytes in %d chunks (%d uploaded, %d deduplicated), catalog %d entries bytes, %d warnings (%.1fs)\n",
		result.Ref.Type, result.Ref.ID, result.Ref.Time.UTC().Format(time.RFC3339),
		result.Archive.Size, result.Archive.ChunkCount,
		result.Archive.NewChunks, result.Archive.ReusedChunks,
		result.Catalog.Size, len(result.Warnings), time.Since(started).Seconds())
}
```