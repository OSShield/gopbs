package gopbs_test

import (
	"context"
	"fmt"
	"log"

	"github.com/scheiblingco/gopbs"
	"github.com/scheiblingco/gopbs/archive"
	"github.com/scheiblingco/gopbs/pbs"
	"github.com/scheiblingco/gopbs/scan"
)

// A complete backup in one call: scan, plan, generate, chunk, deduplicate
// against the previous snapshot, upload, catalog, manifest, finish.
func ExampleBackup() {
	result, err := gopbs.Backup(context.Background(), gopbs.BackupOptions{
		Client: pbs.Config{
			BaseURL:     "https://pbs.example.com:8007",
			Auth:        pbs.TokenAuth{AuthID: "backup@pbs!mytoken", Secret: "…"},
			Fingerprint: "AA:BB:…", // sha256 of the server certificate
			Datastore:   "backups",
		},
		Archive: archive.Options{
			Name: "root",
			Scan: scan.Options{SkipOnError: true},
		},
		Ref:   pbs.SnapshotRef{Type: "host", ID: "myhost"},
		Paths: []string{"/etc", "/srv"},
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s/%s/%s: %d bytes in %d chunks (%d new)\n",
		result.Ref.Type, result.Ref.ID, result.Ref.Time,
		result.Archive.Size, result.Archive.ChunkCount, result.Archive.NewChunks)
}
