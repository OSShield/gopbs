// Command backup-async backs up a directory to Proxmox Backup Server with a
// single gopbs.Backup call, using asynchronous archive generation (the
// library default): the tree layout is planned first, then a pool of workers
// reads file contents in parallel while the stream is chunked, deduplicated
// against the previous snapshot, and uploaded concurrently. The .pcat1
// catalog is included so the snapshot is browsable in the PBS UI.
//
// The flag defaults match the test stack in tests/compose.yml:
//
//	cd tests && docker compose up -d garage pmoxs3
//	go run ./examples/backup-async -source /tmp
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/osshield/gopbs"
	"github.com/osshield/gopbs/archive"
	"github.com/osshield/gopbs/pbs"
	"github.com/osshield/gopbs/scan"
)

func main() {
	var (
		url         = flag.String("url", "https://localhost:8007", "PBS base URL")
		username    = flag.String("username", "garagegarage", "user name (without realm)")
		realm       = flag.String("realm", "pbs", "authentication realm")
		password    = flag.String("password", "garagegaragegarage", "password")
		fingerprint = flag.String("fingerprint", "55:BC:29:4B:BA:B6:A1:03:42:A9:D8:51:14:9D:BD:00:D2:2A:9C:A1:B8:4A:85:E1:AF:B2:0C:48:40:D6:CC:A4", "server certificate SHA-256 fingerprint")
		datastore   = flag.String("datastore", "pbs", "datastore name")
		source      = flag.String("source", "/tmp", "directory to back up")
		name        = flag.String("name", "root", "archive name (uploaded as <name>.pxar.didx)")
		backupID    = flag.String("id", "", "backup id (default: hostname)")
		workers     = flag.Int("workers", 0, "payload-read workers (0 = GOMAXPROCS)")
	)
	flag.Parse()

	started := time.Now()
	result, err := gopbs.Backup(context.Background(), gopbs.BackupOptions{
		Client: pbs.Config{
			BaseURL:     *url,
			Auth:        pbs.PasswordAuth{Username: *username, Realm: *realm, Password: *password},
			Fingerprint: *fingerprint,
			Datastore:   *datastore,
		},
		Archive: archive.Options{
			Name:    *name,
			Workers: *workers, // 0 = asynchronous generation with GOMAXPROCS workers
			Scan:    scan.Options{SkipOnError: true},
			OnWarn: func(w archive.Warning) {
				fmt.Fprintf(os.Stderr, "warning: %s (kind %d, err %v)\n", w.Path, w.Kind, w.Err)
			},
		},
		Ref:        pbs.SnapshotRef{Type: "host", ID: *backupID},
		Paths:      []string{*source},
		OnProgress: progressBar(),
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("backed up %s as %s/%s/%s: %d bytes in %d chunks (%d uploaded, %d deduplicated) in %.1fs\n",
		*source, result.Ref.Type, result.Ref.ID, result.Ref.Time.UTC().Format(time.RFC3339),
		result.Archive.Size, result.Archive.ChunkCount,
		result.Archive.NewChunks, result.Archive.ReusedChunks,
		time.Since(started).Seconds())
}

// progressBar returns an OnProgress callback rendering a live bar on stderr.
func progressBar() func(gopbs.Progress) {
	var last time.Time
	return func(p gopbs.Progress) {
		if !p.Done && time.Since(last) < 100*time.Millisecond {
			return
		}
		last = time.Now()
		if p.Total > 0 {
			frac := float64(p.Stats.Size) / float64(p.Total)
			if frac > 1 {
				frac = 1
			}
			const width = 30
			fmt.Fprintf(os.Stderr, "\r%-22s [%-30s] %5.1f%% %9s / %-9s new %d reused %d ",
				p.Archive, strings.Repeat("=", int(frac*width)), frac*100,
				mib(p.Stats.Size), mib(p.Total), p.Stats.NewChunks, p.Stats.ReusedChunks)
		} else {
			fmt.Fprintf(os.Stderr, "\r%-22s %9s  new %d reused %d ",
				p.Archive, mib(p.Stats.Size), p.Stats.NewChunks, p.Stats.ReusedChunks)
		}
		if p.Done {
			fmt.Fprintln(os.Stderr)
		}
	}
}

func mib(b uint64) string { return fmt.Sprintf("%.1f MiB", float64(b)/(1<<20)) }
