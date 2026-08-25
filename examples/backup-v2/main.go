// Command backup-v2 backs up a directory to Proxmox Backup Server as a v2
// split archive: one gopbs.Backup call with Format: gopbs.FormatV2 uploads a
// metadata stream (<name>.mpxar.didx) and a payload stream (<name>.ppxar.didx)
// as two dynamic indexes, generated and uploaded concurrently. There is no
// .pcat1 catalog — the metadata stream itself serves browsing.
//
// The split layout keeps file contents in their own stream, so metadata-only
// changes (touched mtimes, permission changes) leave the payload stream — by
// far the larger of the two — fully deduplicated against the previous
// snapshot.
//
// Restoring needs proxmox-backup-client >= 3.2; the plain archive name finds
// the split pair automatically:
//
//	proxmox-backup-client restore <snapshot> root.pxar <target> --repository ...
//
// The flag defaults match the test stack in tests/compose.yml:
//
//	cd tests && docker compose up -d garage pmoxs3
//	go run ./examples/backup-v2 -source /tmp
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"sync"
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
		name        = flag.String("name", "root", "archive name (uploaded as <name>.mpxar.didx + <name>.ppxar.didx)")
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
			Workers: *workers,
			Scan:    scan.Options{SkipOnError: true},
			OnWarn: func(w archive.Warning) {
				fmt.Fprintf(os.Stderr, "warning: %s (kind %d, err %v)\n", w.Path, w.Kind, w.Err)
			},
		},
		Ref:        pbs.SnapshotRef{Type: "host", ID: *backupID},
		Format:     gopbs.FormatV2,
		Paths:      []string{*source},
		OnProgress: progressLine(),
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("backed up %s as %s/%s/%s in %.1fs\n",
		*source, result.Ref.Type, result.Ref.ID, result.Ref.Time.UTC().Format(time.RFC3339),
		time.Since(started).Seconds())
	fmt.Printf("  metadata (%s): %d bytes in %d chunks (%d uploaded, %d deduplicated)\n",
		result.ArchiveName, result.Archive.Size, result.Archive.ChunkCount,
		result.Archive.NewChunks, result.Archive.ReusedChunks)
	fmt.Printf("  payload:  %d bytes in %d chunks (%d uploaded, %d deduplicated)\n",
		result.Payload.Size, result.Payload.ChunkCount,
		result.Payload.NewChunks, result.Payload.ReusedChunks)
}

// progressLine returns an OnProgress callback rendering both streams'
// progress on one stderr line. The two indexes upload concurrently, so the
// callback arrives from two goroutines — everything below is mutex-guarded.
func progressLine() func(gopbs.Progress) {
	var (
		mu       sync.Mutex
		last     time.Time
		streams  = make(map[string]gopbs.Progress)
		finished int
	)
	return func(p gopbs.Progress) {
		mu.Lock()
		defer mu.Unlock()
		streams[p.Archive] = p
		if p.Done {
			finished++
		}
		if !p.Done && time.Since(last) < 100*time.Millisecond {
			return
		}
		last = time.Now()

		names := make([]string, 0, len(streams))
		for n := range streams {
			names = append(names, n)
		}
		sort.Strings(names) // mpxar before ppxar
		parts := make([]string, 0, len(streams))
		for _, n := range names {
			s := streams[n]
			short := strings.TrimSuffix(n, ".didx")
			switch {
			case s.Done:
				parts = append(parts, fmt.Sprintf("%s %s done", short, mib(s.Stats.Size)))
			case s.Total > 0:
				parts = append(parts, fmt.Sprintf("%s %s/%s %4.1f%%",
					short, mib(s.Stats.Size), mib(s.Total),
					min(100, 100*float64(s.Stats.Size)/float64(s.Total))))
			default:
				parts = append(parts, fmt.Sprintf("%s %s", short, mib(s.Stats.Size)))
			}
		}
		fmt.Fprintf(os.Stderr, "\r%-100s", strings.Join(parts, " | "))
		if finished == 2 {
			fmt.Fprintln(os.Stderr)
		}
	}
}

func mib(b uint64) string { return fmt.Sprintf("%.1f MiB", float64(b)/(1<<20)) }
