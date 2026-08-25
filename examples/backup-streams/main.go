// Command backup-streams backs up multiple streams of data — virtual files
// that exist nowhere on disk — in one gopbs.Backup call. The streams are
// placed under a virtual root directory named after the archive, and the
// snapshot gets a catalog, so everything browses and restores like a real
// directory tree.
//
// A stream's size must be declared up front (the archive layout commits to
// it), which leads to three practical patterns, all shown here:
//
//  1. generate into a buffer first, then declare the buffer's length —
//     for content whose size is unknown until produced;
//  2. an open file with the size from fstat — streams file content without
//     buffering it;
//  3. a pure reader whose size is known a priori — nothing is buffered at
//     all, the content is produced as the backup consumes it.
//
// The flag defaults match the test stack in tests/compose.yml:
//
//	cd tests && docker compose up -d garage pmoxs3
//	go run ./examples/backup-streams
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"github.com/osshield/gopbs"
	"github.com/osshield/gopbs/archive"
	"github.com/osshield/gopbs/pbs"
)

func main() {
	var (
		url         = flag.String("url", "https://localhost:8007", "PBS base URL")
		username    = flag.String("username", "garagegarage", "user name (without realm)")
		realm       = flag.String("realm", "pbs", "authentication realm")
		password    = flag.String("password", "garagegaragegarage", "password")
		fingerprint = flag.String("fingerprint", "55:BC:29:4B:BA:B6:A1:03:42:A9:D8:51:14:9D:BD:00:D2:2A:9C:A1:B8:4A:85:E1:AF:B2:0C:48:40:D6:CC:A4", "server certificate SHA-256 fingerprint")
		datastore   = flag.String("datastore", "pbs", "datastore name")
		name        = flag.String("name", "streams", "archive name; also the virtual root directory")
		backupID    = flag.String("id", "", "backup id (default: hostname)")
	)
	flag.Parse()

	// Pattern 1: content generated in memory — a report whose size is only
	// known once produced. Buffer it, then declare the buffer's length.
	report, err := json.MarshalIndent(map[string]any{
		"generated": time.Now().UTC().Format(time.RFC3339),
		"host":      hostname(),
		"purpose":   "gopbs multi-stream backup example",
	}, "", "  ")
	if err != nil {
		log.Fatal(err)
	}

	// Pattern 2: file content streamed from an open fd, size from fstat —
	// nothing is buffered in memory.
	hostsFile, err := os.Open("/etc/hosts")
	if err != nil {
		log.Fatal(err)
	}
	defer hostsFile.Close()
	hostsInfo, err := hostsFile.Stat()
	if err != nil {
		log.Fatal(err)
	}

	// Pattern 3: a pure stream of a priori known size — content produced on
	// the fly as the backup consumes it (here 32 MiB of deterministic
	// pseudo-random data; think "database dump of known size").
	const syntheticSize = 32 << 20

	started := time.Now()
	result, err := gopbs.Backup(context.Background(), gopbs.BackupOptions{
		Client: pbs.Config{
			BaseURL:     *url,
			Auth:        pbs.PasswordAuth{Username: *username, Realm: *realm, Password: *password},
			Fingerprint: *fingerprint,
			Datastore:   *datastore,
		},
		// Multiple top-level entries always live under a virtual root
		// directory named Archive.Name.
		Archive: archive.Options{Name: *name},
		Ref:     pbs.SnapshotRef{Type: "host", ID: *backupID},
		Streams: []gopbs.Stream{
			{Name: "report.json", Size: int64(len(report)), Reader: bytes.NewReader(report)},
			{Name: "etc-hosts.txt", Size: hostsInfo.Size(), Reader: hostsFile},
			{Name: "synthetic.bin", Size: syntheticSize, Reader: io.LimitReader(&xorshift{state: 42}, syntheticSize)},
		},
		OnProgress: progressBar(),
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("backed up %d streams as %s/%s/%s: %d bytes in %d chunks (%d uploaded, %d deduplicated) in %.1fs\n",
		3, result.Ref.Type, result.Ref.ID, result.Ref.Time.UTC().Format(time.RFC3339),
		result.Archive.Size, result.Archive.ChunkCount,
		result.Archive.NewChunks, result.Archive.ReusedChunks,
		time.Since(started).Seconds())
}

// xorshift is an endless deterministic byte stream: the same seed always
// produces the same content, so a second run of this example deduplicates
// the synthetic stream completely.
type xorshift struct{ state uint64 }

func (x *xorshift) Read(p []byte) (int, error) {
	for i := range p {
		x.state ^= x.state << 13
		x.state ^= x.state >> 7
		x.state ^= x.state << 17
		p[i] = byte(x.state)
	}
	return len(p), nil
}

func hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return h
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
