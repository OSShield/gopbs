// Command backup-sync backs up a directory to Proxmox Backup Server using
// fully synchronous archive generation (Workers: 1): one goroutine walks the
// tree, reads file contents, and the resulting stream is chunked and
// uploaded one chunk at a time. The .pcat1 catalog is uploaded alongside the
// archive so the snapshot is browsable in the PBS UI.
//
// The flag defaults match the test stack in tests/compose.yml:
//
//	cd tests && docker compose up -d garage pmoxs3
//	go run ./examples/backup-sync -source /tmp
package main

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/scheiblingco/gopbs/archive"
	"github.com/scheiblingco/gopbs/chunker"
	"github.com/scheiblingco/gopbs/pbs"
	"github.com/scheiblingco/gopbs/scan"
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
	)
	flag.Parse()

	if err := run(*url, *username, *realm, *password, *fingerprint, *datastore, *source, *name, *backupID); err != nil {
		log.Fatal(err)
	}
}

func run(url, username, realm, password, fingerprint, datastore, source, name, backupID string) error {
	ctx := context.Background()
	started := time.Now()

	client, err := pbs.NewClient(pbs.Config{
		BaseURL:     url,
		Auth:        pbs.PasswordAuth{Username: username, Realm: realm, Password: password},
		Fingerprint: fingerprint,
		Datastore:   datastore,
	})
	if err != nil {
		return err
	}

	// Workers: 1 selects fully synchronous generation. SkipOnError keeps one
	// unreadable file (common under /tmp) from failing the whole backup; each
	// skip surfaces through OnWarn instead. Name feeds the catalog's
	// top-level entry, which must match the uploaded index name.
	arch, err := archive.New(archive.Options{
		Name:    name,
		Workers: 1,
		Scan:    scan.Options{SkipOnError: true},
		OnWarn: func(w archive.Warning) {
			fmt.Fprintf(os.Stderr, "warning: %s (kind %d, err %v)\n", w.Path, w.Kind, w.Err)
		},
	})
	if err != nil {
		return err
	}
	if err := arch.AddDirectory(source); err != nil {
		return err
	}

	sess, err := client.StartBackup(ctx, pbs.SnapshotRef{Type: "host", ID: backupID})
	if err != nil {
		return err
	}
	defer sess.Abort() // no-op after a successful Finish

	enc := pbs.NewBlobEncoder()
	indexName := name + ".pxar.didx"

	stream, err := arch.GenerateV1(ctx)
	if err != nil {
		return err
	}
	defer stream.Close()
	total, count, err := uploadIndex(ctx, sess, enc, indexName, stream)
	if err != nil {
		return err
	}

	// The .pcat1 catalog makes the snapshot browsable in the PBS UI.
	catStream, err := arch.GenerateCatalog(ctx)
	if err != nil {
		return err
	}
	defer catStream.Close()
	if _, _, err := uploadIndex(ctx, sess, enc, "catalog.pcat1.didx", catStream); err != nil {
		return err
	}

	if err := sess.Finish(ctx); err != nil {
		return err
	}

	fmt.Printf("backed up %s: %d bytes in %d chunks as %s (%.1fs)\n",
		source, total, count, indexName, time.Since(started).Seconds())
	return nil
}

// uploadIndex streams data into one dynamic index: chunk, upload, append in
// batches of 128, close with the index checksum.
func uploadIndex(ctx context.Context, sess *pbs.BackupSession, enc *pbs.BlobEncoder, indexName string, r io.Reader) (total, count uint64, err error) {
	wid, err := sess.CreateDynamicIndex(ctx, indexName)
	if err != nil {
		return 0, 0, err
	}

	var (
		csum    = sha256.New()
		digests []string
		offsets []uint64
	)
	flush := func() error {
		if len(digests) == 0 {
			return nil
		}
		if err := sess.AppendDynamicIndex(ctx, wid, digests, offsets); err != nil {
			return err
		}
		digests, offsets = digests[:0], offsets[:0]
		return nil
	}
	for chunk, err := range chunker.Split(r, 0) { // 0 = the 4 MiB PBS default
		if err != nil {
			return 0, 0, err
		}
		digest := sha256.Sum256(chunk.Data)
		if err := sess.UploadDynamicChunk(ctx, enc, wid, digest, chunk.Data); err != nil {
			return 0, 0, err
		}
		digests = append(digests, hex.EncodeToString(digest[:]))
		offsets = append(offsets, chunk.Offset)
		total = chunk.Offset + uint64(len(chunk.Data))
		count++
		binary.Write(csum, binary.LittleEndian, total)
		csum.Write(digest[:])
		if len(digests) == 128 {
			if err := flush(); err != nil {
				return 0, 0, err
			}
		}
	}
	if err := flush(); err != nil {
		return 0, 0, err
	}

	var csumArr [32]byte
	copy(csumArr[:], csum.Sum(nil))
	return total, count, sess.CloseDynamicIndex(ctx, wid, csumArr, total, count)
}
