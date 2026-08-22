// Command backup-async backs up a directory to Proxmox Backup Server using
// asynchronous archive generation (the library default): the tree layout is
// planned first, then a pool of workers reads file contents in parallel and
// the archive stream is reassembled in order — byte-identical to synchronous
// output, typically many times faster on trees with many files.
//
// It deduplicates against the previous snapshot of the same backup id
// (chunks already known to the server are registered without re-uploading)
// and uploads the .pcat1 catalog alongside the archive so the snapshot is
// browsable in the PBS UI.
//
// The flag defaults match the test stack in tests/compose.yml:
//
//	cd tests && docker compose up -d garage pmoxs3
//	go run ./examples/backup-async -source /tmp
package main

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
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
		workers     = flag.Int("workers", 0, "payload-read workers (0 = GOMAXPROCS)")
	)
	flag.Parse()

	if err := run(*url, *username, *realm, *password, *fingerprint, *datastore, *source, *name, *backupID, *workers); err != nil {
		log.Fatal(err)
	}
}

func run(url, username, realm, password, fingerprint, datastore, source, name, backupID string, workers int) error {
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

	// Workers: 0 selects asynchronous generation with GOMAXPROCS workers —
	// sizes are bound as files are opened, contents prefetched in parallel,
	// and the stream comes out in exact archive order. Name feeds the
	// catalog's top-level entry, which must match the uploaded index name.
	arch, err := archive.New(archive.Options{
		Name:    name,
		Workers: workers,
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

	indexName := name + ".pxar.didx"

	// Seed the dedup set from the previous snapshot of this backup id. The
	// download also registers those chunks with the session, so they may be
	// referenced without re-uploading. Chunks are content-addressed in the
	// datastore, so one set serves the archive and the catalog alike.
	up := &uploader{sess: sess, enc: pbs.NewBlobEncoder(), known: make(map[[32]byte]bool)}
	switch raw, err := sess.DownloadPrevious(ctx, indexName); {
	case err == nil:
		entries, err := pbs.ParseDynamicIndex(raw)
		if err != nil {
			return err
		}
		for _, e := range entries {
			up.known[e.Digest] = true
		}
		fmt.Printf("previous snapshot: %d known chunks\n", len(up.known))
	case errors.Is(err, pbs.ErrNoPrevious):
		fmt.Println("no previous snapshot: full upload")
	default:
		return err
	}

	stream, err := arch.GenerateV1(ctx)
	if err != nil {
		return err
	}
	defer stream.Close()
	total, count, err := up.uploadIndex(ctx, indexName, stream)
	if err != nil {
		return err
	}

	// The .pcat1 catalog makes the snapshot browsable in the PBS UI.
	catStream, err := arch.GenerateCatalog(ctx)
	if err != nil {
		return err
	}
	defer catStream.Close()
	if _, _, err := up.uploadIndex(ctx, "catalog.pcat1.didx", catStream); err != nil {
		return err
	}

	if err := sess.Finish(ctx); err != nil {
		return err
	}

	fmt.Printf("backed up %s: %d bytes in %d chunks (%d uploaded, %d deduplicated) as %s (%.1fs)\n",
		source, total, count, up.uploaded, up.reused, indexName, time.Since(started).Seconds())
	return nil
}

// uploader streams data into one dynamic index at a time: chunk, dedup,
// upload, append in batches of 128, close with the index checksum.
type uploader struct {
	sess     *pbs.BackupSession
	enc      *pbs.BlobEncoder
	known    map[[32]byte]bool
	uploaded uint64
	reused   uint64
}

func (u *uploader) uploadIndex(ctx context.Context, indexName string, r io.Reader) (total, count uint64, err error) {
	wid, err := u.sess.CreateDynamicIndex(ctx, indexName)
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
		if err := u.sess.AppendDynamicIndex(ctx, wid, digests, offsets); err != nil {
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
		if u.known[digest] {
			u.reused++
		} else {
			if err := u.sess.UploadDynamicChunk(ctx, u.enc, wid, digest, chunk.Data); err != nil {
				return 0, 0, err
			}
			u.known[digest] = true // dedup within this backup too
			u.uploaded++
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
	return total, count, u.sess.CloseDynamicIndex(ctx, wid, csumArr, total, count)
}
