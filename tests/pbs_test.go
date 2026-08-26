//go:build integration

package main_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	gopbs "github.com/osshield/gopbs"
	"github.com/osshield/gopbs/archive"
	"github.com/osshield/gopbs/chunker"
	"github.com/osshield/gopbs/pbs"
)

// Connection details of the pmoxs3 service in compose.yml.
const (
	pmoxURL         = "https://localhost:8007"
	pmoxUser        = "garagegarage"
	pmoxRealm       = "pbs"
	pmoxSecret      = "garagegaragegarage"
	pmoxDatastore   = "pbs"
	pmoxFingerprint = "55:BC:29:4B:BA:B6:A1:03:42:A9:D8:51:14:9D:BD:00:D2:2A:9C:A1:B8:4A:85:E1:AF:B2:0C:48:40:D6:CC:A4"
)

type chunkInfo struct {
	digest [32]byte
	hexd   string
	offset uint64
	size   uint64
}

// startPBSStack brings up the garage + pmoxs3 services and tears them down
// after the test (set GOPBS_KEEP_PBS=1 to keep them running for debugging).
func startPBSStack(t *testing.T) {
	t.Helper()
	if err := compose("up", "-d", "garage", "pmoxs3"); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("GOPBS_KEEP_PBS") == "" {
		t.Cleanup(func() {
			if err := compose("rm", "-sf", "pmoxs3", "garage"); err != nil {
				t.Logf("pbs stack teardown: %v", err)
			}
		})
	}
}

// startSession retries StartBackup until the stack is ready (pmoxs3 needs
// garage up and provisioned before logins succeed).
func startSession(t *testing.T, client *pbs.Client, ref pbs.SnapshotRef) *pbs.BackupSession {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	for {
		s, err := client.StartBackup(context.Background(), ref)
		if err == nil {
			return s
		}
		if time.Now().After(deadline) {
			t.Fatalf("pbs stack not ready in time: %v", err)
		}
		time.Sleep(2 * time.Second)
	}
}

// TestPBSBackupSession runs the phase-7 client against a real PBS-protocol
// server implementation (pmoxs3backuproxy backed by garage/S3): a complete
// first backup of the generated source tree, then a second snapshot that
// deduplicates every chunk against the first via /previous.
func TestPBSBackupSession(t *testing.T) {
	startPBSStack(t)
	ctx := context.Background()

	client, err := pbs.NewClient(pbs.Config{
		BaseURL:     pmoxURL,
		Auth:        pbs.PasswordAuth{Username: pmoxUser, Realm: pmoxRealm, Password: pmoxSecret},
		Fingerprint: pmoxFingerprint,
		Datastore:   pmoxDatastore,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Archive the harness source tree and chunk it like the upload pipeline
	// will (small average so even the random tree yields several chunks).
	a, err := archive.New(archive.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.AddDirectory(sourceDir); err != nil {
		t.Fatal(err)
	}
	rc, err := a.GenerateV1(ctx)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(rc)
	rc.Close()
	if err != nil {
		t.Fatal(err)
	}

	var (
		chunks []chunkInfo
		plains [][]byte
		csum   = sha256.New()
		total  uint64
	)
	for c, err := range chunker.Split(bytes.NewReader(data), 128<<10) {
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(c.Data)
		chunks = append(chunks, chunkInfo{
			digest: digest,
			hexd:   hex.EncodeToString(digest[:]),
			offset: c.Offset,
			size:   uint64(len(c.Data)),
		})
		plains = append(plains, c.Data)
		total = c.Offset + uint64(len(c.Data))
		binary.Write(csum, binary.LittleEndian, total)
		csum.Write(digest[:])
	}
	if total != uint64(len(data)) {
		t.Fatalf("chunks cover %d of %d bytes", total, len(data))
	}
	var csumArr [32]byte
	copy(csumArr[:], csum.Sum(nil))
	t.Logf("archive: %d bytes in %d chunks", len(data), len(chunks))

	// Unique backup id per run: fresh history regardless of leftover state.
	ref := pbs.SnapshotRef{Type: "host", ID: fmt.Sprintf("gopbs-it-%d", time.Now().UnixNano())}
	ref.Time = time.Now()

	// --- First backup: everything uploaded. ---
	sess := startSession(t, client, ref)
	if _, err := sess.DownloadPrevious(ctx, "root.pxar.didx"); !errors.Is(err, pbs.ErrNoPrevious) {
		t.Fatalf("previous on first backup of fresh id: %v", err)
	}

	wid, err := sess.CreateDynamicIndex(ctx, "root.pxar.didx")
	if err != nil {
		t.Fatal(err)
	}
	enc := pbs.NewBlobEncoder()
	for i, c := range chunks {
		if err := sess.UploadDynamicChunk(ctx, enc, wid, c.digest, plains[i]); err != nil {
			t.Fatalf("chunk %d: %v", i, err)
		}
	}
	if err := appendAll(ctx, sess, wid, chunks); err != nil {
		t.Fatal(err)
	}
	if err := sess.CloseDynamicIndex(ctx, wid, csumArr, total, uint64(len(chunks))); err != nil {
		t.Fatal(err)
	}
	if err := sess.Finish(ctx); err != nil {
		t.Fatal(err)
	}

	// --- Second backup: dedup everything against the previous snapshot. ---
	ref2 := ref
	ref2.Time = ref.Time.Add(2 * time.Second)
	sess2, err := client.StartBackup(ctx, ref2)
	if err != nil {
		t.Fatal(err)
	}

	raw, err := sess2.DownloadPrevious(ctx, "root.pxar.didx")
	if err != nil {
		t.Fatalf("previous after first backup: %v", err)
	}
	entries, err := pbs.ParseDynamicIndex(raw)
	if err != nil {
		t.Fatal(err)
	}
	known := make(map[string]bool, len(entries))
	for _, e := range entries {
		known[hex.EncodeToString(e.Digest[:])] = true
	}
	for i, c := range chunks {
		if !known[c.hexd] {
			t.Fatalf("chunk %d (%s) missing from previous index", i, c.hexd)
		}
	}
	if len(entries) != len(chunks) {
		t.Errorf("previous index has %d entries, uploaded %d", len(entries), len(chunks))
	}
	if last := entries[len(entries)-1].EndOffset; last != total {
		t.Errorf("previous index size %d, want %d", last, total)
	}

	// Register the same content without re-uploading a single chunk.
	wid2, err := sess2.CreateDynamicIndex(ctx, "root.pxar.didx")
	if err != nil {
		t.Fatal(err)
	}
	if err := appendAll(ctx, sess2, wid2, chunks); err != nil {
		t.Fatalf("dedup append (no uploads): %v", err)
	}
	if err := sess2.CloseDynamicIndex(ctx, wid2, csumArr, total, uint64(len(chunks))); err != nil {
		t.Fatal(err)
	}
	if err := sess2.Finish(ctx); err != nil {
		t.Fatal(err)
	}
}

func appendAll(ctx context.Context, sess *pbs.BackupSession, wid uint64, chunks []chunkInfo) error {
	for start := 0; start < len(chunks); start += 128 {
		end := start + 128
		if end > len(chunks) {
			end = len(chunks)
		}
		digests := make([]string, 0, end-start)
		offsets := make([]uint64, 0, end-start)
		for _, c := range chunks[start:end] {
			digests = append(digests, c.hexd)
			offsets = append(offsets, c.offset)
		}
		if err := sess.AppendDynamicIndex(ctx, wid, digests, offsets); err != nil {
			return err
		}
	}
	return nil
}

// TestBackupOrchestrator is the phase-9 gate: one gopbs.Backup call against
// the pmoxs3 stack, restored with the official proxmox-backup-client and
// compared against the source tree; a second run must deduplicate fully.
func TestBackupOrchestrator(t *testing.T) {
	startPBSStack(t)
	ctx := context.Background()

	opts := gopbs.BackupOptions{
		Client: pbs.Config{
			BaseURL:      pmoxURL,
			Auth:         pbs.PasswordAuth{Username: pmoxUser, Realm: pmoxRealm, Password: pmoxSecret},
			Fingerprint:  pmoxFingerprint,
			Datastore:    pmoxDatastore,
			Workers:      4,
			ChunkSizeAvg: 128 << 10,
		},
		Archive: archive.Options{Name: "root"},
		Ref:     pbs.SnapshotRef{Type: "host", ID: fmt.Sprintf("gopbs-e2e-%d", time.Now().UnixNano())},
		Paths:   []string{sourceDir},
		// Metadata blobs ride alongside the archive in the snapshot without
		// being part of it; ".blob" is appended to the first name.
		Blobs: []gopbs.Blob{
			{Name: "app-meta.json", Data: []byte(`{"app":"gopbs-harness","kept-for":"90d"}`)},
			{Name: "notes.txt.blob", Data: bytes.Repeat([]byte("compressible notes "), 200)},
		},
	}

	// First backup (retried while the stack comes up).
	var (
		result *gopbs.BackupResult
		err    error
	)
	deadline := time.Now().Add(90 * time.Second)
	for {
		result, err = gopbs.Backup(ctx, opts)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("backup did not succeed in time: %v", err)
		}
		time.Sleep(2 * time.Second)
	}
	if result.Archive.ChunkCount == 0 || result.Archive.Size == 0 {
		t.Fatalf("archive stats: %+v", result.Archive)
	}
	if result.Catalog.ChunkCount == 0 {
		t.Fatalf("catalog stats: %+v", result.Catalog)
	}
	t.Logf("backup 1: %+v (catalog %+v)", result.Archive, result.Catalog)

	// Restore with the official client and compare against the source.
	snapshot := fmt.Sprintf("%s/%s/%s", result.Ref.Type, result.Ref.ID,
		result.Ref.Time.UTC().Format(time.RFC3339))
	if err := compose("run", "--rm", "--remove-orphans",
		"-e", "SNAPSHOT="+snapshot,
		"-e", "ARCHIVE=root.pxar",
		"-e", "TARGET=/restore/e2e",
		"pbsrestore"); err != nil {
		t.Fatalf("restore: %v", err)
	}
	equal, err := compareTrees(filepath.Join(restoreDir, "e2e"), sourceDir)
	if err != nil {
		t.Fatal(err)
	}
	if !equal {
		t.Fatal("restored tree differs from source")
	}

	// The metadata blobs restore by name with their exact content.
	for _, blob := range []struct{ name, target string }{
		{"app-meta.json.blob", "e2e-meta.json"},
		{"notes.txt.blob", "e2e-notes.txt"},
	} {
		if err := compose("run", "--rm", "--remove-orphans",
			"-e", "SNAPSHOT="+snapshot,
			"-e", "ARCHIVE="+blob.name,
			"-e", "TARGET=/restore/"+blob.target,
			"pbsrestore"); err != nil {
			t.Fatalf("restoring blob %s: %v", blob.name, err)
		}
	}
	for i, target := range []string{"e2e-meta.json", "e2e-notes.txt"} {
		got, err := os.ReadFile(filepath.Join(restoreDir, target))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, opts.Blobs[i].Data) {
			t.Errorf("blob %s restored %d bytes, want %d", opts.Blobs[i].Name, len(got), len(opts.Blobs[i].Data))
		}
	}

	// Second backup of unchanged content: everything deduplicates.
	time.Sleep(2 * time.Second) // pmoxs3 resolves "previous" at seconds granularity
	opts.Ref.Time = time.Time{}
	result2, err := gopbs.Backup(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("backup 2: %+v (catalog %+v)", result2.Archive, result2.Catalog)
	if result2.Archive.NewChunks != 0 || result2.Archive.ReusedChunks != result2.Archive.ChunkCount {
		t.Errorf("second backup should deduplicate fully: %+v", result2.Archive)
	}
}

// TestBackupOrchestratorEncrypted is the encryption gate: a client-side
// encrypted gopbs.Backup, restored and decrypted by the official
// proxmox-backup-client using a key file gopbs itself created — proving
// key-file, chunk-format and manifest interop in one round trip — then a
// second run that must deduplicate fully against the previous snapshot's
// keyed digests.
func TestBackupOrchestratorEncrypted(t *testing.T) {
	startPBSStack(t)
	ctx := context.Background()

	key, err := pbs.GenerateEncryptionKey()
	if err != nil {
		t.Fatal(err)
	}
	keyJSON, err := pbs.CreateKeyFile(key, nil, pbs.KDFNone, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(keysDir, "pbs-key.json"), keyJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	// Load it back through the library — the restore below then has the
	// official client consume the same file.
	info, err := pbs.LoadKeyFile(keyJSON, nil)
	if err != nil {
		t.Fatal(err)
	}
	if info.Key != key {
		t.Fatal("key file round trip lost the key")
	}

	opts := gopbs.BackupOptions{
		Client: pbs.Config{
			BaseURL:      pmoxURL,
			Auth:         pbs.PasswordAuth{Username: pmoxUser, Realm: pmoxRealm, Password: pmoxSecret},
			Fingerprint:  pmoxFingerprint,
			Datastore:    pmoxDatastore,
			Workers:      4,
			ChunkSizeAvg: 128 << 10,
			Crypt:        info.CryptConfig(pbs.CryptModeEncrypt),
		},
		Archive: archive.Options{Name: "root"},
		Ref:     pbs.SnapshotRef{Type: "host", ID: fmt.Sprintf("gopbs-e2e-enc-%d", time.Now().UnixNano())},
		Paths:   []string{sourceDir},
		Blobs: []gopbs.Blob{
			{Name: "enc-meta.json", Data: []byte(`{"app":"gopbs-harness","encrypted":true}`)},
		},
	}

	var result *gopbs.BackupResult
	deadline := time.Now().Add(90 * time.Second)
	for {
		result, err = gopbs.Backup(ctx, opts)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("backup did not succeed in time: %v", err)
		}
		time.Sleep(2 * time.Second)
	}
	t.Logf("encrypted backup 1: %+v (catalog %+v)", result.Archive, result.Catalog)

	// The official client must decrypt the archive with our key file.
	snapshot := fmt.Sprintf("%s/%s/%s", result.Ref.Type, result.Ref.ID,
		result.Ref.Time.UTC().Format(time.RFC3339))
	if err := compose("run", "--rm", "--remove-orphans",
		"-e", "SNAPSHOT="+snapshot,
		"-e", "ARCHIVE=root.pxar",
		"-e", "TARGET=/restore/e2e-enc",
		"-e", "KEYFILE=/keys/pbs-key.json",
		"pbsrestore"); err != nil {
		t.Fatalf("restore: %v", err)
	}
	equal, err := compareTrees(filepath.Join(restoreDir, "e2e-enc"), sourceDir)
	if err != nil {
		t.Fatal(err)
	}
	if !equal {
		t.Fatal("restored tree differs from source")
	}

	// Blobs are encrypted too; the official client must decrypt them.
	if err := compose("run", "--rm", "--remove-orphans",
		"-e", "SNAPSHOT="+snapshot,
		"-e", "ARCHIVE=enc-meta.json.blob",
		"-e", "TARGET=/restore/e2e-enc-meta.json",
		"-e", "KEYFILE=/keys/pbs-key.json",
		"pbsrestore"); err != nil {
		t.Fatalf("restoring blob: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(restoreDir, "e2e-enc-meta.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, opts.Blobs[0].Data) {
		t.Errorf("blob restored %d bytes, want %d", len(got), len(opts.Blobs[0].Data))
	}

	// Second backup of unchanged content: the keyed digests must match the
	// previous snapshot's index, so everything deduplicates.
	time.Sleep(2 * time.Second) // pmoxs3 resolves "previous" at seconds granularity
	opts.Ref.Time = time.Time{}
	result2, err := gopbs.Backup(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("encrypted backup 2: %+v (catalog %+v)", result2.Archive, result2.Catalog)
	if result2.Archive.NewChunks != 0 || result2.Archive.ReusedChunks != result2.Archive.ChunkCount {
		t.Errorf("second backup should deduplicate fully: %+v", result2.Archive)
	}
}

// TestBackupOrchestratorV2 is the phase-10 gate: one gopbs.Backup call in
// FormatV2 (split mpxar/ppxar, no catalog) against the pmoxs3 stack, restored
// with the official proxmox-backup-client — addressed as "root.pxar" to prove
// the client's split-archive name fallback finds our indexes — and compared
// against the source; a second run must deduplicate fully on both streams.
func TestBackupOrchestratorV2(t *testing.T) {
	startPBSStack(t)
	ctx := context.Background()

	opts := gopbs.BackupOptions{
		Client: pbs.Config{
			BaseURL:      pmoxURL,
			Auth:         pbs.PasswordAuth{Username: pmoxUser, Realm: pmoxRealm, Password: pmoxSecret},
			Fingerprint:  pmoxFingerprint,
			Datastore:    pmoxDatastore,
			Workers:      4,
			ChunkSizeAvg: 128 << 10,
		},
		Archive: archive.Options{Name: "root"},
		Ref:     pbs.SnapshotRef{Type: "host", ID: fmt.Sprintf("gopbs-e2e-v2-%d", time.Now().UnixNano())},
		Format:  gopbs.FormatV2,
		Paths:   []string{sourceDir},
	}

	var (
		result *gopbs.BackupResult
		err    error
	)
	deadline := time.Now().Add(90 * time.Second)
	for {
		result, err = gopbs.Backup(ctx, opts)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("backup did not succeed in time: %v", err)
		}
		time.Sleep(2 * time.Second)
	}
	if result.ArchiveName != "root.mpxar.didx" {
		t.Errorf("archive name %q", result.ArchiveName)
	}
	if result.Archive.ChunkCount == 0 || result.Payload.ChunkCount == 0 {
		t.Fatalf("stream stats: meta %+v payload %+v", result.Archive, result.Payload)
	}
	if result.Catalog.ChunkCount != 0 {
		t.Errorf("v2 backup uploaded a catalog: %+v", result.Catalog)
	}
	t.Logf("backup 1: meta %+v payload %+v", result.Archive, result.Payload)

	snapshot := fmt.Sprintf("%s/%s/%s", result.Ref.Type, result.Ref.ID,
		result.Ref.Time.UTC().Format(time.RFC3339))
	if err := compose("run", "--rm", "--remove-orphans",
		"-e", "SNAPSHOT="+snapshot,
		"-e", "ARCHIVE=root.pxar",
		"-e", "TARGET=/restore/e2e-v2",
		"pbsrestore"); err != nil {
		t.Fatalf("restore: %v", err)
	}
	equal, err := compareTrees(filepath.Join(restoreDir, "e2e-v2"), sourceDir)
	if err != nil {
		t.Fatal(err)
	}
	if !equal {
		t.Fatal("restored tree differs from source")
	}

	// Second backup of unchanged content: everything deduplicates.
	time.Sleep(2 * time.Second) // pmoxs3 resolves "previous" at seconds granularity
	opts.Ref.Time = time.Time{}
	result2, err := gopbs.Backup(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("backup 2: meta %+v payload %+v", result2.Archive, result2.Payload)
	if result2.Payload.NewChunks != 0 || result2.Payload.ReusedChunks != result2.Payload.ChunkCount {
		t.Errorf("second backup should deduplicate the payload stream fully: %+v", result2.Payload)
	}
	if result2.Archive.NewChunks != 0 || result2.Archive.ReusedChunks != result2.Archive.ChunkCount {
		t.Errorf("second backup should deduplicate the metadata stream fully: %+v", result2.Archive)
	}
}
