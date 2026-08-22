package pbs_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/scheiblingco/gopbs/chunker"
	"github.com/scheiblingco/gopbs/pbs"
)

// pipelineData builds a stream with a large repeated region so content-
// defined chunking yields identical interior chunks (intra-stream dedup).
func pipelineData(t *testing.T) []byte {
	t.Helper()
	rng := rand.New(rand.NewSource(11))
	blockA := make([]byte, 2<<20)
	rng.Read(blockA)
	blockB := make([]byte, 1<<20)
	rng.Read(blockB)
	return bytes.Join([][]byte{blockA, blockB, blockA}, nil)
}

type expectedChunk struct {
	digest string
	offset uint64
	size   uint64
}

// expectedChunks computes the reference chunking + digests locally.
func expectedChunks(t *testing.T, data []byte, avg uint64) ([]expectedChunk, [32]byte) {
	t.Helper()
	var out []expectedChunk
	csum := sha256.New()
	for c, err := range chunker.Split(bytes.NewReader(data), avg) {
		if err != nil {
			t.Fatal(err)
		}
		d := sha256.Sum256(c.Data)
		out = append(out, expectedChunk{hex.EncodeToString(d[:]), c.Offset, uint64(len(c.Data))})
		binary.Write(csum, binary.LittleEndian, c.Offset+uint64(len(c.Data)))
		csum.Write(d[:])
	}
	var sum [32]byte
	copy(sum[:], csum.Sum(nil))
	return out, sum
}

// The phase-8 gate: randomized upload latencies force out-of-order chunk
// completion; the index must nevertheless be appended in exact stream order
// with the correct checksum, and repeated content must deduplicate.
func TestUploadPipeline(t *testing.T) {
	m := newMockPBS(t)
	m.mu.Lock()
	m.chunkDelay = func(digest string) time.Duration {
		return time.Duration(digest[0]%32) * time.Millisecond
	}
	m.mu.Unlock()

	data := pipelineData(t)
	const avg = 64 << 10
	expected, wantCsum := expectedChunks(t, data, avg)

	c := clientFor(t, m, func(cfg *pbs.Config) { cfg.Workers = 8; cfg.ChunkSizeAvg = avg })
	s := start(t, c)
	defer s.Abort()

	stats, err := s.UploadPXARv1(context.Background(), "root.pxar", bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}

	if stats.Size != uint64(len(data)) || stats.ChunkCount != uint64(len(expected)) {
		t.Errorf("stats size=%d count=%d, want %d/%d", stats.Size, stats.ChunkCount, len(data), len(expected))
	}
	if stats.NewChunks+stats.ReusedChunks != stats.ChunkCount {
		t.Errorf("new %d + reused %d != count %d", stats.NewChunks, stats.ReusedChunks, stats.ChunkCount)
	}
	if stats.ReusedChunks == 0 {
		t.Error("repeated region produced no intra-stream dedup")
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	var idx *mockIndex
	for _, i := range m.indexes {
		if i.name == "root.pxar.didx" {
			idx = i
		}
	}
	if idx == nil || !idx.closed {
		t.Fatalf("index missing or not closed: %+v", idx)
	}
	if idx.csum != hex.EncodeToString(wantCsum[:]) {
		t.Errorf("index csum %s, want %s", idx.csum, hex.EncodeToString(wantCsum[:]))
	}
	if idx.size != uint64(len(data)) || idx.chunkCount != uint64(len(expected)) {
		t.Errorf("index size=%d count=%d", idx.size, idx.chunkCount)
	}
	if len(idx.digests) != len(expected) {
		t.Fatalf("appended %d chunks, want %d", len(idx.digests), len(expected))
	}
	for i, want := range expected {
		if idx.digests[i] != want.digest || idx.offsets[i] != want.offset {
			t.Fatalf("append order broken at %d: (%s,%d) want (%s,%d)",
				i, idx.digests[i][:12], idx.offsets[i], want.digest[:12], want.offset)
		}
	}
	// Deduplicated chunks are uploaded exactly once.
	uniq := make(map[string]bool)
	for _, e := range expected {
		uniq[e.digest] = true
	}
	if len(m.chunks) != len(uniq) {
		t.Errorf("server stores %d chunks, want %d unique", len(m.chunks), len(uniq))
	}
}

// A second backup of identical content must upload nothing: every chunk is
// known from the previous snapshot's index.
func TestUploadPipelinePreviousDedup(t *testing.T) {
	m := newMockPBS(t)
	data := pipelineData(t)
	const avg = 64 << 10
	expected, _ := expectedChunks(t, data, avg)

	var digests [][32]byte
	for _, e := range expected {
		raw, err := hex.DecodeString(e.digest)
		if err != nil {
			t.Fatal(err)
		}
		var d [32]byte
		copy(d[:], raw)
		digests = append(digests, d)
	}
	m.mu.Lock()
	m.previous["root.pxar.didx"] = makeDidx(digests...)
	m.mu.Unlock()

	c := clientFor(t, m, func(cfg *pbs.Config) { cfg.Workers = 4; cfg.ChunkSizeAvg = avg })
	s := start(t, c)
	defer s.Abort()

	stats, err := s.UploadPXARv1(context.Background(), "root.pxar.didx", bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if stats.NewChunks != 0 || stats.ReusedChunks != stats.ChunkCount {
		t.Errorf("stats %+v: everything should deduplicate", stats)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.chunks) != 0 {
		t.Errorf("%d chunks uploaded despite full dedup", len(m.chunks))
	}
}

func TestUploadPipelineChunkFailure(t *testing.T) {
	m := newMockPBS(t)
	m.mu.Lock()
	m.failPath["/dynamic_chunk"] = 500
	m.mu.Unlock()

	s := start(t, clientFor(t, m, nil))
	defer s.Abort()

	data := make([]byte, 2<<20)
	rand.New(rand.NewSource(3)).Read(data)
	_, err := s.UploadPXARv1(context.Background(), "root.pxar", bytes.NewReader(data))
	if err == nil || !strings.Contains(err.Error(), "mock failure") {
		t.Fatalf("err = %v, want propagated chunk failure", err)
	}
}

func TestUploadCatalogIndexName(t *testing.T) {
	m := newMockPBS(t)
	s := start(t, clientFor(t, m, nil))
	defer s.Abort()

	if _, err := s.UploadCatalog(context.Background(), strings.NewReader("tiny catalog bytes")); err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, idx := range m.indexes {
		if idx.name == "catalog.pcat1.didx" && idx.closed {
			return
		}
	}
	t.Fatal("catalog.pcat1.didx index not created and closed")
}

// Progress callbacks arrive in stream order with monotonic sizes and a final
// done report matching the returned stats.
func TestUploadProgress(t *testing.T) {
	m := newMockPBS(t)
	data := pipelineData(t)
	const avg = 64 << 10

	type report struct {
		name  string
		stats pbs.UploadStats
		done  bool
	}
	var reports []report
	c := clientFor(t, m, func(cfg *pbs.Config) {
		cfg.Workers = 8
		cfg.ChunkSizeAvg = avg
		cfg.OnUploadProgress = func(name string, stats pbs.UploadStats, done bool) {
			reports = append(reports, report{name, stats, done})
		}
	})
	s := start(t, c)
	defer s.Abort()

	stats, err := s.UploadPXARv1(context.Background(), "root.pxar", bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}

	if len(reports) < 2 {
		t.Fatalf("only %d progress reports", len(reports))
	}
	var prev uint64
	for i, r := range reports {
		if r.name != "root.pxar.didx" {
			t.Fatalf("report %d for %q", i, r.name)
		}
		if r.stats.Size < prev {
			t.Fatalf("report %d: size %d < previous %d (not monotonic)", i, r.stats.Size, prev)
		}
		prev = r.stats.Size
		if r.done != (i == len(reports)-1) {
			t.Fatalf("report %d: done=%v", i, r.done)
		}
	}
	if final := reports[len(reports)-1].stats; final != stats {
		t.Fatalf("final report %+v != returned stats %+v", final, stats)
	}
	if reports[len(reports)-1].stats.Size != uint64(len(data)) {
		t.Fatalf("final size %d, want %d", prev, len(data))
	}
}
