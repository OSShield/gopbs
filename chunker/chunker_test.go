package chunker_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"math/rand"
	"os"
	"testing"

	"github.com/osshield/gopbs/chunker"
)

// xorshift64: the same filler the vector generator uses
// (tests/tizbac/genvectors), so vectors never depend on a PRNG library.
func fill(seed uint64, buf []byte) {
	s := seed
	for i := range buf {
		s ^= s << 13
		s ^= s >> 7
		s ^= s << 17
		buf[i] = byte(s)
	}
}

type vector struct {
	Seed       uint64   `json:"seed"`
	Size       int      `json:"size"`
	Avg        uint64   `json:"avg"`
	Boundaries []uint64 `json:"boundaries"`
}

func loadVectors(t *testing.T) []vector {
	t.Helper()
	data, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vs []vector
	if err := json.Unmarshal(data, &vs); err != nil {
		t.Fatal(err)
	}
	if len(vs) == 0 {
		t.Fatal("no vectors")
	}
	return vs
}

func scanAll(t *testing.T, c *chunker.Chunker, data []byte) []uint64 {
	t.Helper()
	var out []uint64
	abs := 0
	for {
		p := c.Scan(data[abs:])
		if p == 0 {
			return out
		}
		abs += p
		out = append(out, uint64(abs))
	}
}

// Break positions must match the reference implementation exactly.
func TestVectorConformance(t *testing.T) {
	for _, v := range loadVectors(t) {
		data := make([]byte, v.Size)
		fill(v.Seed, data)
		c, err := chunker.New(v.Avg)
		if err != nil {
			t.Fatal(err)
		}
		got := scanAll(t, c, data)
		if len(got) != len(v.Boundaries) {
			t.Fatalf("seed %d: %d boundaries, want %d", v.Seed, len(got), len(v.Boundaries))
		}
		for i := range got {
			if got[i] != v.Boundaries[i] {
				t.Fatalf("seed %d: boundary %d at %d, want %d", v.Seed, i, got[i], v.Boundaries[i])
			}
		}
	}
}

// Boundaries must not depend on how the stream is segmented across Scan
// calls.
func TestSegmentationInvariance(t *testing.T) {
	data := make([]byte, 6<<20)
	fill(42, data)

	c, err := chunker.New(256 << 10)
	if err != nil {
		t.Fatal(err)
	}
	want := scanAll(t, c, data)
	if len(want) < 4 {
		t.Fatalf("test data yields only %d boundaries", len(want))
	}

	for _, trial := range []int64{1, 2, 3} {
		rng := rand.New(rand.NewSource(trial))
		c, err := chunker.New(256 << 10)
		if err != nil {
			t.Fatal(err)
		}
		var got []uint64
		abs := 0
		for abs < len(data) {
			segEnd := abs + 1 + rng.Intn(200_000)
			if segEnd > len(data) {
				segEnd = len(data)
			}
			seg := data[abs:segEnd]
			for len(seg) > 0 {
				p := c.Scan(seg)
				if p == 0 {
					break
				}
				got = append(got, uint64(abs+p))
				abs += p
				seg = data[abs:segEnd]
			}
			abs = segEnd
			_ = seg
		}
		if len(got) != len(want) {
			t.Fatalf("trial %d: %d boundaries, want %d", trial, len(got), len(want))
		}
		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("trial %d: boundary %d at %d, want %d", trial, i, got[i], want[i])
			}
		}
	}
}

// All chunks except the trailing one must respect the min/max bounds.
func TestChunkBounds(t *testing.T) {
	const avg = 64 << 10
	data := make([]byte, 8<<20)
	fill(7, data)

	var offsets []uint64
	var total int
	for c, err := range chunker.Split(bytes.NewReader(data), avg) {
		if err != nil {
			t.Fatal(err)
		}
		offsets = append(offsets, c.Offset)
		total += len(c.Data)
		if len(c.Data) > avg<<2 {
			t.Fatalf("chunk at %d exceeds max: %d", c.Offset, len(c.Data))
		}
	}
	if total != len(data) {
		t.Fatalf("chunks cover %d bytes of %d", total, len(data))
	}
	for i := 1; i < len(offsets); i++ {
		size := offsets[i] - offsets[i-1]
		if size < avg>>2 {
			t.Fatalf("non-final chunk %d is %d bytes, below min", i-1, size)
		}
	}
}

// Split must reassemble to the input, with contiguous offsets, matching the
// boundaries Scan reports.
func TestSplitReassembly(t *testing.T) {
	data := make([]byte, 3<<20)
	fill(9, data)

	c, err := chunker.New(128 << 10)
	if err != nil {
		t.Fatal(err)
	}
	want := scanAll(t, c, data)

	var rebuilt []byte
	var bounds []uint64
	for ch, err := range chunker.Split(bytes.NewReader(data), 128<<10) {
		if err != nil {
			t.Fatal(err)
		}
		if uint64(len(rebuilt)) != ch.Offset {
			t.Fatalf("offset %d, expected %d", ch.Offset, len(rebuilt))
		}
		rebuilt = append(rebuilt, ch.Data...)
		bounds = append(bounds, ch.Offset+uint64(len(ch.Data)))
	}
	if !bytes.Equal(rebuilt, data) {
		t.Fatal("reassembled data differs")
	}
	// Every Scan boundary plus the final EOF cut.
	if len(bounds) != len(want)+1 {
		t.Fatalf("%d chunks, want %d", len(bounds), len(want)+1)
	}
	for i, w := range want {
		if bounds[i] != w {
			t.Fatalf("chunk end %d at %d, want %d", i, bounds[i], w)
		}
	}
}

func TestSplitEdgeCases(t *testing.T) {
	// Empty input: no chunks.
	for range chunker.Split(bytes.NewReader(nil), 0) {
		t.Fatal("empty input must yield nothing")
	}

	// Input smaller than the hash window: one final chunk.
	small := []byte("tiny")
	var got [][]byte
	for c, err := range chunker.Split(bytes.NewReader(small), 0) {
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, c.Data)
	}
	if len(got) != 1 || !bytes.Equal(got[0], small) {
		t.Fatalf("small input chunks: %q", got)
	}

	// Read errors surface as the final yield.
	boom := errors.New("boom")
	var sawErr error
	for _, err := range chunker.Split(&failReader{}, 0) {
		sawErr = err
	}
	if !errors.Is(sawErr, boom) && sawErr == nil {
		t.Fatalf("err = %v", sawErr)
	}
}

type failReader struct{}

func (failReader) Read([]byte) (int, error) { return 0, errors.New("boom") }

func TestNewValidation(t *testing.T) {
	for _, bad := range []uint64{3, 100, 6 << 20, 128} {
		if _, err := chunker.New(bad); err == nil {
			t.Errorf("New(%d) must fail", bad)
		}
	}
	if _, err := chunker.New(0); err != nil {
		t.Errorf("New(0) must default: %v", err)
	}
}

func BenchmarkScan(b *testing.B) {
	data := make([]byte, 64<<20)
	fill(1, data)
	c, err := chunker.New(0)
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		abs := 0
		for {
			p := c.Scan(data[abs:])
			if p == 0 {
				break
			}
			abs += p
		}
		c.Reset()
	}
}
