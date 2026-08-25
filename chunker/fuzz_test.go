package chunker_test

import (
	"bytes"
	"testing"

	"github.com/osshield/gopbs/chunker"
)

// FuzzSplit checks the chunker's structural invariants on arbitrary input:
// chunks tile the stream exactly (contiguous offsets, concatenation equals
// the input), every chunk but the last respects the min/max bounds, the last
// respects max, and chunking is deterministic.
func FuzzSplit(f *testing.F) {
	f.Add([]byte("hello world"), uint8(0))
	f.Add(bytes.Repeat([]byte{0}, 100_000), uint8(1))
	f.Add(bytes.Repeat([]byte("abcdefgh"), 50_000), uint8(2))

	split := func(t *testing.T, data []byte, avg uint64) []chunker.Chunk {
		t.Helper()
		var chunks []chunker.Chunk
		for c, err := range chunker.Split(bytes.NewReader(data), avg) {
			if err != nil {
				t.Fatalf("split error on in-memory data: %v", err)
			}
			chunks = append(chunks, c)
		}
		return chunks
	}

	f.Fuzz(func(t *testing.T, data []byte, avgExp uint8) {
		avg := uint64(4096) << (avgExp % 6) // 4 KiB .. 128 KiB
		chunks := split(t, data, avg)

		var rejoined []byte
		var offset uint64
		for i, c := range chunks {
			if c.Offset != offset {
				t.Fatalf("chunk %d: offset %d, want %d (not contiguous)", i, c.Offset, offset)
			}
			if len(c.Data) == 0 {
				t.Fatalf("chunk %d: empty", i)
			}
			size := uint64(len(c.Data))
			if size > avg*4 {
				t.Fatalf("chunk %d: %d bytes above max %d", i, size, avg*4)
			}
			if i < len(chunks)-1 && size < avg/4 {
				t.Fatalf("chunk %d: %d bytes below min %d", i, size, avg/4)
			}
			rejoined = append(rejoined, c.Data...)
			offset += size
		}
		if !bytes.Equal(rejoined, data) {
			t.Fatalf("chunks reassemble to %d bytes, input was %d", len(rejoined), len(data))
		}

		again := split(t, data, avg)
		if len(again) != len(chunks) {
			t.Fatalf("non-deterministic: %d then %d chunks", len(chunks), len(again))
		}
		for i := range again {
			if again[i].Offset != chunks[i].Offset || !bytes.Equal(again[i].Data, chunks[i].Data) {
				t.Fatalf("non-deterministic at chunk %d", i)
			}
		}
	})
}
