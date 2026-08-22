// Command genvectors emits chunk-boundary test vectors for gopbs's chunker
// package, computed with the pbscommon reference implementation (tizbac's
// direct port of pbs-datastore's chunker.rs). Regenerate with:
//
//	go run ./genvectors ../../chunker/testdata/vectors.json
//
// (The reference Chunker prints debug lines to stdout, hence the file arg.)
package main

import (
	"encoding/json"
	"os"

	"local.ly/gopbs/pbscommon"
)

type vector struct {
	Seed       uint64   `json:"seed"`
	Size       int      `json:"size"`
	Avg        uint64   `json:"avg"`
	Boundaries []uint64 `json:"boundaries"`
}

// xorshift64: deterministic filler implemented identically in the consuming
// test, so the data never depends on any library's PRNG stability.
func fill(seed uint64, buf []byte) {
	s := seed
	for i := range buf {
		s ^= s << 13
		s ^= s >> 7
		s ^= s << 17
		buf[i] = byte(s)
	}
}

func boundaries(data []byte, avg uint64) []uint64 {
	c := pbscommon.Chunker{}
	c.New(avg)
	out := []uint64{}
	abs := uint64(0)
	for {
		p := c.Scan(data[abs:])
		if p == 0 {
			return out
		}
		abs += p
		out = append(out, abs)
	}
}

func main() {
	cases := []struct {
		seed uint64
		size int
		avg  uint64
	}{
		{1, 10 << 20, 4 << 20},
		{2, 4 << 20, 64 << 10},
		{3, 100_000, 64 << 10},
		{4, 63, 64 << 10},
		{5, 20 << 20, 1 << 20},
	}
	var vs []vector
	for _, tc := range cases {
		data := make([]byte, tc.size)
		fill(tc.seed, data)
		vs = append(vs, vector{tc.seed, tc.size, tc.avg, boundaries(data, tc.avg)})
	}
	out, err := os.Create(os.Args[1])
	if err != nil {
		panic(err)
	}
	defer out.Close()
	enc := json.NewEncoder(out)
	enc.SetIndent("", " ")
	if err := enc.Encode(vs); err != nil {
		panic(err)
	}
}
