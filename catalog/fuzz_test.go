package catalog_test

import (
	"bytes"
	"testing"

	"github.com/osshield/gopbs/catalog"
)

// FuzzDecode feeds arbitrary bytes to the catalog decoder: it must reject or
// accept without panicking, and an accepted catalog must decode identically
// twice.
func FuzzDecode(f *testing.F) {
	// Seed with a real catalog so the fuzzer starts from valid structure.
	var buf bytes.Buffer
	w, err := catalog.NewWriter(&buf)
	if err != nil {
		f.Fatal(err)
	}
	must := func(err error) {
		if err != nil {
			f.Fatal(err)
		}
	}
	must(w.StartDirectory("root.pxar.didx"))
	must(w.AddFile("readme.txt", 42, 1721000000))
	must(w.StartDirectory("sub"))
	must(w.AddSymlink("link"))
	must(w.AddFile("data.bin", 1<<20, -12345))
	must(w.EndDirectory())
	must(w.EndDirectory())
	must(w.Finish())
	f.Add(buf.Bytes())
	f.Add([]byte{})
	f.Add(catalog.Magic)

	f.Fuzz(func(t *testing.T, data []byte) {
		root, err := catalog.Decode(data)
		if err != nil {
			return
		}
		if root == nil {
			t.Fatal("nil root without error")
		}
		again, err := catalog.Decode(data)
		if err != nil {
			t.Fatalf("second decode failed: %v", err)
		}
		if !equalEntries(root, again) {
			t.Fatal("decode is not deterministic")
		}
	})
}

func equalEntries(a, b *catalog.Entry) bool {
	if a.Name != b.Name || a.Type != b.Type || a.Size != b.Size ||
		a.MtimeSecs != b.MtimeSecs || len(a.Children) != len(b.Children) {
		return false
	}
	for i := range a.Children {
		if !equalEntries(a.Children[i], b.Children[i]) {
			return false
		}
	}
	return true
}

// FuzzVarint round-trips the catalog's two varint encodings — plain uvarint
// and the sign-magnitude i64 variant with its forced-continuation negative
// form — and requires the decoder to survive arbitrary byte suffixes.
func FuzzVarint(f *testing.F) {
	f.Add(uint64(0), int64(0), []byte{})
	f.Add(uint64(1<<63), int64(-1), []byte{0xff, 0xff})
	f.Add(uint64(127), int64(1721000000), []byte{0x80})

	f.Fuzz(func(t *testing.T, u uint64, i int64, junk []byte) {
		enc := catalog.AppendU64(nil, u)
		got, n, err := catalog.DecodeU64(append(enc, junk...))
		if err != nil || n != len(enc) || got != u {
			t.Fatalf("u64 %d: decoded %d consuming %d of %d (err %v)", u, got, n, len(enc), err)
		}

		enc = catalog.AppendI64(nil, i)
		goti, n, err := catalog.DecodeI64(append(enc, junk...))
		if err != nil || n != len(enc) || goti != i {
			t.Fatalf("i64 %d: decoded %d consuming %d of %d (err %v)", i, goti, n, len(enc), err)
		}

		// Arbitrary bytes must never panic the decoders.
		catalog.DecodeU64(junk) //nolint:errcheck
		catalog.DecodeI64(junk) //nolint:errcheck
	})
}
