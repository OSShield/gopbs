package pxar_test

import (
	"bytes"
	"io"
	"io/fs"
	"strings"
	"testing"

	"github.com/osshield/gopbs/pxar"
)

// FuzzValidateFilename checks that filename validation never panics and that
// its verdict matches the invariants an archive depends on: accepted names
// are non-empty, free of '/' and NUL, and not "." or "..".
func FuzzValidateFilename(f *testing.F) {
	for _, s := range []string{"", ".", "..", "a", "with space", "a/b", "nul\x00byte", "üñïçödé"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, name string) {
		err := pxar.ValidateFilename(name)
		bad := name == "" || name == "." || name == ".." ||
			strings.ContainsAny(name, "/\x00")
		if bad && err == nil {
			t.Fatalf("accepted invalid name %q", name)
		}
		if !bad && err != nil {
			t.Fatalf("rejected valid name %q: %v", name, err)
		}
	})
}

// FuzzPermuteBST checks the goodbye-table BST permutation on arbitrary sizes
// and hash seeds: the result must be a permutation of the input satisfying
// the casync implicit-BST invariant (an in-order walk of the array-encoded
// tree yields the items in their original sorted order).
func FuzzPermuteBST(f *testing.F) {
	f.Add(uint16(0), uint64(1))
	f.Add(uint16(17), uint64(42))
	f.Add(uint16(1000), uint64(0))

	f.Fuzz(func(t *testing.T, n uint16, seed uint64) {
		if n > 4096 {
			n = n % 4096
		}
		sorted := make([]pxar.GoodbyeItem, n)
		for i := range sorted {
			// Distinct, ordered hashes; offsets/lengths tag the original index.
			sorted[i] = pxar.GoodbyeItem{Hash: seed + uint64(i), Start: uint64(i), Length: 1}
		}

		tree := pxar.PermuteBST(append([]pxar.GoodbyeItem(nil), sorted...))
		if len(tree) != len(sorted) {
			t.Fatalf("permutation changed length: %d -> %d", len(sorted), len(tree))
		}

		// In-order traversal of the implicit tree must recover sorted order.
		var walk func(i int, visit func(pxar.GoodbyeItem))
		walk = func(i int, visit func(pxar.GoodbyeItem)) {
			if i >= len(tree) {
				return
			}
			walk(2*i+1, visit)
			visit(tree[i])
			walk(2*i+2, visit)
		}
		pos := 0
		walk(0, func(it pxar.GoodbyeItem) {
			if it != sorted[pos] {
				t.Fatalf("in-order position %d: got start %d, want %d", pos, it.Start, sorted[pos].Start)
			}
			pos++
		})
		if pos != len(sorted) {
			t.Fatalf("in-order walk visited %d of %d items", pos, len(sorted))
		}
	})
}

// FuzzReader feeds arbitrary metadata and payload streams to both readers:
// decoding must never panic, and must end in an error or io.EOF.
func FuzzReader(f *testing.F) {
	meta, payload := v2Archive("hello")
	f.Add(meta, payload)
	f.Add(dirRecords(0o755,
		child("f", regular("content")),
		child("h", pxar.AppendHardlink(nil, 1, "f")),
		child("d", dirRecords(0o700, child("l", pxar.AppendEntry(nil, pxar.Entry{Mode: 0o120777}), pxar.AppendSymlink(nil, "x")))),
	), []byte(nil))

	f.Fuzz(func(t *testing.T, meta, payload []byte) {
		for _, r := range []*pxar.Reader{
			pxar.NewReaderV1(bytes.NewReader(meta)),
			pxar.NewReaderV2(bytes.NewReader(meta), bytes.NewReader(payload)),
		} {
			for {
				if _, err := r.Next(); err != nil {
					break
				}
				if _, err := io.Copy(io.Discard, r); err != nil {
					break
				}
			}
		}
	})
}

// FuzzFS opens arbitrary bytes as a v1 archive and walks it: lookups must
// terminate without panicking, whatever the goodbye tables claim.
func FuzzFS(f *testing.F) {
	f.Add(encDir(nil, []kid{
		{name: "a", recs: regular("A")},
		{name: "h", recs: pxar.AppendHardlink(nil, 1, "a")},
		{name: "l", recs: symlink("d/x")},
		{name: "d", dir: []kid{{name: "x", recs: regular("X")}}},
	}))
	f.Fuzz(func(t *testing.T, data []byte) {
		fsys, err := pxar.OpenV1(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			return
		}
		fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
			if err == nil && d.Type().IsRegular() {
				fs.ReadFile(fsys, path)
			}
			fsys.Stat(path)
			return nil
		})
	})
}
