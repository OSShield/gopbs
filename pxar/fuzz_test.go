package pxar_test

import (
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
