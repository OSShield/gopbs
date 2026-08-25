package pxar_test

import (
	"sort"
	"testing"

	"github.com/osshield/gopbs/pxar"
)

// Upstream permutation vectors from proxmox/pxar src/binary_tree_array.rs
// (test at commit aad6fb70, line 196).
func TestPermuteBSTUpstreamVectors(t *testing.T) {
	cases := map[int][]int{
		0:  {},
		1:  {0},
		2:  {1, 0},
		3:  {1, 0, 2},
		4:  {2, 1, 3, 0},
		5:  {3, 1, 4, 0, 2},
		6:  {3, 1, 5, 0, 2, 4},
		7:  {3, 1, 5, 0, 2, 4, 6},
		8:  {4, 2, 6, 1, 3, 5, 7, 0},
		9:  {5, 3, 7, 1, 4, 6, 8, 0, 2},
		10: {6, 3, 8, 1, 5, 7, 9, 0, 2, 4},
		11: {7, 3, 9, 1, 5, 8, 10, 0, 2, 4, 6},
		12: {7, 3, 10, 1, 5, 9, 11, 0, 2, 4, 6, 8},
		13: {7, 3, 11, 1, 5, 9, 12, 0, 2, 4, 6, 8, 10},
		14: {7, 3, 11, 1, 5, 9, 13, 0, 2, 4, 6, 8, 10, 12},
		15: {7, 3, 11, 1, 5, 9, 13, 0, 2, 4, 6, 8, 10, 12, 14},
		16: {8, 4, 12, 2, 6, 10, 14, 1, 3, 5, 7, 9, 11, 13, 15, 0},
		17: {9, 5, 13, 3, 7, 11, 15, 1, 4, 6, 8, 10, 12, 14, 16, 0, 2},
	}

	for n, want := range cases {
		sorted := make([]pxar.GoodbyeItem, n)
		for i := range sorted {
			sorted[i] = pxar.GoodbyeItem{Hash: uint64(i)}
		}
		tree := pxar.PermuteBST(sorted)
		for i, v := range want {
			if int(tree[i].Hash) != v {
				t.Errorf("n=%d: tree[%d].Hash = %d, want %d", n, i, tree[i].Hash, v)
				break
			}
		}
	}
}

// The BST invariant must hold for arbitrary sizes: an in-order traversal of
// the implicit tree (2i+1 left, 2i+2 right) visits hashes in sorted order,
// and every input element appears exactly once.
func TestPermuteBSTInvariant(t *testing.T) {
	for n := 0; n <= 128; n++ {
		sorted := make([]pxar.GoodbyeItem, n)
		for i := range sorted {
			sorted[i] = pxar.GoodbyeItem{Hash: uint64(i * 7)} // arbitrary distinct values
		}
		tree := pxar.PermuteBST(sorted)

		var visited []uint64
		var walk func(i int)
		walk = func(i int) {
			if i >= len(tree) {
				return
			}
			walk(2*i + 1)
			visited = append(visited, tree[i].Hash)
			walk(2*i + 2)
		}
		walk(0)

		if len(visited) != n {
			t.Fatalf("n=%d: in-order traversal visited %d items", n, len(visited))
		}
		if !sort.SliceIsSorted(visited, func(a, b int) bool { return visited[a] < visited[b] }) {
			t.Fatalf("n=%d: in-order traversal not sorted: %v", n, visited)
		}
		seen := make(map[uint64]bool, n)
		for _, h := range visited {
			if seen[h] {
				t.Fatalf("n=%d: duplicate hash %d in tree", n, h)
			}
			seen[h] = true
		}
	}
}
