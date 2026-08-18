package pxar

import "math/bits"

// permuteBST rearranges a hash-sorted slice of goodbye items into the casync
// implicit binary search tree layout: for the item at index i, the item at
// 2i+1 hashes lower and the item at 2i+2 hashes higher, so lookups bisect
// with strictly increasing indexes. Permutation formula by L. Bressel, 2017;
// this is a port of proxmox/pxar src/binary_tree_array.rs (via
// go-pxar/pxar/bintree.go, verified against the upstream test vectors).
func permuteBST(sorted []GoodbyeItem) []GoodbyeItem {
	tree := make([]GoodbyeItem, len(sorted))
	n := uint64(len(sorted))
	insertBST(sorted, tree, n, uint64(bits.Len64(n)), 0)
	return tree
}

func insertBST(sorted, tree []GoodbyeItem, n, e, i uint64) {
	if n == 0 {
		return
	}

	// p: size of the last tree level if it were full; k: index of the root
	// within the sorted slice for a full tree; c: number of elements needed
	// to fill the left subtree's last level.
	p := uint64(1) << (e - 1)
	k := (uint64(1)<<e)/2 - 1
	c := (3*p)/2 - 1

	if n < c {
		k += n - c // unsigned wrap-around yields the correct smaller k
	}

	tree[i] = sorted[k]

	insertBST(sorted, tree, k, e-1, 2*i+1)
	insertBST(sorted[k+1:], tree, n-k-1, e-1, 2*i+2)
}
