package pxar

import (
	"encoding/binary"
	"sort"
)

// GoodbyeItem describes one directory child for goodbye-table construction.
// Start and Length are in stream coordinates: Start is the absolute offset of
// the child's TypeFilename record, Length the child's total encoded length
// (filename record through goodbye table or payload, inclusive).
type GoodbyeItem struct {
	Hash   uint64 // Hash(basename)
	Start  uint64
	Length uint64
}

// SizeGoodbye returns the full encoded size of a goodbye record for a
// directory with n children (n items plus the tail marker).
func SizeGoodbye(n int) uint64 { return HeaderSize + 24*uint64(n+1) }

// AppendGoodbye encodes a directory's goodbye table. dirEntryStart is the
// absolute offset of the directory's own TypeEntry record (i.e. after its
// filename record; for the root directory, the archive start), goodbyeStart
// the absolute offset where this goodbye record begins. Items may be in any
// order; they are sorted by hash and permuted into the BST layout. Item
// offsets are encoded as distances backwards from goodbyeStart.
func AppendGoodbye(dst []byte, items []GoodbyeItem, dirEntryStart, goodbyeStart uint64) []byte {
	length := SizeGoodbye(len(items))
	dst = appendHeader(dst, TypeGoodbye, length)

	sorted := make([]GoodbyeItem, len(items))
	copy(sorted, items)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Hash < sorted[j].Hash })

	for _, item := range permuteBST(sorted) {
		dst = binary.LittleEndian.AppendUint64(dst, item.Hash)
		dst = binary.LittleEndian.AppendUint64(dst, goodbyeStart-item.Start)
		dst = binary.LittleEndian.AppendUint64(dst, item.Length)
	}

	// Tail marker: points back to the directory's entry record and carries
	// the goodbye record's own length.
	dst = binary.LittleEndian.AppendUint64(dst, GoodbyeTailMarker)
	dst = binary.LittleEndian.AppendUint64(dst, goodbyeStart-dirEntryStart)
	return binary.LittleEndian.AppendUint64(dst, length)
}
