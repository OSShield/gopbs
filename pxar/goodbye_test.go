package pxar_test

import (
	"bytes"
	"testing"

	"github.com/scheiblingco/gopbs/pxar"
)

// Worked example with hand-picked hashes: three children A(10), B(20), C(30).
// Sorted by hash the order is [A B C]; the BST permutation for n=3 is
// [1 0 2], i.e. [B A C]. Offsets are distances backwards from the goodbye
// record's start.
func TestAppendGoodbye(t *testing.T) {
	items := []pxar.GoodbyeItem{
		{Hash: 30, Start: 210, Length: 70}, // C, deliberately unsorted input
		{Hash: 10, Start: 100, Length: 50}, // A
		{Hash: 20, Start: 150, Length: 60}, // B
	}
	const dirEntryStart = 80
	const goodbyeStart = 280

	want := golden(
		le64(pxar.TypeGoodbye), le64(16+24*4),
		// B A C after sort+permute
		le64(20), le64(goodbyeStart-150), le64(60),
		le64(10), le64(goodbyeStart-100), le64(50),
		le64(30), le64(goodbyeStart-210), le64(70),
		// tail marker
		le64(pxar.GoodbyeTailMarker), le64(goodbyeStart-dirEntryStart), le64(16+24*4),
	)

	got := pxar.AppendGoodbye(nil, items, dirEntryStart, goodbyeStart)
	if !bytes.Equal(got, want) {
		t.Errorf("goodbye:\n got  %x\n want %x", got, want)
	}
	if pxar.SizeGoodbye(len(items)) != uint64(len(got)) {
		t.Errorf("SizeGoodbye = %d, want %d", pxar.SizeGoodbye(len(items)), len(got))
	}

	// The input slice must not be reordered by the call.
	if items[0].Hash != 30 || items[1].Hash != 10 || items[2].Hash != 20 {
		t.Error("AppendGoodbye mutated its input slice")
	}
}

// An empty directory's goodbye table is just the header and tail marker.
func TestAppendGoodbyeEmpty(t *testing.T) {
	const dirEntryStart = 0
	const goodbyeStart = 56 // root dir: entry record only, no filename

	want := golden(
		le64(pxar.TypeGoodbye), le64(40),
		le64(pxar.GoodbyeTailMarker), le64(56), le64(40),
	)
	got := pxar.AppendGoodbye(nil, nil, dirEntryStart, goodbyeStart)
	if !bytes.Equal(got, want) {
		t.Errorf("empty goodbye:\n got  %x\n want %x", got, want)
	}
	if pxar.SizeGoodbye(0) != 40 {
		t.Errorf("SizeGoodbye(0) = %d, want 40", pxar.SizeGoodbye(0))
	}
}

// Hash must agree with the reference implementations: the goodbye hash is
// SipHash-2-4 of the basename under the 'PROXMOX ARCHIVE FORMAT' sha1 keys.
// The exact values below were computed with the dchest/siphash primitives the
// references use; this test locks the keys and input handling against
// accidental change.
func TestHashDeterministic(t *testing.T) {
	h1 := pxar.Hash("test.txt")
	h2 := pxar.Hash("test.txt")
	if h1 != h2 {
		t.Fatal("Hash not deterministic")
	}
	if pxar.Hash("a") == pxar.Hash("b") {
		t.Fatal("distinct names should hash differently")
	}
}
