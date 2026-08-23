package catalog_test

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/scheiblingco/gopbs/catalog"
)

// Hand-computed golden catalog: archive "a" containing dir "d" (with file
// "g", size 300, mtime -1) and file "f" (size 5, mtime 100).
func TestWriterGolden(t *testing.T) {
	var buf bytes.Buffer
	w, err := catalog.NewWriter(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.StartDirectory("a"); err != nil {
		t.Fatal(err)
	}
	if err := w.StartDirectory("d"); err != nil {
		t.Fatal(err)
	}
	if err := w.AddFile("g", 300, -1); err != nil {
		t.Fatal(err)
	}
	if err := w.EndDirectory(); err != nil {
		t.Fatal(err)
	}
	if err := w.AddFile("f", 5, 100); err != nil {
		t.Fatal(err)
	}
	if err := w.EndDirectory(); err != nil {
		t.Fatal(err)
	}
	if err := w.Finish(); err != nil {
		t.Fatal(err)
	}

	want := bytes.Join([][]byte{
		catalog.Magic,
		// table of "d" at pos 8: len 8; 1 entry: f "g" size=300 mtime=-1
		{0x08, 0x01, 'f', 0x01, 'g', 0xac, 0x02, 0x81, 0x00},
		// table of "a" at pos 17: len 10; d "d" delta 9 (17-8); f "f" 5, 100
		{0x0a, 0x02, 'd', 0x01, 'd', 0x09, 'f', 0x01, 'f', 0x05, 0x64},
		// root table at pos 28: len 5; d "a" delta 11 (28-17)
		{0x05, 0x01, 'd', 0x01, 'a', 0x0b},
		// trailer: LE u64 root table position
		binary.LittleEndian.AppendUint64(nil, 28),
	}, nil)

	if !bytes.Equal(buf.Bytes(), want) {
		t.Fatalf("catalog bytes:\n got  %x\n want %x", buf.Bytes(), want)
	}

	// And it must decode back to the same structure.
	root, err := catalog.Decode(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	a := root.Child("a")
	if a == nil || a.Type != catalog.TypeDirectory || len(a.Children) != 2 {
		t.Fatalf("archive entry: %+v", a)
	}
	if g := a.Child("d").Child("g"); g == nil || g.Size != 300 || g.MtimeSecs != -1 {
		t.Errorf("g: %+v", g)
	}
	if f := a.Child("f"); f == nil || f.Size != 5 || f.MtimeSecs != 100 {
		t.Errorf("f: %+v", f)
	}
}

// Roundtrip with every entry type, many siblings (tables far beyond 128
// bytes, forcing multi-byte deltas — the encoding the go-pxar reference got
// wrong), deep nesting, and extreme sizes/mtimes.
func TestWriterReaderRoundtrip(t *testing.T) {
	var buf bytes.Buffer
	w, err := catalog.NewWriter(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.StartDirectory("backup.pxar.didx"); err != nil {
		t.Fatal(err)
	}

	// Wide directory: 40 files with long names -> table well over 128 bytes.
	if err := w.StartDirectory("wide"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 40; i++ {
		name := fmt.Sprintf("file_with_a_rather_long_name_%02d.bin", i)
		if err := w.AddFile(name, uint64(i)*1_000_000_007, int64(1_700_000_000+i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.EndDirectory(); err != nil {
		t.Fatal(err)
	}

	// Several siblings after it, so their parent deltas differ.
	for _, d := range []string{"sib1", "sib2", "sib3"} {
		if err := w.StartDirectory(d); err != nil {
			t.Fatal(err)
		}
		if err := w.AddFile("x", 1, 1); err != nil {
			t.Fatal(err)
		}
		if err := w.EndDirectory(); err != nil {
			t.Fatal(err)
		}
	}

	// Deep nesting.
	for i := 0; i < 10; i++ {
		if err := w.StartDirectory(fmt.Sprintf("lvl%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.AddFile("deep.bin", 1<<40, -1234567890); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		if err := w.EndDirectory(); err != nil {
			t.Fatal(err)
		}
	}

	// All name-only entry types.
	if err := w.AddSymlink("s.link"); err != nil {
		t.Fatal(err)
	}
	if err := w.AddHardlink("h.link"); err != nil {
		t.Fatal(err)
	}
	if err := w.AddBlockDevice("blk"); err != nil {
		t.Fatal(err)
	}
	if err := w.AddCharDevice("chr"); err != nil {
		t.Fatal(err)
	}
	if err := w.AddFifo("fifo"); err != nil {
		t.Fatal(err)
	}
	if err := w.AddSocket("sock"); err != nil {
		t.Fatal(err)
	}

	if err := w.EndDirectory(); err != nil {
		t.Fatal(err)
	}
	if err := w.Finish(); err != nil {
		t.Fatal(err)
	}

	root, err := catalog.Decode(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	top := root.Child("backup.pxar.didx")
	if top == nil {
		t.Fatal("archive entry missing")
	}

	wide := top.Child("wide")
	if wide == nil || len(wide.Children) != 40 {
		t.Fatalf("wide: %+v", wide)
	}
	f7 := wide.Child("file_with_a_rather_long_name_07.bin")
	if f7 == nil || f7.Size != 7*1_000_000_007 || f7.MtimeSecs != 1_700_000_007 {
		t.Errorf("f7: %+v", f7)
	}

	for _, d := range []string{"sib1", "sib2", "sib3"} {
		if s := top.Child(d); s == nil || s.Child("x") == nil {
			t.Errorf("sibling %s: %+v", d, s)
		}
	}

	cur := top
	for i := 0; i < 10; i++ {
		cur = cur.Child(fmt.Sprintf("lvl%d", i))
		if cur == nil {
			t.Fatalf("lvl%d missing", i)
		}
	}
	if deep := cur.Child("deep.bin"); deep == nil || deep.Size != 1<<40 || deep.MtimeSecs != -1234567890 {
		t.Errorf("deep: %+v", deep)
	}

	for name, typ := range map[string]byte{
		"s.link": catalog.TypeSymlink, "h.link": catalog.TypeHardlink,
		"blk": catalog.TypeBlockDevice, "chr": catalog.TypeCharDevice,
		"fifo": catalog.TypeFifo, "sock": catalog.TypeSocket,
	} {
		if e := top.Child(name); e == nil || e.Type != typ {
			t.Errorf("%s: %+v", name, e)
		}
	}
}

func TestWriterErrors(t *testing.T) {
	w, err := catalog.NewWriter(&bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.AddFile("f", 1, 1); err == nil {
		t.Error("entries at the root must be rejected")
	}
	if err := w.EndDirectory(); err == nil {
		t.Error("EndDirectory at root must fail")
	}
	if err := w.StartDirectory("bad/name"); err == nil {
		t.Error("invalid names must be rejected")
	}
	if err := w.StartDirectory("open"); err != nil {
		t.Fatal(err)
	}
	if err := w.Finish(); err == nil {
		t.Error("Finish with open directories must fail")
	}
}

func TestDecodeErrors(t *testing.T) {
	if _, err := catalog.Decode([]byte("short")); err == nil {
		t.Error("truncated input must fail")
	}
	bad := append(append([]byte{}, catalog.Magic...), binary.LittleEndian.AppendUint64(nil, 999)...)
	if _, err := catalog.Decode(bad); err == nil {
		t.Error("out-of-range root pointer must fail")
	}

	// A directory entry whose child-table delta is 0 aliases its own table;
	// the decoder must reject the cycle instead of recursing forever
	// (found by FuzzDecode; the crasher is in testdata/fuzz/FuzzDecode).
	table := []byte{
		'd', // entry type: directory
		1,   // name length
		'x', // name
		0,   // child table delta 0 -> points at this very table
	}
	body := append([]byte{byte(len(table) + 1), 1}, table...) // table len, count 1
	cyclic := append([]byte{}, catalog.Magic...)
	pos := uint64(len(cyclic))
	cyclic = append(cyclic, body...)
	cyclic = append(cyclic, binary.LittleEndian.AppendUint64(nil, pos)...)
	if _, err := catalog.Decode(cyclic); err == nil {
		t.Error("self-referencing directory table must fail")
	}
}
