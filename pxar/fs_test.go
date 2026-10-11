package pxar_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/osshield/gopbs/pxar"
)

// kid is a directory child for encDir: either a subdirectory or the
// records following its filename. hash overrides the goodbye hash.
type kid struct {
	name string
	recs []byte
	dir  []kid
	hash uint64
}

// encDir appends a v1 directory with real goodbye tables at the end of b.
func encDir(b []byte, kids []kid) []byte {
	entryStart := len(b)
	b = pxar.AppendEntry(b, pxar.Entry{Mode: modeDir | 0o755, MtimeSecs: 1})
	var items []pxar.GoodbyeItem
	for _, k := range kids {
		start := len(b)
		b = pxar.AppendFilename(b, k.name)
		if k.dir != nil {
			b = encDir(b, k.dir)
		} else {
			b = append(b, k.recs...)
		}
		h := pxar.Hash(k.name)
		if k.hash != 0 {
			h = k.hash
		}
		items = append(items, pxar.GoodbyeItem{Hash: h, Start: uint64(start), Length: uint64(len(b) - start)})
	}
	return pxar.AppendGoodbye(b, items, uint64(entryStart), uint64(len(b)))
}

func symlink(target string) []byte {
	return pxar.AppendSymlink(pxar.AppendEntry(nil, pxar.Entry{Mode: 0o120777}), target)
}

func openV1(t *testing.T, kids []kid) *pxar.FS {
	t.Helper()
	b := encDir(nil, kids)
	fsys, err := pxar.OpenV1(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatal(err)
	}
	return fsys
}

func TestFS(t *testing.T) {
	fsys := openV1(t, []kid{
		{name: "a.txt", recs: regular("alpha")},
		{name: "hl", recs: pxar.AppendHardlink(nil, 1, "sub/inner")},
		{name: "rel", recs: symlink("sub/inner")},
		{name: "sd", recs: symlink("sub")},
		{name: "sub", dir: []kid{
			{name: "back", recs: symlink("../a.txt")},
			{name: "inner", recs: regular("inner content")},
		}},
	})
	if err := fstest.TestFS(fsys, "a.txt", "hl", "sub/inner", "sub"); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{
		"a.txt": "alpha", "hl": "inner content", "rel": "inner content",
		"sd/inner": "inner content", "sub/back": "alpha", "sd/back": "alpha",
	} {
		got, err := fs.ReadFile(fsys, name)
		if err != nil || string(got) != want {
			t.Errorf("%s: %q %v, want %q", name, got, err, want)
		}
	}
	for _, name := range []string{"missing", "sub/missing", "a.txt/x"} {
		if _, err := fsys.Stat(name); err == nil {
			t.Errorf("%s: resolved, want an error", name)
		}
	}
	fi, err := fsys.Stat("hl")
	if err != nil || fi.Name() != "hl" || fi.Size() != 13 || fi.Sys().(*pxar.Node).Path != "sub/inner" {
		t.Errorf("stat hardlink: %v %v", fi, err)
	}
}

// Names sharing a goodbye hash are told apart by their filename record.
func TestFSHashCollision(t *testing.T) {
	h := pxar.Hash("b")
	fsys := openV1(t, []kid{{name: "a", recs: regular("A"), hash: h}, {name: "b", recs: regular("B"), hash: h}})
	if got, err := fs.ReadFile(fsys, "b"); err != nil || string(got) != "B" {
		t.Fatalf("b: %q %v", got, err)
	}
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil || len(entries) != 2 || entries[0].Name() != "a" {
		t.Fatalf("readdir: %v %v", entries, err)
	}
}

func TestFSRejects(t *testing.T) {
	loops := openV1(t, []kid{
		{name: "abs", recs: symlink("/etc/passwd")},
		{name: "dirlink", recs: pxar.AppendHardlink(nil, 1, "d")},
		{name: "d", dir: []kid{}},
		{name: "l1", recs: symlink("l2")},
		{name: "l2", recs: symlink("l1")},
		{name: "self", recs: pxar.AppendHardlink(nil, 1, "self")},
		{name: "sub", dir: []kid{{name: "up", recs: symlink("../../outside")}}},
	})
	// Symlinks out of the archive do not resolve, but stay readable.
	for _, name := range []string{"abs", "sub/up", "l1", "self", "dirlink"} {
		if _, err := loops.Stat(name); err == nil {
			t.Errorf("%s: resolved, want an error", name)
		}
	}
	if fi, err := loops.Lstat("abs"); err != nil || fi.Mode().Type() != fs.ModeSymlink {
		t.Errorf("lstat abs: %v %v", fi, err)
	}
	if target, err := loops.ReadLink("sub/up"); err != nil || target != "../../outside" {
		t.Errorf("readlink: %q %v", target, err)
	}
	if _, err := fs.ReadDir(loops, "."); err == nil {
		t.Error("readdir with a hardlink to a directory succeeded")
	}

	// A goodbye item pointing outside the directory.
	b := encDir(nil, []kid{{name: "f", recs: regular("x")}})
	item := len(b) - 2*24
	binary.LittleEndian.PutUint64(b[item+8:], uint64(len(b))*2)
	fsys, err := pxar.OpenV1(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fsys.Stat("f"); err == nil || !strings.Contains(err.Error(), "out of range") {
		t.Errorf("corrupt goodbye: %v", err)
	}
}

func TestFSV2(t *testing.T) {
	meta, payload := v2Archive("split content")
	// v2Archive writes an empty goodbye table; give the root a real one.
	gbStart := bytes.LastIndex(meta, binary.LittleEndian.AppendUint64(nil, pxar.TypeGoodbye))
	fileStart := bytes.Index(meta, binary.LittleEndian.AppendUint64(nil, pxar.TypeFilename))
	meta = pxar.AppendGoodbye(meta[:gbStart:gbStart],
		[]pxar.GoodbyeItem{{Hash: pxar.Hash("f"), Start: uint64(fileStart), Length: uint64(gbStart - fileStart)}},
		0, uint64(gbStart))

	fsys, err := pxar.OpenV2(bytes.NewReader(meta), int64(len(meta)), bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := fs.ReadFile(fsys, "f"); err != nil || string(got) != "split content" {
		t.Fatalf("read: %q %v", got, err)
	}

	// Metadata only: listing works, content does not.
	fsys, err = pxar.OpenV2(bytes.NewReader(meta), int64(len(meta)), nil)
	if err != nil {
		t.Fatal(err)
	}
	if fi, err := fsys.Stat("f"); err != nil || fi.Size() != 13 {
		t.Fatalf("stat: %v %v", fi, err)
	}
	if _, err := fsys.Open("f"); err == nil {
		t.Fatal("opened content without a payload stream")
	}

	// A payload stream cut short is an error, not a short file.
	fsys, err = pxar.OpenV2(bytes.NewReader(meta), int64(len(meta)), bytes.NewReader(payload[:len(payload)-pxar.MarkerSize-3]))
	if err != nil {
		t.Fatal(err)
	}
	f, err := fsys.Open("f")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(f); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("truncated payload: %v", err)
	}
}
