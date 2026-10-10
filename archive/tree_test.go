package archive_test

import (
	"bytes"
	"encoding/binary"
	"io"
	"math/rand"
	"strings"
	"testing"

	"github.com/osshield/gopbs/archive"
	"github.com/osshield/gopbs/pxar"
	"github.com/osshield/gopbs/scan"
)

// lazyReader is what a cloud-backed tree hands gopbs: the content is produced
// on the first Read, and the test counts whether that ever happened
type lazyReader struct {
	data  []byte
	r     *bytes.Reader
	reads int
}

func (l *lazyReader) Read(p []byte) (int, error) {
	if l.r == nil {
		l.reads++
		l.r = bytes.NewReader(l.data)
	}
	return l.r.Read(p)
}

func randomBytes(n int, seed int64) []byte {
	buf := make([]byte, n)
	rand.New(rand.NewSource(seed)).Read(buf)
	return buf
}

const treeStamp = 1_790_000_000 // fixed mtime: unchanged metadata between runs

func leaf(name string, data []byte, mtime int64) (*scan.Node, *lazyReader) {
	lr := &lazyReader{data: data}
	return &scan.Node{
		Name:   name,
		Kind:   scan.KindStream,
		Stat:   scan.Stat{Mode: scan.ModeRegular | 0o644, Size: int64(len(data)), MtimeSecs: mtime, Nlink: 1},
		Stream: lr,
	}, lr
}

func dir(name string, children ...*scan.Node) *scan.Node {
	return &scan.Node{Name: name, Kind: scan.KindDirectory, Stat: scan.Stat{Mode: scan.ModeDir | 0o755, MtimeSecs: treeStamp, Nlink: 1}, Children: children}
}

// mailboxTree models one run of a virtual mailbox: a root file and a folder
// with three items; contents come from the seeds so a changed item is one seed
func mailboxTree(seeds map[string]int64, mtimes map[string]int64) (*scan.Node, map[string]*lazyReader, map[string][]byte) {
	readers := map[string]*lazyReader{}
	contents := map[string][]byte{}
	mk := func(path, name string) *scan.Node {
		data := randomBytes(200<<10, seeds[path])
		mt := int64(treeStamp)
		if m, ok := mtimes[path]; ok {
			mt = m
		}
		n, lr := leaf(name, data, mt)
		readers[path], contents[path] = lr, data
		return n
	}
	// Children deliberately unsorted: AddTree must sort them
	root := dir("mailbox",
		dir("inbox", mk("inbox/c.exoitem", "c.exoitem"), mk("inbox/a.exoitem", "a.exoitem"), mk("inbox/b.exoitem", "b.exoitem")),
		mk("folders.json", "folders.json"),
	)
	return root, readers, contents
}

// decodeTree checks every file record of a v2 archive against the expected
// contents and returns the decoded paths
func decodeTree(t *testing.T, meta, payload []byte, contents map[string][]byte) []string {
	t.Helper()
	var paths []string
	_, err := pxar.DecodeMetadata(bytes.NewReader(meta), func(f pxar.MetaFile) error {
		paths = append(paths, f.Path)
		want, ok := contents[f.Path]
		if !ok {
			t.Fatalf("unexpected file %s in archive", f.Path)
		}
		rec := payload[f.PayloadOffset:]
		if binary.LittleEndian.Uint64(rec[8:]) != pxar.HeaderSize+f.Size || f.Size != uint64(len(want)) {
			t.Fatalf("%s: payload record of %d bytes, want %d", f.Path, f.Size, len(want))
		}
		if !bytes.Equal(rec[pxar.HeaderSize:pxar.HeaderSize+f.Size], want) {
			t.Fatalf("%s: archived content differs", f.Path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return paths
}

func TestAddTreeReusesUnchangedStreams(t *testing.T) {
	seeds := map[string]int64{"inbox/a.exoitem": 1, "inbox/b.exoitem": 2, "inbox/c.exoitem": 3, "folders.json": 4}

	// Run 1: a single tree is the archive root; everything is read once
	root1, readers1, contents1 := mailboxTree(seeds, nil)
	a1, err := archive.New(archive.Options{Workers: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := a1.AddTree(root1); err != nil {
		t.Fatal(err)
	}
	meta1, payload1 := generateV2(t, a1)
	paths := decodeTree(t, meta1, payload1, contents1)
	if strings.Join(paths, " ") != "folders.json inbox/a.exoitem inbox/b.exoitem inbox/c.exoitem" {
		t.Fatalf("archive paths %v: tree is not the root or children are unsorted", paths)
	}
	for p, lr := range readers1 {
		if lr.reads != 1 {
			t.Fatalf("run 1: %s read %d times", p, lr.reads)
		}
	}

	// Run 2: b changed (new content and mtime), the rest is identical metadata
	entries, prevData := payloadChunks(t, payload1)
	prev, err := archive.LoadPrevious(bytes.NewReader(meta1), entries)
	if err != nil {
		t.Fatal(err)
	}
	seeds["inbox/b.exoitem"] = 22
	root2, readers2, contents2 := mailboxTree(seeds, map[string]int64{"inbox/b.exoitem": treeStamp + 60})
	for _, workers := range []int{1, 4} {
		root, readers, contents := root2, readers2, contents2
		if workers != 1 {
			root, readers, contents = mailboxTree(seeds, map[string]int64{"inbox/b.exoitem": treeStamp + 60})
		}
		a2, err := archive.New(archive.Options{Workers: workers, Previous: prev})
		if err != nil {
			t.Fatal(err)
		}
		if err := a2.AddTree(root); err != nil {
			t.Fatal(err)
		}
		meta2, framed := generateV2(t, a2)
		payload2, injected := rebuildPayload(t, framed, prevData)
		decodeTree(t, meta2, payload2, contents)
		stats := a2.ReuseStats()
		if stats.Files != 4 || stats.ReusedFiles != 3 || injected == 0 {
			t.Fatalf("workers=%d: expected 3 of 4 streams reused: %+v (injected %d)", workers, stats, injected)
		}
		for p, lr := range readers {
			want := 0
			if p == "inbox/b.exoitem" {
				want = 1
			}
			if lr.reads != want {
				t.Fatalf("workers=%d: %s read %d times, want %d", workers, p, lr.reads, want)
			}
		}
	}
}

func TestAddTreeUnderVirtualRoot(t *testing.T) {
	root, _, contents := mailboxTree(map[string]int64{"inbox/a.exoitem": 1, "inbox/b.exoitem": 2, "inbox/c.exoitem": 3, "folders.json": 4}, nil)
	a, err := archive.New(archive.Options{Name: "user", Workers: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.AddTree(root); err != nil {
		t.Fatal(err)
	}
	if err := a.AddStream("extra.json", 4, strings.NewReader("tiny")); err != nil {
		t.Fatal(err)
	}
	prefixed := map[string][]byte{"extra.json": []byte("tiny")}
	for p, c := range contents {
		prefixed["mailbox/"+p] = c
	}
	meta, payload := generateV2(t, a)
	paths := decodeTree(t, meta, payload, prefixed)
	if len(paths) != 5 || paths[0] != "extra.json" || paths[1] != "mailbox/folders.json" {
		t.Fatalf("paths %v", paths)
	}
}

func TestAddTreeValidation(t *testing.T) {
	a, err := archive.New(archive.Options{})
	if err != nil {
		t.Fatal(err)
	}
	stream, _ := leaf("x", []byte("x"), treeStamp)
	cases := map[string]*scan.Node{
		"nil":         nil,
		"stream root": stream,
		"duplicate":   dir("r", dir("same"), dir("same")),
		"bad name":    dir("r", dir("a/b")),
		"no reader":   dir("r", &scan.Node{Name: "s", Kind: scan.KindStream, Stat: scan.Stat{Size: 1}}),
		"file kind":   dir("r", &scan.Node{Name: "f", Kind: scan.KindFile, Path: "/etc/hostname"}),
	}
	for name, n := range cases {
		if err := a.AddTree(n); err == nil {
			t.Errorf("%s: AddTree accepted %+v", name, n)
		}
	}
	// A stream node without mode bits is fixed up rather than rejected
	bare := dir("r", &scan.Node{Name: "s", Kind: scan.KindStream, Stat: scan.Stat{Size: 1}, Stream: io.NopCloser(strings.NewReader("x"))})
	if err := a.AddTree(bare); err != nil {
		t.Fatal(err)
	}
	if got := bare.Children[0].Stat; got.Mode != scan.ModeRegular || got.Nlink != 1 {
		t.Fatalf("stat not normalised: %+v", got)
	}
}
