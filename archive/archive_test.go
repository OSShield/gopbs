//go:build linux

package archive_test

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/osshield/gopbs/archive"
	"github.com/osshield/gopbs/catalog"
	"github.com/osshield/gopbs/scan"
	"golang.org/x/sys/unix"
)

func generate(t *testing.T, a *archive.Archive) []byte {
	t.Helper()
	rc, err := a.GenerateV1(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	data, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// A single-directory archive: structure, content, metadata, goodbye tables
// (verified inside the parser), hardlink offsets, and the estimate invariant.
func TestGenerateV1SingleRoot(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "sub", "empty"), 0o755); err != nil {
		t.Fatal(err)
	}
	content := []byte("late offset binding works")
	if err := os.WriteFile(filepath.Join(root, "b.txt"), content, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "sub", "data.bin"), bytes.Repeat([]byte{7}, 3000), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../b.txt", filepath.Join(root, "sub", "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(root, "b.txt"), filepath.Join(root, "sub", "z.hard")); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filepath.Join(root, "a.fifo"), 0o600); err != nil {
		t.Fatal(err)
	}

	a, err := archive.New(archive.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.AddDirectory(root); err != nil {
		t.Fatal(err)
	}

	estimate, err := a.EstimatedSizeV1()
	if err != nil {
		t.Fatal(err)
	}
	data := generate(t, a)
	if int64(len(data)) != estimate {
		t.Errorf("emitted %d bytes, estimate was %d", len(data), estimate)
	}

	dec, err := parseArchive(data)
	if err != nil {
		t.Fatal(err)
	}

	file := dec.find("b.txt")
	if file == nil || !bytes.Equal(file.content, content) {
		t.Fatalf("b.txt content mismatch: %+v", file)
	}
	if file.mode&0o7777 != 0o640 {
		t.Errorf("b.txt mode %o", file.mode&0o7777)
	}
	info, _ := os.Lstat(filepath.Join(root, "b.txt"))
	if file.mtimeSecs != info.ModTime().Unix() || file.uid != uint32(os.Getuid()) {
		t.Errorf("b.txt metadata: secs=%d uid=%d", file.mtimeSecs, file.uid)
	}

	if l := dec.find("sub/link"); l == nil || l.symlink != "../b.txt" {
		t.Errorf("symlink: %+v", l)
	}
	if f := dec.find("a.fifo"); f == nil || f.mode&scan.ModeTypeMask != scan.ModeFifo {
		t.Errorf("fifo: %+v", f)
	}
	if e := dec.find("sub/empty"); e == nil || len(e.children) != 0 {
		t.Errorf("empty dir: %+v", e)
	}

	hl := dec.find("sub/z.hard")
	if hl == nil || hl.hardlink.target != "b.txt" {
		t.Fatalf("hardlink: %+v", hl)
	}
	if got := hl.start - hl.hardlink.offset; got != file.start {
		t.Errorf("hardlink offset resolves to %d, target filename record at %d", got, file.start)
	}
}

// Virtual root: multiple directories, a bare file, and a stream, with a
// cross-root hardlink.
func TestGenerateV1VirtualRoot(t *testing.T) {
	base := t.TempDir()
	d1, d2 := filepath.Join(base, "d1"), filepath.Join(base, "d2")
	for _, d := range []string{d1, d2} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(d1, "orig"), []byte("shared"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(d1, "orig"), filepath.Join(d2, "linked")); err != nil {
		t.Fatal(err)
	}
	loose := filepath.Join(base, "loose.txt")
	if err := os.WriteFile(loose, []byte("bare file"), 0o644); err != nil {
		t.Fatal(err)
	}

	a, err := archive.New(archive.Options{Name: "backup"})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.AddDirectories([]string{d1, d2}); err != nil {
		t.Fatal(err)
	}
	if err := a.AddFile(loose); err != nil {
		t.Fatal(err)
	}
	if err := a.AddStream("stream.bin", 5, strings.NewReader("12345")); err != nil {
		t.Fatal(err)
	}

	dec, err := parseArchive(generate(t, a))
	if err != nil {
		t.Fatal(err)
	}

	// Virtual root children in byte order.
	var names []string
	for _, c := range dec.children {
		names = append(names, c.name)
	}
	if strings.Join(names, ",") != "d1,d2,loose.txt,stream.bin" {
		t.Errorf("root children: %v", names)
	}
	if s := dec.find("stream.bin"); s == nil || string(s.content) != "12345" {
		t.Errorf("stream: %+v", s)
	}

	hl := dec.find("d2/linked")
	orig := dec.find("d1/orig")
	if hl == nil || orig == nil || hl.hardlink.target != "d1/orig" {
		t.Fatalf("cross-root hardlink: %+v", hl)
	}
	if got := hl.start - hl.hardlink.offset; got != orig.start {
		t.Errorf("cross-root hardlink offset resolves to %d, target at %d", got, orig.start)
	}
}

// Streams that yield the wrong byte count are padded or truncated to the
// declared size, with warnings.
func TestGenerateV1StreamPadTruncate(t *testing.T) {
	var warns []archive.Warning
	a, err := archive.New(archive.Options{
		Name:   "pad",
		OnWarn: func(w archive.Warning) { warns = append(warns, w) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.AddStream("short.bin", 10, strings.NewReader("1234")); err != nil {
		t.Fatal(err)
	}
	if err := a.AddStream("long.bin", 4, strings.NewReader("123456")); err != nil {
		t.Fatal(err)
	}

	dec, err := parseArchive(generate(t, a))
	if err != nil {
		t.Fatal(err)
	}

	if s := dec.find("short.bin"); !bytes.Equal(s.content, append([]byte("1234"), make([]byte, 6)...)) {
		t.Errorf("short.bin content %q", s.content)
	}
	if l := dec.find("long.bin"); string(l.content) != "1234" {
		t.Errorf("long.bin content %q", l.content)
	}

	if len(warns) != 2 {
		t.Fatalf("warnings: %+v", warns)
	}
	for _, w := range warns {
		if w.Kind != archive.WarnSizeChanged {
			t.Errorf("warning kind %d", w.Kind)
		}
	}
	if warns[0].Bound != 4 || warns[0].Actual != 5 { // long.bin sorts first
		t.Errorf("truncate warning: %+v", warns[0])
	}
	if warns[1].Bound != 10 || warns[1].Actual != 4 {
		t.Errorf("pad warning: %+v", warns[1])
	}
}

// staleSizeReader lies about one file's size at scan time; late binding must
// silently emit the real size (only the estimate drifts).
type staleSizeReader struct {
	scan.MetadataReader
	path  string
	delta int64
}

func (r staleSizeReader) Lstat(path string) (scan.Stat, error) {
	st, err := r.MetadataReader.Lstat(path)
	if err == nil && path == r.path {
		st.Size += r.delta
	}
	return st, err
}

func TestGenerateV1LateBindingRebindsSize(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "changed.bin")
	content := []byte("actual content on disk")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}

	inner, err := scan.DefaultReader()
	if err != nil {
		t.Fatal(err)
	}
	var warns []archive.Warning
	a, err := archive.New(archive.Options{
		OnWarn: func(w archive.Warning) { warns = append(warns, w) },
		Scan:   scan.Options{Reader: staleSizeReader{inner, path, 1000}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.AddDirectory(root); err != nil {
		t.Fatal(err)
	}

	estimate, err := a.EstimatedSizeV1()
	if err != nil {
		t.Fatal(err)
	}
	data := generate(t, a)
	if int64(len(data)) != estimate-1000 {
		t.Errorf("emitted %d, stale estimate %d: late binding should shave the lie", len(data), estimate)
	}

	dec, err := parseArchive(data)
	if err != nil {
		t.Fatal(err)
	}
	if f := dec.find("changed.bin"); !bytes.Equal(f.content, content) {
		t.Errorf("content %q", f.content)
	}
	// Scan-to-dispatch drift is not a conflict — no warnings.
	if len(warns) != 0 {
		t.Errorf("unexpected warnings: %+v", warns)
	}
}

func TestGenerateV1Errors(t *testing.T) {
	a, err := archive.New(archive.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.GenerateV1(context.Background()); err == nil {
		t.Error("empty archive must fail")
	}

	// Multiple roots without a name.
	if err := a.AddStream("s1", 1, strings.NewReader("x")); err != nil {
		t.Fatal(err)
	}
	if err := a.AddStream("s2", 1, strings.NewReader("y")); err != nil {
		t.Fatal(err)
	}
	if _, err := a.GenerateV1(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "Name") {
		t.Errorf("nameless virtual root: %v", err)
	}
}

func TestGenerateV1Cancellation(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "f"), make([]byte, 1<<20), 0o644); err != nil {
		t.Fatal(err)
	}
	a, err := archive.New(archive.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.AddDirectory(root); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	rc, err := a.GenerateV1(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	cancel()
	if _, err := io.ReadAll(rc); err == nil {
		t.Error("reads after cancellation must fail")
	}
}

// GenerateCatalog must mirror the archive's tree with scan-time metadata.
func TestGenerateCatalog(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	content := []byte("catalog content")
	if err := os.WriteFile(filepath.Join(root, "b.txt"), content, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("b.txt", filepath.Join(root, "sub", "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(root, "b.txt"), filepath.Join(root, "sub", "z.hard")); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filepath.Join(root, "a.fifo"), 0o600); err != nil {
		t.Fatal(err)
	}

	a, err := archive.New(archive.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.AddDirectory(root); err != nil {
		t.Fatal(err)
	}

	rc, err := a.GenerateCatalog(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	data, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}

	dec, err := catalog.Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	top := dec.Child("backup.pxar.didx")
	if top == nil {
		t.Fatalf("archive entry missing; root children: %+v", dec.Children)
	}

	info, err := os.Lstat(filepath.Join(root, "b.txt"))
	if err != nil {
		t.Fatal(err)
	}
	f := top.Child("b.txt")
	if f == nil || f.Type != catalog.TypeFile ||
		f.Size != uint64(len(content)) || f.MtimeSecs != info.ModTime().Unix() {
		t.Errorf("b.txt: %+v", f)
	}
	if l := top.Child("sub").Child("link"); l == nil || l.Type != catalog.TypeSymlink {
		t.Errorf("link: %+v", l)
	}
	if h := top.Child("sub").Child("z.hard"); h == nil || h.Type != catalog.TypeHardlink {
		t.Errorf("z.hard: %+v", h)
	}
	if p := top.Child("a.fifo"); p == nil || p.Type != catalog.TypeFifo {
		t.Errorf("a.fifo: %+v", p)
	}
}

// AddDirectoryAs places a directory under a caller-chosen name, and
// hardlink targets resolve through that name rather than the on-disk basename.
func TestAddDirectoryAs(t *testing.T) {
	base := t.TempDir()
	d1 := filepath.Join(base, "d1")
	d2 := filepath.Join(base, "d2")
	for _, d := range []string{d1, d2} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(d1, "orig"), []byte("shared"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(d1, "orig"), filepath.Join(d2, "linked")); err != nil {
		t.Fatal(err)
	}

	a, err := archive.New(archive.Options{Name: "backup"})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.AddDirectoryAs(d1, "etc"); err != nil {
		t.Fatal(err)
	}
	if err := a.AddDirectoryAs(d2, "var"); err != nil {
		t.Fatal(err)
	}

	dec, err := parseArchive(generate(t, a))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, c := range dec.children {
		names = append(names, c.name)
	}
	if strings.Join(names, ",") != "etc,var" {
		t.Errorf("root children: %v", names)
	}
	if dec.find("d1") != nil || dec.find("d2") != nil {
		t.Errorf("on-disk basenames leaked into the archive: %v", names)
	}
	hl := dec.find("var/linked")
	orig := dec.find("etc/orig")
	if hl == nil || orig == nil || hl.hardlink.target != "etc/orig" {
		t.Fatalf("renamed-root hardlink: %+v", hl)
	}
	if got := hl.start - hl.hardlink.offset; got != orig.start {
		t.Errorf("hardlink offset resolves to %d, target at %d", got, orig.start)
	}
}

// AddDirectoriesAs queues every entry of the map; invalid names and
// non-directories are rejected at Add time, duplicates at generate time.
func TestAddDirectoriesAs(t *testing.T) {
	base := t.TempDir()
	d1 := filepath.Join(base, "same")
	d2 := filepath.Join(base, "nested", "same")
	if err := os.MkdirAll(d2, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(d1, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d1, "a"), []byte("1"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d2, "b"), []byte("2"), 0o644); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(base, "file")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}

	// Two directories with the same basename would collide under
	// AddDirectories; renaming resolves it.
	a, err := archive.New(archive.Options{Name: "backup"})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.AddDirectoriesAs(map[string]string{d1: "first", d2: "second"}); err != nil {
		t.Fatal(err)
	}
	dec, err := parseArchive(generate(t, a))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, c := range dec.children {
		names = append(names, c.name)
	}
	if strings.Join(names, ",") != "first,second" {
		t.Errorf("root children: %v", names)
	}
	if dec.find("first/a") == nil || dec.find("second/b") == nil {
		t.Errorf("children not found under renamed roots")
	}

	// Invalid archive names are rejected at Add time.
	for _, bad := range []string{"", ".", "..", "a/b", "nul\x00"} {
		a, _ := archive.New(archive.Options{Name: "backup"})
		if err := a.AddDirectoryAs(d1, bad); err == nil {
			t.Errorf("AddDirectoryAs(%q): expected error", bad)
		}
	}

	// Non-directories are rejected, and paths sorting before the failing
	// one have already been queued.
	a, _ = archive.New(archive.Options{Name: "backup"})
	if err := a.AddDirectoriesAs(map[string]string{d1: "x", file: "y"}); err == nil {
		t.Error("AddDirectoriesAs with a file: expected error")
	}

	// Two roots renamed to the same name collide at generate time.
	a, _ = archive.New(archive.Options{Name: "backup"})
	if err := a.AddDirectoriesAs(map[string]string{d1: "dup", d2: "dup"}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.GenerateV1(context.Background()); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("duplicate archive names: got %v", err)
	}
}
