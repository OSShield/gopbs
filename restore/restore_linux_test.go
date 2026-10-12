//go:build linux

package restore_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/osshield/gopbs/archive"
	"github.com/osshield/gopbs/pxar"
	"github.com/osshield/gopbs/restore"
	"github.com/osshield/gopbs/scan"
	"golang.org/x/sys/unix"
)

// sourceTree writes a tree with every entry type an unprivileged user can
// create, plus root-only ones when running as root.
func sourceTree(t *testing.T) string {
	t.Helper()
	src := t.TempDir()
	p := func(name string) string { return filepath.Join(src, name) }
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, d := range []string{"dir", "dir/sub", "ro", "empty"} {
		must(os.Mkdir(p(d), 0o755))
	}
	big := make([]byte, 3<<20)
	rand.New(rand.NewSource(1)).Read(big)
	must(os.WriteFile(p("big.bin"), big, 0o644))
	must(os.WriteFile(p("a.txt"), []byte("alpha"), 0o640))
	must(os.WriteFile(p("setuid"), []byte("#!/bin/sh\n"), 0o755))
	must(unix.Chmod(p("setuid"), 0o4755))
	must(os.WriteFile(p("dir/sub/c"), []byte("gamma"), 0o600))
	must(os.WriteFile(p("ro/locked"), []byte("read only"), 0o444))
	must(os.Link(p("a.txt"), p("z.hard")))
	must(os.Symlink("dir/sub/c", p("s.link")))
	must(os.Symlink("../nowhere", p("dangling")))
	must(unix.Mkfifo(p("fifo"), 0o620))
	if err := unix.Setxattr(p("a.txt"), "user.note", []byte("x\x00y"), 0); err != nil {
		t.Logf("user xattrs unsupported here: %v", err)
	}
	if _, err := exec.LookPath("setfacl"); err == nil {
		for _, args := range [][]string{{"-m", "u:65534:r,g:65534:rw", p("a.txt")}, {"-d", "-m", "g:65534:rx", p("dir")}} {
			if out, err := exec.Command("setfacl", args...).CombinedOutput(); err != nil {
				t.Logf("setfacl %v: %v %s", args, err, out)
			}
		}
	}
	if os.Geteuid() == 0 {
		must(unix.Mknod(p("null"), unix.S_IFCHR|0o666, int(unix.Mkdev(1, 3))))
		must(os.WriteFile(p("owned"), nil, 0o644))
		must(os.Lchown(p("owned"), 1234, 5678))
		must(os.Lchown(p("s.link"), 4321, 8765))
		// VFS_CAP_REVISION_2 with CAP_NET_BIND_SERVICE permitted+effective.
		caps := []byte{1, 0, 0, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
		must(os.WriteFile(p("capped"), nil, 0o755))
		must(unix.Setxattr(p("capped"), "security.capability", caps, 0))
	}
	must(unix.Chmod(p("dir/sub"), 0o2775))
	must(os.Chmod(p("ro"), 0o555))
	// mtimes last, deepest first, so creating entries does not touch them.
	for i, name := range []string{"dir/sub/c", "dir/sub", "dir", "ro", "a.txt", "big.bin", "empty", "."} {
		when := time.Unix(1_600_000_000+int64(i)*1000, int64(i)*111_111_111)
		must(os.Chtimes(p(name), when, when))
	}
	must(unix.Lutimes(p("s.link"), []unix.Timeval{{Sec: 1_500_000_000}, {Sec: 1_500_000_000, Usec: 5}}))
	t.Cleanup(func() { os.Chmod(p("ro"), 0o755) })
	return src
}

func newArchive(t *testing.T, src string) *archive.Archive {
	t.Helper()
	a, err := archive.New(archive.Options{Name: "t"})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.AddDirectory(src); err != nil {
		t.Fatal(err)
	}
	return a
}

func archiveV1(t *testing.T, src string) []byte {
	t.Helper()
	rc, err := newArchive(t, src).GenerateV1(context.Background())
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

func archiveV2(t *testing.T, src string) (meta, payload []byte) {
	t.Helper()
	metaRC, payloadRC, err := newArchive(t, src).GenerateV2(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer metaRC.Close()
	defer payloadRC.Close()
	var wg sync.WaitGroup
	var perr error
	wg.Go(func() { payload, perr = io.ReadAll(payloadRC) })
	meta, err = io.ReadAll(metaRC)
	wg.Wait()
	if err != nil || perr != nil {
		t.Fatal(err, perr)
	}
	return meta, payload
}

// compareTrees scans both trees and compares every node field by field,
// and regular file contents byte by byte.
func compareTrees(t *testing.T, want, got string) {
	t.Helper()
	s, err := scan.NewScanner(scan.Options{})
	if err != nil {
		t.Fatal(err)
	}
	a, err := s.ScanDirectory(want, "")
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.ScanDirectory(got, "")
	if err != nil {
		t.Fatal(err)
	}
	var walk func(a, b *scan.Node, rel string)
	walk = func(a, b *scan.Node, rel string) {
		if (rel != "." && a.Name != b.Name) || a.Kind != b.Kind || a.LinkTarget != b.LinkTarget || len(a.Children) != len(b.Children) {
			t.Fatalf("%q: %s %v %q (%d children), restored %s %v %q (%d children)", rel,
				a.Name, a.Kind, a.LinkTarget, len(a.Children), b.Name, b.Kind, b.LinkTarget, len(b.Children))
		}
		sa, sb := a.Stat, b.Stat
		sa.Dev, sa.Ino, sa.Nlink, sb.Dev, sb.Ino, sb.Nlink = 0, 0, 0, 0, 0, 0
		if a.Kind == scan.KindDirectory || a.Kind == scan.KindSymlink {
			sa.Size, sb.Size = 0, 0 // filesystem-dependent
		}
		if sa != sb {
			t.Errorf("%q: stat %+v, restored %+v", rel, sa, sb)
		}
		if !reflect.DeepEqual(a.Xattrs, b.Xattrs) || !reflect.DeepEqual(a.ACL, b.ACL) ||
			!bytes.Equal(a.FCaps, b.FCaps) {
			t.Errorf("%q: xattrs %v acl %+v fcaps %x, restored %v %+v %x", rel, a.Xattrs, a.ACL, a.FCaps, b.Xattrs, b.ACL, b.FCaps)
		}
		if a.Kind == scan.KindFile {
			x, _ := os.ReadFile(a.Path)
			y, _ := os.ReadFile(b.Path)
			if !bytes.Equal(x, y) {
				t.Errorf("%q: content differs", rel)
			}
		}
		for i := range a.Children {
			walk(a.Children[i], b.Children[i], filepath.Join(rel, a.Children[i].Name))
		}
	}
	walk(a, b, ".")
}

func TestExtract(t *testing.T) {
	src := sourceTree(t)
	v1 := archiveV1(t, src)
	meta, payload := archiveV2(t, src)
	for name, r := range map[string]*pxar.Reader{
		"v1": pxar.NewReaderV1(bytes.NewReader(v1)),
		"v2": pxar.NewReaderV2(bytes.NewReader(meta), bytes.NewReader(payload)),
	} {
		t.Run(name, func(t *testing.T) {
			dst := filepath.Join(t.TempDir(), "out")
			var warns []restore.Warning
			err := restore.Extract(context.Background(), r, dst, restore.Options{
				OnWarn: func(w restore.Warning) { warns = append(warns, w) },
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { os.Chmod(filepath.Join(dst, "ro"), 0o755) })
			if len(warns) > 0 {
				t.Errorf("warnings: %v", warns)
			}
			compareTrees(t, src, dst)
		})
	}
}

func TestExtractPaths(t *testing.T) {
	src := sourceTree(t)
	v1 := archiveV1(t, src)
	fsys, err := pxar.OpenV1(bytes.NewReader(v1), int64(len(v1)))
	if err != nil {
		t.Fatal(err)
	}
	dst := t.TempDir()
	progress := map[string]int{}
	err = restore.ExtractPaths(context.Background(), fsys, []string{"dir/sub", "z.hard", "dir/sub/c"}, dst, restore.Options{
		OnProgress: func(path string, n int) { progress[path] += n },
	})
	if err != nil {
		t.Fatal(err)
	}
	if want := map[string]int{"dir/sub/c": 5, "z.hard": 5}; !reflect.DeepEqual(progress, want) {
		t.Fatalf("progress = %v, want %v", progress, want)
	}
	var got []string
	filepath.Walk(dst, func(path string, _ os.FileInfo, _ error) error {
		rel, _ := filepath.Rel(dst, path)
		got = append(got, rel)
		return nil
	})
	if strings.Join(got, ",") != ".,dir,dir/sub,dir/sub/c,z.hard" {
		t.Fatalf("restored %q", got)
	}
	// A selected hardlink becomes a copy of its target.
	if data, err := os.ReadFile(filepath.Join(dst, "z.hard")); err != nil || string(data) != "alpha" {
		t.Fatalf("z.hard: %q %v", data, err)
	}
	fi, _ := os.Stat(filepath.Join(dst, "dir/sub"))
	if fi.Mode()&os.ModeSetgid == 0 || fi.ModTime().Unix() != 1_600_001_000 {
		t.Fatalf("dir/sub metadata not restored: %v %v", fi.Mode(), fi.ModTime())
	}
}

// Existing content is refused without Overwrite; with it, a symlink in the
// way is replaced, never followed out of the target.
func TestExtractOverwrite(t *testing.T) {
	src := sourceTree(t)
	v1 := archiveV1(t, src)
	dst, outside := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(dst, "a.txt"), []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dst, "dir")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(filepath.Join(dst, "ro"), 0o755) })

	err := restore.Extract(context.Background(), pxar.NewReaderV1(bytes.NewReader(v1)), dst, restore.Options{})
	if !errors.Is(err, restore.ErrTargetNotEmpty) {
		t.Fatalf("non-empty target: %v", err)
	}
	err = restore.Extract(context.Background(), pxar.NewReaderV1(bytes.NewReader(v1)), dst, restore.Options{Overwrite: true})
	if err != nil {
		t.Fatal(err)
	}
	if entries, _ := os.ReadDir(outside); len(entries) != 0 {
		t.Fatalf("restore wrote through a symlink: %v", entries)
	}
	compareTrees(t, src, dst)
}

// Without privileges, foreign ownership is a warning, not a failure.
func TestExtractWarnsUnprivileged(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root")
	}
	var b []byte
	b = pxar.AppendEntry(b, pxar.Entry{Mode: 0o040755})
	b = pxar.AppendFilename(b, "f")
	b = pxar.AppendEntry(b, pxar.Entry{Mode: 0o100644, UID: 0, GID: 0})
	b = append(pxar.AppendPayloadHeader(b, 2), "hi"...)
	b = pxar.AppendFilename(b, "null")
	b = pxar.AppendEntry(b, pxar.Entry{Mode: 0o020666})
	b = pxar.AppendDevice(b, pxar.Device{Major: 1, Minor: 3})
	b = pxar.AppendGoodbye(b, nil, 0, uint64(len(b)))

	dst := t.TempDir()
	var warns []string
	err := restore.Extract(context.Background(), pxar.NewReaderV1(bytes.NewReader(b)), dst, restore.Options{
		OnWarn: func(w restore.Warning) { warns = append(warns, w.Error()) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(filepath.Join(dst, "f")); err != nil || string(data) != "hi" {
		t.Fatalf("content: %q %v", data, err)
	}
	all := strings.Join(warns, "\n")
	if !strings.Contains(all, "f: chown 0:0") || !strings.Contains(all, "null: ") {
		t.Fatalf("warnings: %s", all)
	}
}

func TestExtractCancel(t *testing.T) {
	v1 := archiveV1(t, sourceTree(t))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := restore.Extract(ctx, pxar.NewReaderV1(bytes.NewReader(v1)), t.TempDir(), restore.Options{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
}

// BenchmarkExtract measures decoding plus writing to disk, no network:
// many small files stress per-entry metadata calls, few large ones raw
// throughput.
func BenchmarkExtract(b *testing.B) {
	for _, shape := range []struct {
		name        string
		files, size int
	}{{"many-small", 4000, 4 << 10}, {"few-large", 4, 16 << 20}} {
		b.Run(shape.name, func(b *testing.B) {
			src := b.TempDir()
			rng := rand.New(rand.NewSource(1))
			for i := range shape.files {
				data := make([]byte, shape.size)
				rng.Read(data)
				dir := filepath.Join(src, fmt.Sprintf("d%02d", i%50))
				os.MkdirAll(dir, 0o755)
				if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("f%d", i)), data, 0o644); err != nil {
					b.Fatal(err)
				}
			}
			a, err := archive.New(archive.Options{})
			if err != nil {
				b.Fatal(err)
			}
			if err := a.AddDirectory(src); err != nil {
				b.Fatal(err)
			}
			rc, err := a.GenerateV1(context.Background())
			if err != nil {
				b.Fatal(err)
			}
			v1, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				b.Fatal(err)
			}
			b.SetBytes(int64(shape.files * shape.size))
			for b.Loop() {
				dst := filepath.Join(b.TempDir(), "out")
				if err := restore.Extract(context.Background(), pxar.NewReaderV1(bytes.NewReader(v1)), dst, restore.Options{}); err != nil {
					b.Fatal(err)
				}
				b.StopTimer()
				os.RemoveAll(dst)
				b.StartTimer()
			}
			b.ReportMetric(float64(shape.files)*float64(b.N)/b.Elapsed().Seconds(), "files/s")
		})
	}
}
