//go:build linux

package archive_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/osshield/gopbs/archive"
	"github.com/osshield/gopbs/catalog"
	"github.com/osshield/gopbs/scan"
)

const cliPatternsContent = "*.tmp\n!keep.tmp\ncache/\n"

var cliPatterns = []string{"*.tmp", "!keep.tmp", "cache/"}

func excludeFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, f := range []string{"a.tmp", "keep.tmp", "b.txt", "cache/x", "sub/cache/y", "sub/c.tmp", "sub/d.txt"} {
		p := filepath.Join(root, f)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("content of "+f), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func newExcludeArchive(t *testing.T, opts archive.Options, root string) *archive.Archive {
	t.Helper()
	a, err := archive.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.AddDirectory(root); err != nil {
		t.Fatal(err)
	}
	return a
}

// checkCLIFile asserts the synthetic .pxarexclude-cli entry: last child of
// the root, mode 0600, owned by the process's real uid/gid, mtime 0, with
// the pattern lines as content.
func checkCLIFile(t *testing.T, root *decNode, want string) {
	t.Helper()
	if len(root.children) == 0 {
		t.Fatal("root has no children")
	}
	last := root.children[len(root.children)-1]
	if last.name != ".pxarexclude-cli" {
		t.Fatalf("last root child is %q, want .pxarexclude-cli (children: %v)", last.name, childNames(root))
	}
	if last.mode != scan.ModeRegular|0o600 {
		t.Errorf(".pxarexclude-cli mode = %o", last.mode)
	}
	if last.uid != uint32(os.Getuid()) || last.gid != uint32(os.Getgid()) {
		t.Errorf(".pxarexclude-cli uid/gid = %d/%d, want %d/%d", last.uid, last.gid, os.Getuid(), os.Getgid())
	}
	if last.mtimeSecs != 0 || last.mtimeNanos != 0 {
		t.Errorf(".pxarexclude-cli mtime = %d.%d, want 0", last.mtimeSecs, last.mtimeNanos)
	}
	if string(last.content) != want {
		t.Errorf(".pxarexclude-cli content = %q, want %q", last.content, want)
	}
}

func childNames(n *decNode) []string {
	names := make([]string, len(n.children))
	for i, c := range n.children {
		names[i] = c.name
	}
	return names
}

func TestGenerateV1ExcludeCLIFile(t *testing.T) {
	root := excludeFixture(t)
	for _, workers := range []int{1, 0} {
		a := newExcludeArchive(t, archive.Options{Workers: workers, Scan: scan.Options{Exclude: cliPatterns}}, root)
		estimate, err := a.EstimatedSizeV1()
		if err != nil {
			t.Fatal(err)
		}
		data := generate(t, a)
		if int64(len(data)) != estimate {
			t.Errorf("workers=%d: emitted %d bytes, estimate was %d", workers, len(data), estimate)
		}
		dec, err := parseArchive(data)
		if err != nil {
			t.Fatal(err)
		}
		checkCLIFile(t, dec, cliPatternsContent)
		for _, absent := range []string{"a.tmp", "cache", "sub/cache", "sub/c.tmp"} {
			if dec.find(absent) != nil {
				t.Errorf("workers=%d: %s should be excluded", workers, absent)
			}
		}
		for _, present := range []string{"keep.tmp", "b.txt", "sub/d.txt"} {
			if dec.find(present) == nil {
				t.Errorf("workers=%d: %s missing", workers, present)
			}
		}
		if workers == 1 {
			// Generating again must produce the same bytes: the synthetic
			// node's reader is rebuilt per generation.
			if again := generate(t, a); !bytes.Equal(again, data) {
				t.Error("second generation differs")
			}
		}
	}
}

func TestGenerateV1NoPatternsNoCLIFile(t *testing.T) {
	root := excludeFixture(t)
	for name, opts := range map[string]scan.Options{
		"plain":       {},
		"pxarexclude": {PxarExcludeFiles: true},
		"filter":      {Filter: func(_, ap string, _ scan.Stat) bool { return ap != "a.tmp" }},
	} {
		a := newExcludeArchive(t, archive.Options{Scan: opts}, root)
		dec, err := parseArchive(generate(t, a))
		if err != nil {
			t.Fatal(err)
		}
		if dec.find(".pxarexclude-cli") != nil {
			t.Errorf("%s: unexpected .pxarexclude-cli", name)
		}
		if name == "filter" && dec.find("a.tmp") != nil {
			t.Error("filter: a.tmp should be excluded")
		}
	}
}

// Under a virtual root the patterns see the roots' archive names as the
// first path component, and the synthetic file still comes last.
func TestGenerateV1VirtualRootExclude(t *testing.T) {
	base := t.TempDir()
	d1, d2 := filepath.Join(base, "d1"), filepath.Join(base, "d2")
	for _, f := range []string{"d1/orig", "d1/skip.tmp", "d2/orig", "d2/zzz"} {
		p := filepath.Join(base, f)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(f), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	a, err := archive.New(archive.Options{Name: "backup", Scan: scan.Options{Exclude: []string{"*.tmp", "/d2/orig"}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.AddDirectories([]string{d1, d2}); err != nil {
		t.Fatal(err)
	}
	if err := a.AddStream("zzz-stream", 3, bytes.NewReader([]byte("abc"))); err != nil {
		t.Fatal(err)
	}
	dec, err := parseArchive(generate(t, a))
	if err != nil {
		t.Fatal(err)
	}
	checkCLIFile(t, dec, "*.tmp\n/d2/orig\n")
	if dec.find("d1/orig") == nil || dec.find("d2/zzz") == nil || dec.find("zzz-stream") == nil {
		t.Errorf("expected entries missing: %v", childNames(dec))
	}
	if dec.find("d1/skip.tmp") != nil || dec.find("d2/orig") != nil {
		t.Error("excluded entries present")
	}
}

// A real root entry named .pxarexclude-cli is dropped with a warning,
// patterns or not, like the official client does.
func TestReservedNameDropped(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".pxarexclude-cli"), []byte("user file"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "f"), []byte("f"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, patterns := range [][]string{nil, cliPatterns} {
		var warns []archive.Warning
		a := newExcludeArchive(t, archive.Options{
			Scan:   scan.Options{Exclude: patterns},
			OnWarn: func(w archive.Warning) { warns = append(warns, w) },
		}, root)
		dec, err := parseArchive(generate(t, a))
		if err != nil {
			t.Fatal(err)
		}
		if len(warns) != 1 || warns[0].Kind != archive.WarnSkipped || !errors.Is(warns[0].Err, archive.ErrReservedName) ||
			filepath.Base(warns[0].Path) != ".pxarexclude-cli" {
			t.Errorf("patterns=%v: warnings = %+v", patterns, warns)
		}
		cli := dec.find(".pxarexclude-cli")
		if patterns == nil {
			if cli != nil {
				t.Error("real .pxarexclude-cli must be dropped")
			}
		} else if cli == nil || string(cli.content) != cliPatternsContent {
			t.Errorf("synthetic .pxarexclude-cli = %+v", cli)
		}
		if dec.find("f") == nil {
			t.Error("f missing")
		}
	}
}

func TestGenerateCatalogExclude(t *testing.T) {
	root := excludeFixture(t)
	a := newExcludeArchive(t, archive.Options{Scan: scan.Options{Exclude: cliPatterns}}, root)
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
		t.Fatalf("archive entry missing: %+v", dec.Children)
	}
	cli := top.Child(".pxarexclude-cli")
	if cli == nil || cli.Type != catalog.TypeFile || cli.Size != uint64(len(cliPatternsContent)) || cli.MtimeSecs != 0 {
		t.Errorf(".pxarexclude-cli catalog entry = %+v", cli)
	}
	if top.Child("a.tmp") != nil || top.Child("cache") != nil || top.Child("sub").Child("cache") != nil {
		t.Error("excluded entries present in catalog")
	}
	if top.Child("keep.tmp") == nil {
		t.Error("keep.tmp missing from catalog")
	}
}

func TestGenerateV2Prelude(t *testing.T) {
	root := excludeFixture(t)
	wantPrelude := `{"exclude-patterns":"*.tmp\n!keep.tmp\ncache/\n"}`
	var first []byte
	for _, workers := range []int{1, 0} {
		a := newExcludeArchive(t, archive.Options{Workers: workers, Scan: scan.Options{Exclude: cliPatterns}}, root)
		estMeta, estPayload, err := a.EstimatedSizeV2()
		if err != nil {
			t.Fatal(err)
		}
		meta, payload := generateV2(t, a)
		if int64(len(meta)) != estMeta || int64(len(payload)) != estPayload {
			t.Errorf("workers=%d: sizes %d/%d, estimates %d/%d", workers, len(meta), len(payload), estMeta, estPayload)
		}
		dec, err := parseArchiveV2(meta, payload)
		if err != nil {
			t.Fatal(err)
		}
		if string(dec.prelude) != wantPrelude {
			t.Errorf("prelude = %q, want %q", dec.prelude, wantPrelude)
		}
		if dec.find(".pxarexclude-cli") != nil {
			t.Error("v2 must not carry a .pxarexclude-cli file")
		}
		if dec.find("a.tmp") != nil || dec.find("cache") != nil || dec.find("keep.tmp") == nil {
			t.Error("exclusion not applied")
		}
		both := append(append([]byte(nil), meta...), payload...)
		if first == nil {
			first = both
		} else if !bytes.Equal(first, both) {
			t.Error("async output differs from sync")
		}
	}
}

func TestGenerateV2NoPrelude(t *testing.T) {
	root := excludeFixture(t)
	a := newExcludeArchive(t, archive.Options{Scan: scan.Options{PxarExcludeFiles: true}}, root)
	dec, err := parseArchiveV2(generateV2(t, a))
	if err != nil {
		t.Fatal(err)
	}
	if dec.prelude != nil {
		t.Errorf("unexpected prelude %q", dec.prelude)
	}
}

// serde_json-compatible escaping: quotes, backslashes and control
// characters only; multi-byte UTF-8, HTML characters and DEL pass through.
func TestPreludeJSON(t *testing.T) {
	for in, want := range map[string]string{
		"*.tmp\n":                 `{"exclude-patterns":"*.tmp\n"}`,
		"":                        `{"exclude-patterns":""}`,
		"a\"b\\c\t\r\b\f\x01\x1f": `{"exclude-patterns":"a\"b\\c\t\r\b\f\u0001\u001f"}`,
		"ünï/<>&\x7f":             "{\"exclude-patterns\":\"ünï/<>&\x7f\"}",
	} {
		if got := string(archive.PreludeJSON([]byte(in))); got != want {
			t.Errorf("preludeJSON(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestWarnBadPatternMapping(t *testing.T) {
	root := excludeFixture(t)
	if err := os.WriteFile(filepath.Join(root, ".pxarexclude"), []byte("[bad\n*.tmp\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var warns []archive.Warning
	a := newExcludeArchive(t, archive.Options{
		Scan:   scan.Options{PxarExcludeFiles: true},
		OnWarn: func(w archive.Warning) { warns = append(warns, w) },
	}, root)
	dec, err := parseArchive(generate(t, a))
	if err != nil {
		t.Fatal(err)
	}
	if len(warns) != 1 || warns[0].Kind != archive.WarnBadPattern || filepath.Base(warns[0].Path) != ".pxarexclude" {
		t.Fatalf("warnings = %+v", warns)
	}
	var pe *scan.PatternError
	if !errors.As(warns[0].Err, &pe) || pe.Pattern != "[bad" {
		t.Errorf("warning error = %v", warns[0].Err)
	}
	if dec.find("a.tmp") != nil || dec.find(".pxarexclude") == nil {
		t.Error("good lines must still apply and the file must be archived")
	}
}

func TestNewRejectsBadPattern(t *testing.T) {
	_, err := archive.New(archive.Options{Scan: scan.Options{Exclude: []string{"*.tmp", ""}}})
	var pe *scan.PatternError
	if !errors.As(err, &pe) || pe.Pattern != "" {
		t.Errorf("New error = %v", err)
	}
}
