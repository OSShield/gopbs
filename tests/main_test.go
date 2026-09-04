//go:build integration

// Integration harness: generates a random source tree, builds PXAR archives
// of it with three implementations (the official pxar CLI, tizbac's client,
// and gopbs), extracts them all with the official pxar CLI, and compares the
// restored trees with each other and with the source.
//
// Requires docker with the compose plugin. Run with:
//
//	go test -tags integration .
package main_test

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const (
	maxLevels = 4
	maxSize   = 1024 * 10 // 10 KiB
	maxDirs   = 5
	maxFiles  = 8
)

const (
	sourceDir     = "./.test-source"
	sourceExclDir = "./.test-source-exclude" // deterministic exclude fixture (exclude_test.go)
	pxarDir       = "./.test-pxar"
	restoreDir    = "./.test-restore"
	keysDir       = "./.test-keys"
)

func TestMain(m *testing.M) {
	flag.Parse() // compose() consults testing.Verbose

	cleanAll()
	makeTree()
	makeExcludeTree()

	// One build up front, then one one-off container per archiver. The CLI
	// (unlike the compose Go SDK this harness used before) handles one-off
	// container lifecycle reliably.
	if err := compose("build"); err != nil {
		log.Fatal(err)
	}
	for _, svc := range []string{
		"pbs", "tizbac", "gopbs", "pbssplit", "gopbssplit",
		"pbsexclude", "gopbsexclude", "pbssplitexclude", "gopbssplitexclude",
	} {
		if err := compose("run", "--rm", "--remove-orphans", svc); err != nil {
			log.Fatalf("creating %s archive: %v", svc, err)
		}
	}

	os.Exit(m.Run())
}

// TestComparison extracts all archives with the official pxar CLI and
// requires the restored trees to be identical to each other and the source.
func TestComparison(t *testing.T) {
	if err := compose("run", "--rm", "--remove-orphans", "restore"); err != nil {
		t.Fatalf("restore: %v", err)
	}

	for _, cmp := range []struct{ a, b string }{
		{filepath.Join(restoreDir, "tizbac"), filepath.Join(restoreDir, "pbs")},
		{filepath.Join(restoreDir, "gopbs"), filepath.Join(restoreDir, "pbs")},
		{filepath.Join(restoreDir, "gopbs"), sourceDir},
		{filepath.Join(restoreDir, "gopbs-split"), sourceDir},
	} {
		equal, err := compareTrees(cmp.a, cmp.b)
		if err != nil {
			t.Fatalf("comparing %s with %s: %v", cmp.a, cmp.b, err)
		}
		if !equal {
			t.Errorf("%s and %s differ", cmp.a, cmp.b)
		}
	}
}

// TestSplitComparison requires gopbs's v2 split archive to be byte-identical
// to the official pxar CLI's, stream for stream. (The restore-based check for
// the split archive lives in TestComparison.)
func TestSplitComparison(t *testing.T) {
	for _, name := range []string{"mpxar", "ppxar"} {
		ours, err := os.ReadFile(filepath.Join(pxarDir, "gopbs."+name))
		if err != nil {
			t.Fatal(err)
		}
		official, err := os.ReadFile(filepath.Join(pxarDir, "pbs."+name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(ours, official) {
			t.Errorf("%s differs from the official encoder's (%d vs %d bytes)", name, len(ours), len(official))
		}
	}
}

// compose runs `docker compose <args>` in the tests directory, forwarding
// UID/GID so containers write host-owned files. Output is shown only on
// failure.
func compose(args ...string) error {
	cmd := exec.Command("docker", append([]string{"compose"}, args...)...)
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("UID=%d", os.Getuid()),
		fmt.Sprintf("GID=%d", os.Getgid()),
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker compose %s: %w\n%s", strings.Join(args, " "), err, out)
	}
	if testing.Verbose() {
		fmt.Printf("docker compose %s:\n%s", strings.Join(args, " "), out)
	}
	return nil
}

func makeTree() {
	levels := 1 + int(randInt(maxLevels))
	log.Printf("generating tree in %s (max levels: %d)", sourceDir, levels)
	if err := generateTree(sourceDir, 1, levels); err != nil {
		log.Fatalf("generating tree: %v", err)
	}
}

func generateTree(dir string, level, maxLevel int) error {
	for i := int64(0); i < randInt(maxFiles+1); i++ {
		data := make([]byte, randInt(maxSize+1))
		rand.Read(data)
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("file_%d.bin", i)), data, 0o644); err != nil {
			return err
		}
	}
	if level >= maxLevel {
		return nil
	}
	for i := int64(0); i < randInt(maxDirs+1); i++ {
		sub := filepath.Join(dir, fmt.Sprintf("dir_%d", i))
		if err := os.MkdirAll(sub, 0o755); err != nil {
			return err
		}
		if err := generateTree(sub, level+1, maxLevel); err != nil {
			return err
		}
	}
	return nil
}

func randInt(max int64) int64 {
	n, err := rand.Int(rand.Reader, big.NewInt(max))
	if err != nil {
		panic(fmt.Sprintf("random: %v", err))
	}
	return n.Int64()
}

// cleanAll resets the work directories, keeping their .gitkeep files.
func cleanAll() {
	clean := func(dir string, keep func(string) bool) {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			log.Fatalf("creating %s: %v", dir, err)
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			log.Fatalf("reading %s: %v", dir, err)
		}
		for _, e := range entries {
			if keep(e.Name()) {
				continue
			}
			if err := os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
				log.Fatalf("cleaning %s: %v", dir, err)
			}
		}
	}
	notGitkeep := func(name string) bool { return name == ".gitkeep" }
	clean(sourceDir, notGitkeep)
	clean(sourceExclDir, notGitkeep)
	clean(pxarDir, notGitkeep)
	clean(restoreDir, notGitkeep)
	clean(keysDir, notGitkeep)
}

// compareTrees reports whether two directory trees are identical in
// structure and file content.
func compareTrees(dir1, dir2 string) (bool, error) {
	entries1, err := collectEntries(dir1)
	if err != nil {
		return false, err
	}
	entries2, err := collectEntries(dir2)
	if err != nil {
		return false, err
	}
	if len(entries1) != len(entries2) {
		return false, nil
	}
	for rel, e1 := range entries1 {
		if e2, ok := entries2[rel]; !ok || e1 != e2 {
			return false, nil
		}
	}
	return true, nil
}

type treeEntry struct {
	isDir bool
	hash  string
}

func collectEntries(root string) (map[string]treeEntry, error) {
	entries := make(map[string]treeEntry)
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		e := treeEntry{isDir: info.IsDir()}
		if !info.IsDir() {
			f, err := os.Open(path)
			if err != nil {
				return fmt.Errorf("opening %s: %w", path, err)
			}
			h := sha256.New()
			_, err = io.Copy(h, f)
			f.Close()
			if err != nil {
				return fmt.Errorf("hashing %s: %w", path, err)
			}
			e.hash = fmt.Sprintf("%x", h.Sum(nil))
		}
		entries[rel] = e
		return nil
	})
	return entries, err
}
