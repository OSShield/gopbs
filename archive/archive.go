package archive

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"time"

	"github.com/scheiblingco/gopbs/scan"
)

// WarnKind classifies non-fatal generation events.
type WarnKind int

const (
	// WarnSkipped: an entry could not be scanned and was omitted
	// (scan.Options.SkipOnError).
	WarnSkipped WarnKind = iota
	// WarnSizeChanged: a payload yielded a different byte count than its
	// bound size and was padded or truncated to keep the archive valid.
	WarnSizeChanged
	// WarnTorn: a file's size or mtime changed while its content was being
	// read; the archived bytes may interleave old and new content.
	WarnTorn
)

// Warning is a non-fatal event surfaced during generation.
type Warning struct {
	Kind   WarnKind
	Path   string
	Err    error // WarnSkipped: the scan error
	Bound  int64 // WarnSizeChanged: the size the archive committed to
	Actual int64 // WarnSizeChanged: the byte count the source yielded
}

// Options configures an Archive.
type Options struct {
	// Name is the archive name; it becomes the virtual root directory's name
	// when more than one root is added. Required in that case.
	Name string
	// Workers is the payload-read parallelism: 0 = GOMAXPROCS, 1 = fully
	// synchronous generation. Both modes produce byte-identical output.
	Workers int
	// Buffer is the reorder-buffer memory budget in bytes (async mode);
	// 0 = 64 MiB.
	Buffer int64
	// OnWarn receives non-fatal events; nil discards them.
	OnWarn func(Warning)
	// Scan carries scanner policy (SkipOnError, custom reader, quota
	// lookups). Its OnWarn field is ignored; scan warnings arrive at OnWarn
	// above as WarnSkipped.
	Scan scan.Options
}

type rootKind int

const (
	addDir rootKind = iota
	addFile
)

type addition struct {
	kind rootKind
	path string
}

// Archive accumulates roots and generates PXAR streams. Not safe for
// concurrent use; scanning happens at generation time, so the filesystem
// state that matters is the one at Generate, not at Add.
type Archive struct {
	opts    Options
	adds    []addition
	streams []*scan.Node
}

// New returns an empty Archive.
func New(opts Options) (*Archive, error) {
	if opts.Workers < 0 {
		return nil, fmt.Errorf("archive: negative worker count %d", opts.Workers)
	}
	if opts.Buffer < 0 {
		return nil, fmt.Errorf("archive: negative buffer budget %d", opts.Buffer)
	}
	return &Archive{opts: opts}, nil
}

// AddDirectory queues a directory tree. A single queued directory becomes the
// archive root; any other combination is placed under a virtual root named
// Options.Name.
func (a *Archive) AddDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("archive: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("archive: %s is not a directory", path)
	}
	a.adds = append(a.adds, addition{addDir, path})
	return nil
}

// AddDirectories queues several directory trees.
func (a *Archive) AddDirectories(paths []string) error {
	for _, p := range paths {
		if err := a.AddDirectory(p); err != nil {
			return err
		}
	}
	return nil
}

// AddFile queues a single non-directory entry, placed under the virtual root.
func (a *Archive) AddFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("archive: %w", err)
	}
	if info.IsDir() {
		return fmt.Errorf("archive: %s is a directory (use AddDirectory)", path)
	}
	a.adds = append(a.adds, addition{addFile, path})
	return nil
}

// AddFiles queues several non-directory entries.
func (a *Archive) AddFiles(paths []string) error {
	for _, p := range paths {
		if err := a.AddFile(p); err != nil {
			return err
		}
	}
	return nil
}

// AddStream queues a virtual file backed by r. size must be declared up
// front; if r yields a different byte count the output is padded or truncated
// to exactly size bytes and a WarnSizeChanged warning is issued. The reader
// is consumed during generation, so an Archive with streams generates once.
func (a *Archive) AddStream(name string, size int64, r io.Reader) error {
	n, err := scan.StreamNode(name, size, r)
	if err != nil {
		return fmt.Errorf("archive: %w", err)
	}
	a.streams = append(a.streams, n)
	return nil
}

// buildTree scans the queued roots into a single node tree.
func (a *Archive) buildTree() (*scan.Node, error) {
	if len(a.adds) == 0 && len(a.streams) == 0 {
		return nil, errors.New("archive: nothing added")
	}

	scanOpts := a.opts.Scan
	scanOpts.OnWarn = func(w scan.Warning) {
		a.warn(Warning{Kind: WarnSkipped, Path: w.Path, Err: w.Err})
	}
	s, err := scan.NewScanner(scanOpts)
	if err != nil {
		return nil, err
	}

	// A single directory and nothing else: that directory is the root.
	if len(a.adds) == 1 && a.adds[0].kind == addDir && len(a.streams) == 0 {
		return s.ScanDirectory(a.adds[0].path, "")
	}

	if a.opts.Name == "" {
		return nil, errors.New("archive: Options.Name is required when the archive has multiple roots")
	}

	children := make([]*scan.Node, 0, len(a.adds)+len(a.streams))
	for _, add := range a.adds {
		var (
			n   *scan.Node
			err error
		)
		// The archive path prefix is the entry's basename: its path under
		// the virtual root, used for hardlink target resolution.
		switch add.kind {
		case addDir:
			n, err = s.ScanDirectory(add.path, baseName(add.path))
		case addFile:
			n, err = s.ScanFile(add.path, baseName(add.path))
		}
		if err != nil {
			return nil, err
		}
		children = append(children, n)
	}
	children = append(children, a.streams...)

	root, err := scan.VirtualRoot(a.opts.Name, children)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	root.Stat.MtimeSecs = now.Unix()
	root.Stat.MtimeNanos = uint32(now.Nanosecond())
	return root, nil
}

// GenerateV1 builds the node tree and returns the archive as a stream.
// Generation runs concurrently with consumption; errors surface from Read,
// and Close cancels generation.
func (a *Archive) GenerateV1(ctx context.Context) (io.ReadCloser, error) {
	root, err := a.buildTree()
	if err != nil {
		return nil, err
	}

	workers := a.opts.Workers
	if workers == 0 {
		workers = runtime.GOMAXPROCS(0)
	}

	pr, pw := io.Pipe()
	go func() {
		genCtx, cancel := context.WithCancel(ctx)
		var src payloadSource = syncSource{}
		var async *asyncSource
		if workers > 1 {
			async = newAsyncSource(genCtx, collectPayloads(root, nil), workers, a.opts.Buffer)
		}
		if async != nil {
			src = async
		}

		em := &emitter{
			w:    &countWriter{ctx: genCtx, w: pw},
			src:  src,
			warn: a.warn,
		}
		err := em.run(root)
		cancel()
		if async != nil {
			async.wait()
		}
		pw.CloseWithError(err)
	}()
	return pr, nil
}

// EstimatedSizeV1 scans the queued roots and returns the archive size implied
// by scan-time metadata. An estimate: payload sizes are re-bound at emission,
// so files changed after the estimate shift the real total.
func (a *Archive) EstimatedSizeV1() (int64, error) {
	root, err := a.buildTree()
	if err != nil {
		return 0, err
	}
	return int64(estimateV1(root, true)), nil
}

func (a *Archive) warn(w Warning) {
	if a.opts.OnWarn != nil {
		a.opts.OnWarn(w)
	}
}

func baseName(path string) string {
	// filepath.Base semantics without importing path/filepath twice over.
	if path == "" {
		return ""
	}
	for len(path) > 1 && path[len(path)-1] == '/' {
		path = path[:len(path)-1]
	}
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[i+1:]
		}
	}
	return path
}
