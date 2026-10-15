// Package restore writes decoded pxar archives to disk.
//
// Extract restores a whole archive in one sequential pass over a
// pxar.Reader; ExtractPaths restores selected paths through a random-access
// pxar.FS. Both write through an os.Root, so no entry — whatever its name,
// symlink or hardlink target — can create or modify anything outside the
// target directory.
//
// Metadata is applied best-effort through a MetadataWriter, the platform
// seam mirroring scan.MetadataReader: the Linux writer restores owners,
// permissions, xattrs, POSIX ACLs, file capabilities, device and fifo nodes
// and nanosecond mtimes; other platforms restore content, directories,
// symlinks and hardlinks where the system allows, permissions and mtimes.
// Whatever cannot be applied (ownership without privilege, a name invalid on
// Windows) is reported through Options.OnWarn and the restore goes on.
// Directory metadata is applied last, deepest first, so restoring a
// directory's content does not disturb its mtime or permissions.
package restore

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/osshield/gopbs/pxar"
)

// ErrTargetNotEmpty is returned for a target directory with content when
// Options.Overwrite is not set.
var ErrTargetNotEmpty = errors.New("restore: target directory is not empty")

// Options configures a restore. The zero value restores into a missing or
// empty directory with the platform's MetadataWriter.
type Options struct {
	// Overwrite allows a target directory with content: entries replace
	// existing files, symlinks and special files of the same name, and
	// existing directories are merged into. A directory in the way of a
	// non-directory entry (or the reverse) is still an error.
	Overwrite bool
	// Writer overrides the platform MetadataWriter.
	Writer MetadataWriter
	// OnWarn receives non-fatal events; nil discards them.
	OnWarn func(Warning)
	// OnProgress, when set, is called with the archive-relative path and
	// the byte count each time a slice of file content is written. Called
	// from the restoring goroutine; keep it fast.
	OnProgress func(path string, n int)
}

// Warning is a non-fatal restore event: metadata that could not be applied,
// or an entry that could not be created on this system.
type Warning struct {
	Path string // archive-relative path
	Err  error
}

func (w Warning) Error() string { return w.Path + ": " + w.Err.Error() }

// MetadataWriter is the platform seam: it creates special files and applies
// an entry's metadata. Names are slash-separated paths relative to root;
// "." is root itself. Neither method may follow a final symlink.
type MetadataWriter interface {
	// Mknod creates a block or char device, fifo or socket.
	Mknod(root *os.Root, name string, n *pxar.Node) error
	// Apply sets n's owner, permissions, xattrs, ACLs, file capabilities and
	// mtime on the existing entry name, reporting each failure to warn.
	Apply(root *os.Root, name string, n *pxar.Node, warn func(error))
}

// Extract restores every entry r yields below dir, creating dir if needed.
// The archive root's own metadata is applied to dir.
func Extract(ctx context.Context, r *pxar.Reader, dir string, opts Options) error {
	x, err := newExtractor(ctx, dir, opts)
	if err != nil {
		return err
	}
	defer x.root.Close()
	for {
		n, err := r.Next()
		if err == io.EOF {
			return x.finish()
		}
		if err != nil {
			return err
		}
		if err := x.entry(n, n.Path, r); err != nil {
			return err
		}
	}
}

// ExtractPaths restores the named archive paths, each with its subtree,
// below dir at their archive-relative location ("." is the whole archive).
// Parent directories of a path are created plain. Hardlinks are restored as
// copies, since the entry they link to may lie outside the selection.
func ExtractPaths(ctx context.Context, fsys *pxar.FS, paths []string, dir string, opts Options) error {
	for _, p := range paths {
		if !fs.ValidPath(p) {
			return fmt.Errorf("restore: invalid archive path %q", p)
		}
	}
	x, err := newExtractor(ctx, dir, opts)
	if err != nil {
		return err
	}
	defer x.root.Close()
	for _, p := range paths {
		if covered(p, paths) {
			continue
		}
		if parent := path.Dir(p); p != "." && parent != "." {
			if err := x.root.MkdirAll(filepath.FromSlash(parent), 0o755); err != nil {
				return fmt.Errorf("restore: %w", err)
			}
		}
		err := fs.WalkDir(fsys, p, func(name string, _ fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			info, err := fsys.Lstat(name)
			if err != nil {
				return err
			}
			n := info.Sys().(*pxar.Node)
			var content io.Reader
			if info.Mode().IsRegular() {
				f, err := fsys.Open(name)
				if err != nil {
					return err
				}
				defer f.Close()
				content = f
			}
			if name == "." {
				name = ""
			}
			return x.entry(n, name, content)
		})
		if err != nil {
			return err
		}
	}
	return x.finish()
}

// covered reports whether another requested path contains p.
func covered(p string, paths []string) bool {
	for _, q := range paths {
		if q != p && (q == "." || strings.HasPrefix(p, q+"/")) {
			return true
		}
	}
	return false
}

type extractor struct {
	ctx  context.Context
	root *os.Root
	w    MetadataWriter
	opts Options

	dirs []deferredDir // metadata applied by finish
	skip string        // subtree skipped for an unusable name
}

type deferredDir struct {
	name string
	n    *pxar.Node
}

func newExtractor(ctx context.Context, dir string, opts Options) (*extractor, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("restore: %w", err)
	}
	if !opts.Overwrite {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return nil, fmt.Errorf("restore: %w", err)
		}
		if len(entries) > 0 {
			return nil, ErrTargetNotEmpty
		}
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("restore: %w", err)
	}
	w := opts.Writer
	if w == nil {
		w = DefaultWriter()
	}
	return &extractor{ctx: ctx, root: root, w: w, opts: opts}, nil
}

func (x *extractor) warn(name string, err error) {
	if x.opts.OnWarn != nil {
		x.opts.OnWarn(Warning{Path: name, Err: err})
	}
}

// entry restores one entry; rel is its archive-relative path ("" for the
// root) and content the reader of a regular file's content.
func (x *extractor) entry(n *pxar.Node, rel string, content io.Reader) error {
	if err := x.ctx.Err(); err != nil {
		return err
	}
	name := rel
	if name == "" {
		name = "."
	}
	if x.skip != "" && strings.HasPrefix(name, x.skip+"/") {
		return nil
	}
	typ := n.Mode & typeMask
	if name != "." {
		if err := validName(path.Base(name)); err != nil {
			x.warn(name, err)
			if typ == modeDir {
				x.skip = name
			}
			return nil
		}
	}
	osName := filepath.FromSlash(name)

	if n.Hardlink {
		if err := x.clear(osName, false); err != nil {
			return err
		}
		if err := x.root.Link(filepath.FromSlash(n.LinkTarget), osName); err != nil {
			x.warn(name, fmt.Errorf("hardlink to %q: %w", n.LinkTarget, err))
		}
		return nil
	}

	switch typ {
	case modeDir:
		if name != "." {
			if err := x.clear(osName, true); err != nil {
				return err
			}
			if err := x.root.Mkdir(osName, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
				return fmt.Errorf("restore: %w", err)
			}
		}
		x.dirs = append(x.dirs, deferredDir{name, n})
		return nil
	case modeRegular:
		if err := x.clear(osName, false); err != nil {
			return err
		}
		f, err := x.root.OpenFile(osName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return fmt.Errorf("restore: %w", err)
		}
		var progress func(int)
		if x.opts.OnProgress != nil {
			progress = func(n int) { x.opts.OnProgress(name, n) }
		}
		_, err = io.Copy(f, ctxReader{x.ctx, content, progress})
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return fmt.Errorf("restore: %s: %w", name, err)
		}
	case modeSymlink:
		if err := x.clear(osName, false); err != nil {
			return err
		}
		if err := x.root.Symlink(n.LinkTarget, osName); err != nil {
			x.warn(name, err)
			return nil
		}
	default:
		if err := x.clear(osName, false); err != nil {
			return err
		}
		if err := x.w.Mknod(x.root, name, n); err != nil {
			x.warn(name, err)
			return nil
		}
	}
	x.w.Apply(x.root, name, n, func(err error) { x.warn(name, err) })
	return nil
}

// clear makes way for an entry when overwriting: an existing non-directory
// is removed; an existing directory is kept for a directory entry and an
// error otherwise. Without Overwrite nothing is touched, so a name that
// already exists (a duplicate in the archive) fails on creation.
func (x *extractor) clear(osName string, isDir bool) error {
	if !x.opts.Overwrite {
		return nil
	}
	fi, err := x.root.Lstat(osName)
	if err != nil {
		return nil
	}
	if fi.IsDir() {
		if isDir {
			return nil
		}
		return fmt.Errorf("restore: %s: a directory is in the way", osName)
	}
	if err := x.root.Remove(osName); err != nil {
		return fmt.Errorf("restore: %w", err)
	}
	return nil
}

// finish applies directory metadata, children before parents.
func (x *extractor) finish() error {
	for i := len(x.dirs) - 1; i >= 0; i-- {
		if err := x.ctx.Err(); err != nil {
			return err
		}
		d := x.dirs[i]
		x.w.Apply(x.root, d.name, d.n, func(err error) { x.warn(d.name, err) })
	}
	return nil
}

type ctxReader struct {
	ctx      context.Context
	r        io.Reader
	progress func(int) // nil: no reporting
}

func (c ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := c.r.Read(p)
	if n > 0 && c.progress != nil {
		c.progress(n)
	}
	return n, err
}

// st_mode type bits.
const (
	typeMask    = 0o170000
	modeSymlink = 0o120000
	modeRegular = 0o100000
	modeDir     = 0o040000
)
