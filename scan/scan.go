package scan

import (
	"fmt"
	"io"
	"path/filepath"
	"sort"

	"github.com/scheiblingco/gopbs/pxar"
)

// File-type bits of Stat.Mode (the universal S_IF* values; kept local so the
// portable core does not depend on platform packages).
const (
	ModeTypeMask uint64 = 0o170000
	ModeSocket   uint64 = 0o140000
	ModeSymlink  uint64 = 0o120000
	ModeRegular  uint64 = 0o100000
	ModeBlockDev uint64 = 0o060000
	ModeDir      uint64 = 0o040000
	ModeCharDev  uint64 = 0o020000
	ModeFifo     uint64 = 0o010000
)

// Kind classifies a node. Devices carry block/char in the Mode type bits.
type Kind int

const (
	KindDirectory Kind = iota
	KindFile
	KindSymlink
	KindHardlink
	KindBlockDevice
	KindCharDevice
	KindFifo
	KindSocket
	// KindStream is a virtual file entry backed by an io.Reader with a
	// caller-declared size.
	KindStream
)

// Node is one entry in a scanned tree. Metadata is captured at scan time;
// file contents are read later by the archive emitter.
type Node struct {
	Name string // basename within the parent (archive naming)
	Path string // absolute source path; empty for virtual nodes
	Kind Kind

	Stat Stat

	// LinkTarget holds the symlink target (KindSymlink) or the
	// archive-relative path of the hardlink's first occurrence (KindHardlink).
	LinkTarget string

	Xattrs      []Xattr
	ACL         *ACLs
	FCaps       []byte
	QuotaProjID uint64 // 0 = none
	Children    []*Node

	// Stream backs KindStream nodes; Stat.Size holds the declared size.
	Stream io.Reader
}

// Warning is a non-fatal scan event (skipped entry under SkipOnError).
type Warning struct {
	Path string
	Err  error
}

// Options configures a Scanner. The zero value scans with the platform
// default reader, fails on the first error, and reads quota project ids.
type Options struct {
	// Reader overrides the platform MetadataReader (used in tests and by
	// future non-Linux implementations).
	Reader MetadataReader
	// SkipOnError downgrades per-entry scan failures to warnings, omitting
	// the entry, instead of failing the scan.
	SkipOnError bool
	// OnWarn receives warnings; nil discards them.
	OnWarn func(Warning)
	// SkipQuotaProjIDs disables the per-node quota project id lookup, which
	// costs one open+ioctl per directory and regular file.
	SkipQuotaProjIDs bool
}

type devino struct{ dev, ino uint64 }

// Scanner walks filesystem trees into Node trees. A single Scanner may scan
// several roots (multiple AddDirectory/AddFile calls); hardlink identity is
// tracked across all of them so cross-root hardlinks resolve correctly.
type Scanner struct {
	opts      Options
	r         MetadataReader
	hardlinks map[devino]string // (dev, ino) -> archive path of first occurrence
}

// NewScanner returns a Scanner for the given options. It fails on platforms
// without a default MetadataReader when none is supplied.
func NewScanner(opts Options) (*Scanner, error) {
	r := opts.Reader
	if r == nil {
		var err error
		if r, err = DefaultReader(); err != nil {
			return nil, err
		}
	}
	return &Scanner{opts: opts, r: r, hardlinks: make(map[devino]string)}, nil
}

// ScanDirectory scans the tree rooted at path. archivePath is the node's
// path within the archive ("" when this directory is the archive root); it
// prefixes the recorded hardlink targets of everything below.
func (s *Scanner) ScanDirectory(path, archivePath string) (*Node, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("scan %s: %w", path, err)
	}
	st, err := s.r.Lstat(abs)
	if err != nil {
		return nil, fmt.Errorf("scan %s: %w", abs, err)
	}
	if st.Mode&ModeTypeMask != ModeDir {
		return nil, fmt.Errorf("scan %s: not a directory", abs)
	}
	return s.scanNode(abs, filepath.Base(abs), archivePath, st)
}

// ScanFile scans a single non-directory entry (top-level AddFile).
func (s *Scanner) ScanFile(path, archivePath string) (*Node, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("scan %s: %w", path, err)
	}
	st, err := s.r.Lstat(abs)
	if err != nil {
		return nil, fmt.Errorf("scan %s: %w", abs, err)
	}
	if st.Mode&ModeTypeMask == ModeDir {
		return nil, fmt.Errorf("scan %s: is a directory", abs)
	}
	return s.scanNode(abs, filepath.Base(abs), archivePath, st)
}

func (s *Scanner) scanNode(abs, name, archivePath string, st Stat) (*Node, error) {
	n := &Node{Name: name, Path: abs, Stat: st}

	switch st.Mode & ModeTypeMask {
	case ModeDir:
		n.Kind = KindDirectory
		if err := s.readExtras(n, true); err != nil {
			return nil, err
		}
		names, err := s.r.ReadDirNames(abs)
		if err != nil {
			return nil, fmt.Errorf("scan %s: %w", abs, err)
		}
		for _, childName := range names {
			childAbs := filepath.Join(abs, childName)
			child, err := s.scanChild(childAbs, childName, joinArchive(archivePath, childName))
			if err != nil {
				if s.opts.SkipOnError {
					s.warn(childAbs, err)
					continue
				}
				return nil, err
			}
			n.Children = append(n.Children, child)
		}
		return n, nil

	case ModeRegular:
		// Hardlink tracking applies to regular files, matching the upstream
		// encoder: the second occurrence of an inode becomes a hardlink
		// entry referencing the first.
		if st.Nlink > 1 {
			key := devino{st.Dev, st.Ino}
			if target, seen := s.hardlinks[key]; seen {
				n.Kind = KindHardlink
				n.LinkTarget = target
				return n, nil
			}
			s.hardlinks[key] = archivePath
		}
		n.Kind = KindFile
		if err := s.readExtras(n, true); err != nil {
			return nil, err
		}
		return n, nil

	case ModeSymlink:
		n.Kind = KindSymlink
		target, err := s.r.Readlink(abs)
		if err != nil {
			return nil, fmt.Errorf("scan %s: %w", abs, err)
		}
		n.LinkTarget = target
		return n, nil

	case ModeBlockDev:
		n.Kind = KindBlockDevice
		return n, s.readExtras(n, false)
	case ModeCharDev:
		n.Kind = KindCharDevice
		return n, s.readExtras(n, false)
	case ModeFifo:
		n.Kind = KindFifo
		return n, s.readExtras(n, false)
	case ModeSocket:
		n.Kind = KindSocket
		return n, s.readExtras(n, false)
	}

	return nil, fmt.Errorf("scan %s: unsupported file type %o", abs, st.Mode&ModeTypeMask)
}

func (s *Scanner) scanChild(abs, name, archivePath string) (*Node, error) {
	if err := pxar.ValidateFilename(name); err != nil {
		return nil, fmt.Errorf("scan %s: %w", abs, err)
	}
	st, err := s.r.Lstat(abs)
	if err != nil {
		return nil, fmt.Errorf("scan %s: %w", abs, err)
	}
	return s.scanNode(abs, name, archivePath, st)
}

// readExtras fills xattrs and ACLs (all kinds it is called for), plus fcaps
// (regular files) and quota project ids (directories and regular files) when
// fidelity is requested.
func (s *Scanner) readExtras(n *Node, fidelity bool) error {
	var err error
	if n.Xattrs, err = s.r.Xattrs(n.Path); err != nil {
		return fmt.Errorf("scan %s: xattrs: %w", n.Path, err)
	}
	if n.ACL, err = s.r.ACLs(n.Path); err != nil {
		return fmt.Errorf("scan %s: acls: %w", n.Path, err)
	}
	if !fidelity {
		return nil
	}
	if n.Kind == KindFile {
		if n.FCaps, err = s.r.FCaps(n.Path); err != nil {
			return fmt.Errorf("scan %s: fcaps: %w", n.Path, err)
		}
	}
	if !s.opts.SkipQuotaProjIDs {
		id, ok, err := s.r.QuotaProjID(n.Path)
		if err != nil {
			return fmt.Errorf("scan %s: quota project id: %w", n.Path, err)
		}
		if ok {
			n.QuotaProjID = id
		}
	}
	return nil
}

func (s *Scanner) warn(path string, err error) {
	if s.opts.OnWarn != nil {
		s.opts.OnWarn(Warning{Path: path, Err: err})
	}
}

func joinArchive(prefix, name string) string {
	if prefix == "" {
		return name
	}
	return prefix + "/" + name
}

// StreamNode returns a virtual regular-file node backed by r with the
// declared size. The pad/truncate policy applies if r yields a different
// byte count. Mode is a plain 0644 regular file owned by uid/gid 0; the
// caller may adjust Stat before planning.
func StreamNode(name string, size int64, r io.Reader) (*Node, error) {
	if err := pxar.ValidateFilename(name); err != nil {
		return nil, err
	}
	if size < 0 {
		return nil, fmt.Errorf("scan: negative stream size %d", size)
	}
	return &Node{
		Name:   name,
		Kind:   KindStream,
		Stat:   Stat{Mode: ModeRegular | 0o644, Size: size, Nlink: 1},
		Stream: r,
	}, nil
}

// VirtualRoot synthesizes the top-level directory used when an archive holds
// multiple roots or bare files: mode drwxrwxrwx, uid/gid 0. Children are
// sorted into archive order; names must be unique. The caller stamps the
// mtime (plan time).
func VirtualRoot(name string, children []*Node) (*Node, error) {
	seen := make(map[string]bool, len(children))
	for _, c := range children {
		if err := pxar.ValidateFilename(c.Name); err != nil {
			return nil, err
		}
		if seen[c.Name] {
			return nil, fmt.Errorf("scan: duplicate top-level name %q", c.Name)
		}
		seen[c.Name] = true
	}
	sorted := make([]*Node, len(children))
	copy(sorted, children)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })

	return &Node{
		Name:     name,
		Kind:     KindDirectory,
		Stat:     Stat{Mode: ModeDir | 0o777, Nlink: 1},
		Children: sorted,
	}, nil
}
