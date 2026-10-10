package pxar

import (
	"bufio"
	"cmp"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"slices"
	"strings"
	"syscall"
	"time"
)

// FS is a read-only, random-access view of an archive as an io/fs file
// system. It implements fs.FS, fs.ReadDirFS, fs.StatFS and fs.ReadLinkFS.
//
// Paths are looked up through the directories' goodbye tables, so only the
// records on the way are read: over a remote index (see pbs
// OpenDynamicIndexAt) a lookup fetches a handful of chunks, not the archive.
// Listing a v2 directory reads the metadata stream only; payload records are
// checked when a file is opened.
//
// Open and Stat follow symbolic links inside the archive; links with an
// absolute target, or a relative one leaving the archive, do not resolve.
// A hardlink resolves to the entry it links to, under its own name.
// FileInfo.Sys returns the *Node with the full metadata.
//
// The file system is safe for concurrent use if its io.ReaderAt sources are.
type FS struct {
	meta    io.ReaderAt
	payload io.ReaderAt
	version int
	root    *fsNode
}

const maxGoodbye = 64 << 20

// fsNode is a decoded entry and where it lives.
type fsNode struct {
	*Node
	name string // base name it was reached by ("." for the root)

	start, end int64 // directories: the span in the metadata stream
	content    int64 // v1 regular files: content offset in the archive
}

// OpenV1 opens a pxar v1 archive of the given size.
func OpenV1(r io.ReaderAt, size int64) (*FS, error) {
	return open(r, size, nil, 1)
}

// OpenV2 opens a v2 split archive: the metadata stream of metaSize bytes
// and the payload stream. payload may be nil when only metadata is needed;
// opening a regular file then fails.
func OpenV2(meta io.ReaderAt, metaSize int64, payload io.ReaderAt) (*FS, error) {
	if payload != nil {
		if err := checkPayloadStart(payload); err != nil {
			return nil, err
		}
	}
	return open(meta, metaSize, payload, 2)
}

func open(meta io.ReaderAt, size int64, payload io.ReaderAt, version int) (*FS, error) {
	f := &FS{meta: meta, payload: payload, version: version}
	r := &Reader{br: bufio.NewReaderSize(io.NewSectionReader(meta, 0, size), 4096), version: version}
	n, err := r.Next()
	if err != nil {
		return nil, err
	}
	if n.Mode&modeTypeMask != modeDir {
		return nil, errors.New("pxar: archive root is not a directory")
	}
	f.root = &fsNode{Node: n, name: ".", start: 0, end: size}
	return f, nil
}

// goodbye returns the start offsets and lengths of a directory's children,
// in archive order, and where its goodbye record begins.
func (f *FS) goodbye(d *fsNode) (items [][3]uint64, gbStart int64, err error) {
	var tail [24]byte
	if d.end-d.start < HeaderSize+24 {
		return nil, 0, fmt.Errorf("pxar: directory %q: span too short", d.Path)
	}
	if _, err := f.meta.ReadAt(tail[:], d.end-24); err != nil {
		return nil, 0, fmt.Errorf("pxar: directory %q: goodbye tail: %w", d.Path, err)
	}
	length := binary.LittleEndian.Uint64(tail[16:])
	if binary.LittleEndian.Uint64(tail[:]) != GoodbyeTailMarker ||
		length < HeaderSize+24 || (length-HeaderSize)%24 != 0 || length > uint64(d.end-d.start) {
		return nil, 0, fmt.Errorf("pxar: directory %q: malformed goodbye table", d.Path)
	}
	// ponytail: the whole table is read per lookup and capped at ~2.8M
	// children; stream it in slices if larger directories ever matter.
	if length > maxGoodbye {
		return nil, 0, fmt.Errorf("pxar: directory %q: goodbye table of %d bytes exceeds the limit", d.Path, length)
	}
	gbStart = d.end - int64(length)
	table := make([]byte, length)
	if _, err := f.meta.ReadAt(table, gbStart); err != nil {
		return nil, 0, fmt.Errorf("pxar: directory %q: goodbye table: %w", d.Path, err)
	}
	if binary.LittleEndian.Uint64(table) != TypeGoodbye || binary.LittleEndian.Uint64(table[8:]) != length {
		return nil, 0, fmt.Errorf("pxar: directory %q: malformed goodbye table", d.Path)
	}
	table = table[HeaderSize : length-24]
	for i := 0; i < len(table); i += 24 {
		hash := binary.LittleEndian.Uint64(table[i:])
		off := binary.LittleEndian.Uint64(table[i+8:])
		size := binary.LittleEndian.Uint64(table[i+16:])
		start := uint64(gbStart) - off
		// Children lie between the directory's own entry and its goodbye.
		if off == 0 || off >= uint64(gbStart-d.start) || size == 0 || size > 1<<62 {
			return nil, 0, fmt.Errorf("pxar: directory %q: goodbye item out of range", d.Path)
		}
		items = append(items, [3]uint64{hash, start, size})
	}
	slices.SortFunc(items, func(a, b [3]uint64) int { return cmp.Compare(a[1], b[1]) })
	return items, gbStart, nil
}

// child decodes the child whose filename record starts at item[1].
func (f *FS) child(d *fsNode, item [3]uint64, gbStart int64) (*fsNode, error) {
	start := int64(item[1])
	r := &Reader{
		br:      bufio.NewReaderSize(io.NewSectionReader(f.meta, start, gbStart-start), 4096),
		version: f.version,
		started: true,
		dirs:    []string{d.Path},
	}
	n, err := r.next()
	if err != nil {
		return nil, err
	}
	c := &fsNode{Node: n, name: path.Base(n.Path)}
	switch {
	case n.Hardlink:
	case n.Mode&modeTypeMask == modeDir:
		c.start, c.end = start, start+int64(item[2])
		if c.end > gbStart {
			return nil, fmt.Errorf("pxar: directory %q exceeds its parent", n.Path)
		}
	case n.Mode&modeTypeMask == modeRegular && f.version == 1:
		c.content = start + int64(r.pos)
		if c.content+int64(n.Size) > gbStart || n.Size > 1<<62 {
			return nil, fmt.Errorf("pxar: content of %q exceeds its directory", n.Path)
		}
	}
	return c, nil
}

// lookupChild finds a directory's child by name; a hardlink is returned
// as is.
func (f *FS) lookupChild(d *fsNode, name string) (*fsNode, error) {
	items, gbStart, err := f.goodbye(d)
	if err != nil {
		return nil, err
	}
	// Hash collisions are possible: check every matching item's name.
	h := Hash(name)
	for _, it := range items {
		if it[0] != h {
			continue
		}
		c, err := f.child(d, it, gbStart)
		if err != nil {
			return nil, err
		}
		if c.name == name {
			return c, nil
		}
	}
	return nil, fs.ErrNotExist
}

// resolveHardlink returns the entry a hardlink links to, under the link's
// name.
func (f *FS) resolveHardlink(c *fsNode) (*fsNode, error) {
	if !c.Hardlink {
		return c, nil
	}
	t, err := f.resolve(c.LinkTarget, false, true)
	if err != nil {
		return nil, fmt.Errorf("pxar: hardlink %q: target %q: %w", c.Path, c.LinkTarget, err)
	}
	if t.Mode&modeTypeMask == modeDir {
		return nil, fmt.Errorf("pxar: hardlink %q targets a directory", c.Path)
	}
	return &fsNode{Node: t.Node, name: c.name, content: t.content}, nil
}

// resolve walks an archive path, following symlinks on the way and, when
// follow is set, at the end. Hardlinks resolve to their target; a hardlink
// met while resolving one (nested) is an error, so they cannot loop.
func (f *FS) resolve(name string, follow, nested bool) (*fsNode, error) {
	cur, rest, links := f.root, name, 0
	if rest == "." {
		rest = ""
	}
	for rest != "" {
		comp, after, _ := strings.Cut(rest, "/")
		if cur.Mode&modeTypeMask != modeDir {
			return nil, syscall.ENOTDIR
		}
		c, err := f.lookupChild(cur, comp)
		if err != nil {
			return nil, err
		}
		if c.Hardlink {
			if nested {
				return nil, fmt.Errorf("pxar: hardlink %q targets another hardlink", c.Path)
			}
			if c, err = f.resolveHardlink(c); err != nil {
				return nil, err
			}
		}
		if c.Mode&modeTypeMask == modeSymlink && (after != "" || follow) {
			if links++; links > 40 {
				return nil, errors.New("too many levels of symbolic links")
			}
			target := path.Join(cur.Path, c.LinkTarget)
			if path.IsAbs(c.LinkTarget) || target == ".." || strings.HasPrefix(target, "../") {
				return nil, fs.ErrNotExist // leaves the archive
			}
			if target == "." {
				target = ""
			}
			if rest = target; after != "" {
				rest = strings.TrimPrefix(target+"/"+after, "/")
			}
			cur = f.root
			continue
		}
		cur, rest = c, after
	}
	return cur, nil
}

func (f *FS) lookup(op, name string, follow bool) (*fsNode, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: op, Path: name, Err: fs.ErrInvalid}
	}
	n, err := f.resolve(name, follow, false)
	if err != nil {
		return nil, &fs.PathError{Op: op, Path: name, Err: err}
	}
	named := *n // the root is shared
	if name != "." {
		named.name = path.Base(name)
	}
	return &named, nil
}

// Open opens the named file, following symbolic links.
func (f *FS) Open(name string) (fs.File, error) {
	n, err := f.lookup("open", name, true)
	if err != nil {
		return nil, err
	}
	switch n.Mode & modeTypeMask {
	case modeDir:
		return &dirFile{fs: f, n: n}, nil
	case modeRegular:
		src, off := f.meta, n.content
		if f.version == 2 {
			if f.payload == nil {
				return nil, &fs.PathError{Op: "open", Path: name, Err: errors.New("no payload stream")}
			}
			if err := checkPayloadRecord(f.payload, n.Node); err != nil {
				return nil, &fs.PathError{Op: "open", Path: name, Err: err}
			}
			src, off = f.payload, int64(n.PayloadOffset)+HeaderSize
		}
		return &file{n: n, SectionReader: io.NewSectionReader(src, off, int64(n.Size))}, nil
	}
	return &file{n: n, SectionReader: io.NewSectionReader(nil, 0, 0)}, nil
}

// Stat returns a FileInfo for the named file, following symbolic links.
func (f *FS) Stat(name string) (fs.FileInfo, error) {
	n, err := f.lookup("stat", name, true)
	if err != nil {
		return nil, err
	}
	return info{n}, nil
}

// Lstat returns a FileInfo for the named file without following a final
// symbolic link.
func (f *FS) Lstat(name string) (fs.FileInfo, error) {
	n, err := f.lookup("lstat", name, false)
	if err != nil {
		return nil, err
	}
	return info{n}, nil
}

// ReadLink returns the target of the named symbolic link.
func (f *FS) ReadLink(name string) (string, error) {
	n, err := f.lookup("readlink", name, false)
	if err != nil {
		return "", err
	}
	if n.Mode&modeTypeMask != modeSymlink {
		return "", &fs.PathError{Op: "readlink", Path: name, Err: fs.ErrInvalid}
	}
	return n.LinkTarget, nil
}

// ReadDir reads the named directory, following symbolic links, and returns
// its entries sorted by name.
func (f *FS) ReadDir(name string) ([]fs.DirEntry, error) {
	n, err := f.lookup("readdir", name, true)
	if err != nil {
		return nil, err
	}
	d := &dirFile{fs: f, n: n}
	return d.ReadDir(-1)
}

type info struct{ n *fsNode }

func (i info) Name() string       { return i.n.name }
func (i info) Size() int64        { return int64(i.n.Size) }
func (i info) Mode() fs.FileMode  { return FileMode(i.n.Mode) }
func (i info) ModTime() time.Time { return time.Unix(i.n.MtimeSecs, int64(i.n.MtimeNanos)) }
func (i info) IsDir() bool        { return i.n.Mode&modeTypeMask == modeDir }
func (i info) Sys() any           { return i.n.Node }

// FileMode converts an st_mode value to an fs.FileMode.
func FileMode(mode uint64) fs.FileMode {
	m := fs.FileMode(mode & 0o777)
	if mode&0o4000 != 0 {
		m |= fs.ModeSetuid
	}
	if mode&0o2000 != 0 {
		m |= fs.ModeSetgid
	}
	if mode&0o1000 != 0 {
		m |= fs.ModeSticky
	}
	switch mode & modeTypeMask {
	case modeDir:
		m |= fs.ModeDir
	case modeSymlink:
		m |= fs.ModeSymlink
	case modeBlockDev:
		m |= fs.ModeDevice
	case modeCharDev:
		m |= fs.ModeDevice | fs.ModeCharDevice
	case modeFifo:
		m |= fs.ModeNamedPipe
	case modeSocket:
		m |= fs.ModeSocket
	}
	return m
}

// file is an open non-directory. Regular files support Read, ReadAt and
// Seek; content cut short by the source is an error, not io.EOF.
type file struct {
	n *fsNode
	*io.SectionReader
}

func (f *file) Stat() (fs.FileInfo, error) { return info{f.n}, nil }
func (f *file) Close() error               { return nil }

func (f *file) Read(p []byte) (int, error) {
	pos, _ := f.Seek(0, io.SeekCurrent)
	n, err := f.SectionReader.Read(p)
	return n, short(err, pos+int64(n), f.Size())
}

func (f *file) ReadAt(p []byte, off int64) (int, error) {
	n, err := f.SectionReader.ReadAt(p, off)
	return n, short(err, off+int64(n), min(off+int64(len(p)), f.Size()))
}

func short(err error, reached, want int64) error {
	if err == io.EOF && reached < want {
		return io.ErrUnexpectedEOF
	}
	return err
}

type dirFile struct {
	fs      *FS
	n       *fsNode
	entries []fs.DirEntry
	loaded  bool
}

func (d *dirFile) Stat() (fs.FileInfo, error) { return info{d.n}, nil }
func (d *dirFile) Close() error               { return nil }
func (d *dirFile) Read([]byte) (int, error) {
	return 0, &fs.PathError{Op: "read", Path: d.n.Path, Err: fs.ErrInvalid}
}

// ReadDir follows fs.ReadDirFile: n > 0 returns at most n entries and
// io.EOF at the end, n <= 0 returns all remaining entries.
func (d *dirFile) ReadDir(n int) ([]fs.DirEntry, error) {
	if !d.loaded {
		items, gbStart, err := d.fs.goodbye(d.n)
		if err != nil {
			return nil, err
		}
		for _, it := range items {
			c, err := d.fs.child(d.n, it, gbStart)
			if err == nil {
				c, err = d.fs.resolveHardlink(c)
			}
			if err != nil {
				return nil, err
			}
			d.entries = append(d.entries, fs.FileInfoToDirEntry(info{c}))
		}
		slices.SortFunc(d.entries, func(a, b fs.DirEntry) int { return strings.Compare(a.Name(), b.Name()) })
		d.loaded = true
	}
	if n <= 0 {
		out := d.entries
		d.entries = nil
		return out, nil
	}
	if len(d.entries) == 0 {
		return nil, io.EOF
	}
	n = min(n, len(d.entries))
	out := d.entries[:n]
	d.entries = d.entries[n:]
	return out, nil
}
