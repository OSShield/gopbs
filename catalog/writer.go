package catalog

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Magic identifies a .pcat1 catalog (PROXMOX_CATALOG_FILE_MAGIC_1_0).
var Magic = []byte{145, 253, 96, 249, 196, 103, 88, 213}

// Entry type bytes as stored on disk.
const (
	TypeDirectory   = 'd'
	TypeFile        = 'f'
	TypeSymlink     = 'l'
	TypeHardlink    = 'h'
	TypeBlockDevice = 'b'
	TypeCharDevice  = 'c'
	TypeFifo        = 'p'
	TypeSocket      = 's'
)

type entry struct {
	typ   byte
	name  string
	size  uint64 // TypeFile
	mtime int64  // TypeFile
	start uint64 // TypeDirectory: absolute position of the child's table
}

type dirInfo struct {
	name    string
	entries []entry
}

// Writer streams a .pcat1 catalog. Directory tables are written bottom-up as
// directories close, so parents reference children by backward delta; entries
// within a table appear in the order they were added (canonical: sorted walk
// order, directories recorded when they close).
//
// Usage: NewWriter, StartDirectory(archiveName), Add*/nested directories,
// EndDirectory, Finish. The top-level directory conventionally carries the
// archive's index name (e.g. "root.pxar.didx"); a catalog may hold several.
type Writer struct {
	w     io.Writer
	pos   uint64
	stack []*dirInfo // stack[0] is the root (archive list) table
}

// NewWriter writes the magic and returns a Writer positioned at the root.
func NewWriter(w io.Writer) (*Writer, error) {
	if _, err := w.Write(Magic); err != nil {
		return nil, fmt.Errorf("catalog: %w", err)
	}
	return &Writer{w: w, pos: 8, stack: []*dirInfo{{}}}, nil
}

// StartDirectory opens a directory (or, at the top level, an archive entry).
func (c *Writer) StartDirectory(name string) error {
	if err := checkName(name); err != nil {
		return err
	}
	c.stack = append(c.stack, &dirInfo{name: name})
	return nil
}

// EndDirectory encodes and writes the current directory's table and records
// it in the parent.
func (c *Writer) EndDirectory() error {
	if len(c.stack) < 2 {
		return errors.New("catalog: EndDirectory without matching StartDirectory")
	}
	dir := c.stack[len(c.stack)-1]
	c.stack = c.stack[:len(c.stack)-1]

	start := c.pos
	if err := c.writeTable(dir, start); err != nil {
		return err
	}
	parent := c.stack[len(c.stack)-1]
	parent.entries = append(parent.entries, entry{typ: TypeDirectory, name: dir.name, start: start})
	return nil
}

// AddFile records a regular file in the current directory.
func (c *Writer) AddFile(name string, size uint64, mtimeSecs int64) error {
	return c.add(entry{typ: TypeFile, name: name, size: size, mtime: mtimeSecs})
}

// AddSymlink, AddHardlink, AddBlockDevice, AddCharDevice, AddFifo and
// AddSocket record name-only entries of the respective type.
func (c *Writer) AddSymlink(name string) error  { return c.add(entry{typ: TypeSymlink, name: name}) }
func (c *Writer) AddHardlink(name string) error { return c.add(entry{typ: TypeHardlink, name: name}) }
func (c *Writer) AddBlockDevice(name string) error {
	return c.add(entry{typ: TypeBlockDevice, name: name})
}
func (c *Writer) AddCharDevice(name string) error {
	return c.add(entry{typ: TypeCharDevice, name: name})
}
func (c *Writer) AddFifo(name string) error   { return c.add(entry{typ: TypeFifo, name: name}) }
func (c *Writer) AddSocket(name string) error { return c.add(entry{typ: TypeSocket, name: name}) }

func (c *Writer) add(e entry) error {
	if err := checkName(e.name); err != nil {
		return err
	}
	if len(c.stack) < 2 {
		return fmt.Errorf("catalog: entry %q added outside a directory", e.name)
	}
	dir := c.stack[len(c.stack)-1]
	dir.entries = append(dir.entries, e)
	return nil
}

// Finish writes the root table and the trailing little-endian u64 pointing
// at it. The Writer is unusable afterwards.
func (c *Writer) Finish() error {
	if len(c.stack) != 1 {
		return fmt.Errorf("catalog: Finish with %d unclosed directories", len(c.stack)-1)
	}
	root := c.stack[0]
	c.stack = nil

	start := c.pos
	if err := c.writeTable(root, start); err != nil {
		return err
	}
	var trailer [8]byte
	binary.LittleEndian.PutUint64(trailer[:], start)
	return c.write(trailer[:])
}

// writeTable encodes one directory table at position start:
// uvarint(len(table)) followed by table = uvarint(entryCount) + entries.
// Directory entries store the backward delta start - child.start.
func (c *Writer) writeTable(dir *dirInfo, start uint64) error {
	table := appendU64(nil, uint64(len(dir.entries)))
	for _, e := range dir.entries {
		table = append(table, e.typ)
		table = appendU64(table, uint64(len(e.name)))
		table = append(table, e.name...)
		switch e.typ {
		case TypeDirectory:
			table = appendU64(table, start-e.start)
		case TypeFile:
			table = appendU64(table, e.size)
			table = appendI64(table, e.mtime)
		}
	}
	out := appendU64(nil, uint64(len(table)))
	return c.write(append(out, table...))
}

func (c *Writer) write(p []byte) error {
	n, err := c.w.Write(p)
	c.pos += uint64(n)
	if err != nil {
		return fmt.Errorf("catalog: %w", err)
	}
	return nil
}

func checkName(name string) error {
	if name == "" {
		return errors.New("catalog: empty entry name")
	}
	for i := 0; i < len(name); i++ {
		if name[i] == '/' || name[i] == 0 {
			return fmt.Errorf("catalog: invalid entry name %q", name)
		}
	}
	return nil
}
