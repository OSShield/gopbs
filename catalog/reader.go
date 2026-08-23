package catalog

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// Entry is one decoded catalog entry. Directories carry Children; files
// carry Size and MtimeSecs. Decode returns a synthetic root directory whose
// children are the archive entries.
type Entry struct {
	Name      string
	Type      byte
	Size      uint64
	MtimeSecs int64
	Children  []*Entry
}

// Child returns the named child of a directory entry, or nil.
func (e *Entry) Child(name string) *Entry {
	for _, c := range e.Children {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// Decode parses a complete .pcat1 catalog.
func Decode(data []byte) (*Entry, error) {
	if len(data) < len(Magic)+8 || !bytes.Equal(data[:len(Magic)], Magic) {
		return nil, fmt.Errorf("catalog: bad magic or truncated file")
	}
	rootPos := binary.LittleEndian.Uint64(data[len(data)-8:])
	if rootPos < 8 || rootPos >= uint64(len(data)-8) {
		return nil, fmt.Errorf("catalog: root table pointer %d out of range", rootPos)
	}
	root := &Entry{Type: TypeDirectory}
	if err := decodeTable(data, rootPos, root, 0); err != nil {
		return nil, err
	}
	return root, nil
}

// maxDepth bounds directory nesting during decoding. Legitimate nesting is
// limited by PATH_MAX (≈2048 single-character components); the bound exists
// so a corrupt catalog cannot recurse the decoder into a stack overflow.
const maxDepth = 4096

func decodeTable(data []byte, pos uint64, dir *Entry, depth int) error {
	if depth > maxDepth {
		return fmt.Errorf("catalog: directory nesting exceeds %d levels", maxDepth)
	}
	if pos >= uint64(len(data)) {
		return fmt.Errorf("catalog: table position %d out of range", pos)
	}
	tableLen, n, err := decodeU64(data[pos:])
	if err != nil {
		return err
	}
	table := data[pos+uint64(n):]
	if tableLen > uint64(len(table)) {
		return fmt.Errorf("catalog: table at %d overruns file", pos)
	}
	table = table[:tableLen]

	count, n, err := decodeU64(table)
	if err != nil {
		return err
	}
	table = table[n:]

	for i := uint64(0); i < count; i++ {
		if len(table) < 1 {
			return fmt.Errorf("catalog: truncated entry in table at %d", pos)
		}
		e := &Entry{Type: table[0]}
		table = table[1:]

		nameLen, n, err := decodeU64(table)
		if err != nil {
			return err
		}
		table = table[n:]
		if nameLen > uint64(len(table)) {
			return fmt.Errorf("catalog: entry name overruns table at %d", pos)
		}
		e.Name = string(table[:nameLen])
		table = table[nameLen:]

		switch e.Type {
		case TypeDirectory:
			delta, n, err := decodeU64(table)
			if err != nil {
				return err
			}
			table = table[n:]
			// Tables are written bottom-up: a child table lies strictly
			// before its parent. Delta 0 would alias the current table and
			// recurse forever on corrupt input.
			if delta == 0 || delta > pos {
				return fmt.Errorf("catalog: %q: child table delta %d out of range", e.Name, delta)
			}
			if err := decodeTable(data, pos-delta, e, depth+1); err != nil {
				return err
			}
		case TypeFile:
			var size uint64
			if size, n, err = decodeU64(table); err != nil {
				return err
			}
			table = table[n:]
			var mtime int64
			if mtime, n, err = decodeI64(table); err != nil {
				return err
			}
			table = table[n:]
			e.Size, e.MtimeSecs = size, mtime
		case TypeSymlink, TypeHardlink, TypeBlockDevice, TypeCharDevice, TypeFifo, TypeSocket:
			// name-only entries
		default:
			return fmt.Errorf("catalog: unknown entry type %#x in table at %d", e.Type, pos)
		}
		dir.Children = append(dir.Children, e)
	}
	return nil
}
