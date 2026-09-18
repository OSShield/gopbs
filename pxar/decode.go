package pxar

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// MetaFile is one regular file found while decoding a pxar metadata stream.
type MetaFile struct {
	// Path is the archive-relative path ("" for the root, "dir/name" below it).
	Path string
	// Meta is the file's ENTRY record followed by its metadata records
	// (xattrs, ACLs, fcaps, quota project id), byte for byte as encoded.
	Meta []byte
	// Size is the content byte count.
	Size uint64
	// PayloadOffset is the position of the file's payload record header in
	// the payload stream (v2 only; 0 in a v1 archive).
	PayloadOffset uint64
}

// st_mode type bits (Linux S_IFMT and friends), needed to walk the tree.
const (
	modeTypeMask = 0o170000
	modeSocket   = 0o140000
	modeSymlink  = 0o120000
	modeRegular  = 0o100000
	modeBlockDev = 0o060000
	modeDir      = 0o040000
	modeCharDev  = 0o020000
	modeFifo     = 0o010000
)

// DecodeMetadata walks a pxar v1 archive or v2 metadata stream in order and
// calls visit for every regular file with its encoded metadata and payload
// reference. Payload content of a v1 archive is skipped. It returns the
// format version (1 or 2). Change detection uses it to index the previous
// snapshot's metadata stream.
func DecodeMetadata(r io.Reader, visit func(MetaFile) error) (version int, err error) {
	d := &decoder{r: bufio.NewReaderSize(r, 256<<10), visit: visit}
	version = 1
	typ, length, err := d.peek()
	if err != nil {
		return 0, err
	}
	if typ == TypeFormatVersion {
		body, err := d.body(length)
		if err != nil {
			return 0, err
		}
		if len(body) != 8 {
			return 0, fmt.Errorf("pxar: format version record has %d body bytes", len(body))
		}
		version = int(binary.LittleEndian.Uint64(body))
		if version != 2 {
			return 0, fmt.Errorf("pxar: unsupported format version %d", version)
		}
		typ, length, err = d.peek()
		if err != nil {
			return 0, err
		}
		if typ == TypePrelude {
			if _, err := d.body(length); err != nil {
				return 0, err
			}
		}
	}
	if err := d.node("", true); err != nil {
		return 0, err
	}
	return version, nil
}

type decoder struct {
	r     *bufio.Reader
	visit func(MetaFile) error

	// one-record lookahead
	have   bool
	typ    uint64
	length uint64
	pos    uint64
}

// peek reads the next record header without consuming it
func (d *decoder) peek() (typ, length uint64, err error) {
	if d.have {
		return d.typ, d.length, nil
	}
	var hdr [HeaderSize]byte
	if _, err := io.ReadFull(d.r, hdr[:]); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return 0, 0, fmt.Errorf("pxar: truncated archive at %d", d.pos)
		}
		return 0, 0, err
	}
	d.typ = binary.LittleEndian.Uint64(hdr[:])
	d.length = binary.LittleEndian.Uint64(hdr[8:])
	if d.length < HeaderSize {
		return 0, 0, fmt.Errorf("pxar: record %#x at %d: bad length %d", d.typ, d.pos, d.length)
	}
	d.have = true
	return d.typ, d.length, nil
}

// body consumes the peeked record and returns its body
func (d *decoder) body(length uint64) ([]byte, error) {
	if !d.have {
		return nil, errors.New("pxar: internal: body without header")
	}
	n := length - HeaderSize
	if n > 1<<31 {
		return nil, fmt.Errorf("pxar: record %#x at %d too large (%d bytes)", d.typ, d.pos, n)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(d.r, body); err != nil {
		return nil, fmt.Errorf("pxar: truncated record %#x at %d: %w", d.typ, d.pos, err)
	}
	d.have = false
	d.pos += length
	return body, nil
}

// raw consumes the peeked record and returns it whole (header + body)
func (d *decoder) raw(dst []byte, length uint64) ([]byte, error) {
	typ := d.typ
	body, err := d.body(length)
	if err != nil {
		return nil, err
	}
	dst = appendHeader(dst, typ, length)
	return append(dst, body...), nil
}

// skip consumes the peeked record without keeping its body
func (d *decoder) skip(length uint64) error {
	if !d.have {
		return errors.New("pxar: internal: skip without header")
	}
	if _, err := io.CopyN(io.Discard, d.r, int64(length-HeaderSize)); err != nil {
		return fmt.Errorf("pxar: truncated record %#x at %d: %w", d.typ, d.pos, err)
	}
	d.have = false
	d.pos += length
	return nil
}

func isMetadataRecord(typ uint64) bool {
	switch typ {
	case TypeXAttr, TypeACLUser, TypeACLGroup, TypeACLGroupObj, TypeACLDefault, TypeACLDefaultUser, TypeACLDefaultGroup, TypeFCaps, TypeQuotaProjID:
		return true
	}
	return false
}

func (d *decoder) node(path string, isRoot bool) error {
	typ, length, err := d.peek()
	if err != nil {
		return err
	}
	if !isRoot {
		if typ != TypeFilename {
			return fmt.Errorf("pxar: expected filename record at %d, got %#x", d.pos, typ)
		}
		body, err := d.body(length)
		if err != nil {
			return err
		}
		if len(body) == 0 || body[len(body)-1] != 0 {
			return fmt.Errorf("pxar: filename record at %d is not NUL-terminated", d.pos)
		}
		name := string(body[:len(body)-1])
		if path == "" {
			path = name
		} else {
			path += "/" + name
		}
		if typ, length, err = d.peek(); err != nil {
			return err
		}
	}
	if typ == TypeHardlink {
		return d.skip(length)
	}
	if typ == TypeEntryV1 {
		return fmt.Errorf("pxar: obsolete ENTRY_V1 record at %d is not supported", d.pos)
	}
	if typ != TypeEntry {
		return fmt.Errorf("pxar: expected entry record for %q at %d, got %#x", path, d.pos, typ)
	}
	if length != EntrySize {
		return fmt.Errorf("pxar: entry record for %q has length %d", path, length)
	}
	meta, err := d.raw(nil, length)
	if err != nil {
		return err
	}
	mode := binary.LittleEndian.Uint64(meta[HeaderSize:])
	for {
		typ, length, err = d.peek()
		if err != nil {
			return err
		}
		if !isMetadataRecord(typ) {
			break
		}
		if meta, err = d.raw(meta, length); err != nil {
			return err
		}
	}
	switch mode & modeTypeMask {
	case modeDir:
		for {
			typ, length, err := d.peek()
			if err != nil {
				return err
			}
			if typ == TypeGoodbye {
				return d.skip(length)
			}
			if err := d.node(path, false); err != nil {
				return err
			}
		}
	case modeRegular:
		f := MetaFile{Path: path, Meta: meta}
		switch typ {
		case TypePayloadRef:
			body, err := d.body(length)
			if err != nil {
				return err
			}
			if len(body) != 16 {
				return fmt.Errorf("pxar: payload ref for %q has %d body bytes", path, len(body))
			}
			f.PayloadOffset = binary.LittleEndian.Uint64(body)
			f.Size = binary.LittleEndian.Uint64(body[8:])
		case TypePayload:
			f.Size = length - HeaderSize
			if err := d.skip(length); err != nil {
				return err
			}
		default:
			return fmt.Errorf("pxar: expected payload for %q at %d, got %#x", path, d.pos, typ)
		}
		if d.visit != nil {
			return d.visit(f)
		}
		return nil
	case modeSymlink:
		if typ != TypeSymlink {
			return fmt.Errorf("pxar: expected symlink record for %q, got %#x", path, typ)
		}
		return d.skip(length)
	case modeBlockDev, modeCharDev:
		if typ != TypeDevice {
			return fmt.Errorf("pxar: expected device record for %q, got %#x", path, typ)
		}
		return d.skip(length)
	case modeFifo, modeSocket:
		return nil
	}
	return fmt.Errorf("pxar: unsupported mode %#o for %q", mode, path)
}
