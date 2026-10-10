package pxar

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Xattr is one extended attribute. Values may contain arbitrary bytes.
type Xattr struct {
	Name  string
	Value []byte
}

// ACLs holds a node's POSIX ACL entries in encoder-ready form. A nil *ACLs
// means the node has no ACL records (a trivial ACL that only mirrors the
// mode bits does not count).
type ACLs struct {
	Users    []ACLUser  // named users (access ACL)
	Groups   []ACLGroup // named groups (access ACL)
	GroupObj *uint64    // owning-group permissions; set only when a mask entry exists

	Default       *ACLDefault // default ACL object permissions (directories)
	DefaultUsers  []ACLUser
	DefaultGroups []ACLGroup
}

// Node is one archive entry as decoded by Reader.
type Node struct {
	// Path is the archive-relative path ("" for the root, "dir/name" below it).
	Path string
	// Entry is the stat record. It is zero for a hardlink, which carries no
	// metadata of its own.
	Entry

	// Hardlink marks a hardlink to an earlier entry of the archive.
	Hardlink bool
	// LinkTarget holds the symlink target, or for a hardlink the
	// archive-relative path of the entry it links to.
	LinkTarget string

	Xattrs      []Xattr
	ACL         *ACLs
	FCaps       []byte
	QuotaProjID uint64 // 0 = none
	Device      Device // block and char devices

	// Size is the content byte count of a regular file; Reader.Read returns
	// exactly that many bytes.
	Size uint64
	// PayloadOffset is the position of the file's payload record header in
	// the payload stream (v2 only).
	PayloadOffset uint64

	meta []byte // entry + metadata records as encoded, for DecodeMetadata
}

// Archives come from a server and are untrusted: every buffered record is
// bounded, and so is the nesting depth (deeper paths cannot be created on
// Linux anyway, PATH_MAX being 4096).
const (
	maxRecordBody = 1 << 20
	maxDepth      = 2048
)

// Reader reads a pxar archive entry by entry, in archive order, like
// archive/tar: Next advances to the next entry, Read returns the content of
// the current regular file. Unread content is skipped by Next.
//
// Every entry is validated as it is decoded: filenames and hardlink targets
// must be plain relative names, records must have their exact sizes, and
// a stream must end exactly after the root directory's goodbye table.
type Reader struct {
	br      *bufio.Reader
	payload io.ReaderAt
	version int // 1 or 2; 0 detects (DecodeMetadata)

	keepMeta bool
	started  bool
	checked  bool     // v2 payload start marker verified
	dirs     []string // paths of the open directories
	pos      uint64   // metadata stream position of the next unread byte

	// one-record lookahead
	have   bool
	typ    uint64
	length uint64

	content io.Reader // current regular file's remaining content
	left    uint64    // its unread byte count
	inline  bool      // content is read from br (v1)
	err     error     // sticky
}

// NewReaderV1 reads a pxar v1 archive.
func NewReaderV1(r io.Reader) *Reader {
	return &Reader{br: bufio.NewReaderSize(r, 256<<10), version: 1}
}

// NewReaderV2 reads a v2 split archive: the metadata stream (.mpxar) in
// order, and the payload stream (.ppxar) at the offsets the metadata stream
// references. payload may be nil when only metadata is needed; Read then
// fails.
func NewReaderV2(meta io.Reader, payload io.ReaderAt) *Reader {
	return &Reader{br: bufio.NewReaderSize(meta, 256<<10), payload: payload, version: 2}
}

// Next advances to the next entry. The root directory comes first, with
// Path "". At the end of the archive Next returns io.EOF.
func (r *Reader) Next() (*Node, error) {
	if r.err != nil {
		return nil, r.err
	}
	n, err := r.next()
	if err != nil {
		r.err = err
		return nil, err
	}
	return n, nil
}

func (r *Reader) next() (*Node, error) {
	if r.inline && r.left > 0 {
		if _, err := io.CopyN(io.Discard, r, int64(r.left)); err != nil {
			return nil, err
		}
	}
	r.content, r.left, r.inline = nil, 0, false

	if !r.started {
		r.started = true
		if err := r.readHead(); err != nil {
			return nil, err
		}
		return r.node("")
	}
	for {
		if len(r.dirs) == 0 {
			switch _, err := r.br.Peek(1); err {
			case io.EOF:
				return nil, io.EOF
			case nil:
				return nil, fmt.Errorf("pxar: trailing data at %d", r.pos)
			default:
				return nil, err
			}
		}
		typ, length, err := r.peek()
		if err != nil {
			return nil, err
		}
		dir := r.dirs[len(r.dirs)-1]
		switch typ {
		case TypeGoodbye:
			if err := r.skip(length); err != nil {
				return nil, err
			}
			r.dirs = r.dirs[:len(r.dirs)-1]
		case TypeFilename:
			body, err := r.body(length)
			if err != nil {
				return nil, err
			}
			name, err := cstring(body)
			if err == nil {
				err = ValidateFilename(name)
			}
			if err != nil {
				return nil, fmt.Errorf("pxar: filename in %q: %w", dir, err)
			}
			if dir != "" {
				name = dir + "/" + name
			}
			return r.node(name)
		default:
			return nil, fmt.Errorf("pxar: expected filename or goodbye in %q at %d, got %#x", dir, r.pos, typ)
		}
	}
}

// readHead consumes the v2 format version and prelude records.
func (r *Reader) readHead() error {
	typ, length, err := r.peek()
	if err != nil {
		return err
	}
	if typ != TypeFormatVersion {
		if r.version == 2 {
			return errors.New("pxar: not a v2 metadata stream (no format version record)")
		}
		r.version = 1
		return nil
	}
	if r.version == 1 {
		return errors.New("pxar: v2 metadata stream given to the v1 reader")
	}
	body, err := r.body(length)
	if err != nil {
		return err
	}
	if len(body) != 8 {
		return fmt.Errorf("pxar: format version record has %d body bytes", len(body))
	}
	if v := binary.LittleEndian.Uint64(body); v != 2 {
		return fmt.Errorf("pxar: unsupported format version %d", v)
	}
	r.version = 2
	if typ, length, err = r.peek(); err != nil {
		return err
	}
	if typ == TypePrelude {
		_, err = r.body(length)
	}
	return err
}

// node decodes the entry following a filename record (or the root entry).
func (r *Reader) node(path string) (*Node, error) {
	n := &Node{Path: path}
	typ, length, err := r.peek()
	if err != nil {
		return nil, err
	}
	if typ == TypeHardlink && path != "" {
		body, err := r.body(length)
		if err != nil {
			return nil, err
		}
		if len(body) < 9 {
			return nil, fmt.Errorf("pxar: hardlink %q: record too short", path)
		}
		target, err := cstring(body[8:])
		if err == nil {
			err = validatePath(target)
		}
		if err != nil {
			return nil, fmt.Errorf("pxar: hardlink %q: target: %w", path, err)
		}
		n.Hardlink, n.LinkTarget = true, target
		return n, nil
	}
	if typ == TypeEntryV1 {
		return nil, fmt.Errorf("pxar: obsolete ENTRY_V1 record at %d is not supported", r.pos)
	}
	if typ != TypeEntry {
		return nil, fmt.Errorf("pxar: expected entry record for %q at %d, got %#x", path, r.pos, typ)
	}
	if length != EntrySize {
		return nil, fmt.Errorf("pxar: entry record for %q has length %d", path, length)
	}
	body, err := r.body(length)
	if err != nil {
		return nil, err
	}
	n.Entry = Entry{
		Mode:       binary.LittleEndian.Uint64(body),
		Flags:      binary.LittleEndian.Uint64(body[8:]),
		UID:        binary.LittleEndian.Uint32(body[16:]),
		GID:        binary.LittleEndian.Uint32(body[20:]),
		MtimeSecs:  int64(binary.LittleEndian.Uint64(body[24:])),
		MtimeNanos: binary.LittleEndian.Uint32(body[32:]),
	}
	r.keep(n, TypeEntry, body)
	if typ, length, err = r.metadata(n); err != nil {
		return nil, err
	}

	switch n.Mode & modeTypeMask {
	case modeDir:
		if len(r.dirs) >= maxDepth {
			return nil, fmt.Errorf("pxar: %q nests deeper than %d directories", path, maxDepth)
		}
		r.dirs = append(r.dirs, path)
	case modeRegular:
		if err := r.payloadRecord(n, typ, length); err != nil {
			return nil, err
		}
	case modeSymlink:
		if typ != TypeSymlink {
			return nil, fmt.Errorf("pxar: expected symlink record for %q, got %#x", path, typ)
		}
		body, err := r.body(length)
		if err != nil {
			return nil, err
		}
		if n.LinkTarget, err = cstring(body); err == nil && n.LinkTarget == "" {
			err = errors.New("empty target")
		}
		if err != nil {
			return nil, fmt.Errorf("pxar: symlink %q: %w", path, err)
		}
	case modeBlockDev, modeCharDev:
		if typ != TypeDevice || length != DeviceSize {
			return nil, fmt.Errorf("pxar: expected device record for %q, got %#x (length %d)", path, typ, length)
		}
		body, err := r.body(length)
		if err != nil {
			return nil, err
		}
		n.Device = Device{Major: binary.LittleEndian.Uint64(body), Minor: binary.LittleEndian.Uint64(body[8:])}
	case modeFifo, modeSocket:
	default:
		return nil, fmt.Errorf("pxar: unsupported mode %#o for %q", n.Mode, path)
	}
	return n, nil
}

// metadata decodes the records between an entry and its type-specific
// record, and returns the header of the first record after them.
func (r *Reader) metadata(n *Node) (typ, length uint64, err error) {
	acl := func() *ACLs {
		if n.ACL == nil {
			n.ACL = &ACLs{}
		}
		return n.ACL
	}
	for {
		if typ, length, err = r.peek(); err != nil {
			return 0, 0, err
		}
		want, ok := metadataRecord(typ)
		if !ok {
			return typ, length, nil
		}
		if want != 0 && length != want {
			return 0, 0, fmt.Errorf("pxar: %q: metadata record %#x has length %d", n.Path, typ, length)
		}
		body, err := r.body(length)
		if err != nil {
			return 0, 0, err
		}
		r.keep(n, typ, body)
		u64 := func(i int) uint64 { return binary.LittleEndian.Uint64(body[8*i:]) }
		switch typ {
		case TypeXAttr:
			i := bytes.IndexByte(body, 0)
			if i <= 0 {
				return 0, 0, fmt.Errorf("pxar: %q: malformed xattr record", n.Path)
			}
			n.Xattrs = append(n.Xattrs, Xattr{Name: string(body[:i]), Value: body[i+1:]})
		case TypeACLUser:
			acl().Users = append(acl().Users, ACLUser{UID: u64(0), Permissions: u64(1)})
		case TypeACLDefaultUser:
			acl().DefaultUsers = append(acl().DefaultUsers, ACLUser{UID: u64(0), Permissions: u64(1)})
		case TypeACLGroup:
			acl().Groups = append(acl().Groups, ACLGroup{GID: u64(0), Permissions: u64(1)})
		case TypeACLDefaultGroup:
			acl().DefaultGroups = append(acl().DefaultGroups, ACLGroup{GID: u64(0), Permissions: u64(1)})
		case TypeACLGroupObj:
			p := u64(0)
			acl().GroupObj = &p
		case TypeACLDefault:
			acl().Default = &ACLDefault{
				UserObjPermissions:  u64(0),
				GroupObjPermissions: u64(1),
				OtherPermissions:    u64(2),
				MaskPermissions:     u64(3),
			}
		case TypeFCaps:
			n.FCaps = body
		case TypeQuotaProjID:
			n.QuotaProjID = u64(0)
		}
	}
}

// metadataRecord reports whether typ is a metadata record and, for the
// fixed-layout ones, its exact length (0 for variable-length records).
func metadataRecord(typ uint64) (length uint64, ok bool) {
	switch typ {
	case TypeACLUser, TypeACLDefaultUser:
		return ACLUserSize, true
	case TypeACLGroup, TypeACLDefaultGroup:
		return ACLGroupSize, true
	case TypeACLGroupObj:
		return ACLGroupObjSize, true
	case TypeACLDefault:
		return ACLDefaultSize, true
	case TypeQuotaProjID:
		return QuotaProjIDSize, true
	case TypeXAttr, TypeFCaps:
		return 0, true
	}
	return 0, false
}

// payloadRecord consumes a regular file's payload (v1) or payload reference
// (v2) and makes its content readable.
func (r *Reader) payloadRecord(n *Node, typ, length uint64) error {
	switch {
	case r.version == 1 && typ == TypePayload:
		n.Size = length - HeaderSize
		r.have = false
		r.pos += HeaderSize
		r.content, r.left, r.inline = r.br, n.Size, true
		return nil

	case r.version == 2 && typ == TypePayloadRef:
		if length != PayloadRefSize {
			return fmt.Errorf("pxar: payload ref for %q has length %d", n.Path, length)
		}
		body, err := r.body(length)
		if err != nil {
			return err
		}
		n.PayloadOffset = binary.LittleEndian.Uint64(body)
		n.Size = binary.LittleEndian.Uint64(body[8:])
		if r.payload == nil {
			r.content, r.left = errReader{errors.New("no payload stream")}, n.Size
			return nil
		}
		if err := r.checkPayload(n); err != nil {
			return err
		}
		r.content = io.NewSectionReader(r.payload, int64(n.PayloadOffset+HeaderSize), int64(n.Size))
		r.left = n.Size
		return nil
	}
	return fmt.Errorf("pxar: expected payload for %q at %d, got %#x", n.Path, r.pos, typ)
}

// checkPayload verifies that a payload reference resolves to a payload
// record of the referenced size.
func (r *Reader) checkPayload(n *Node) error {
	var hdr [HeaderSize]byte
	if !r.checked {
		if _, err := r.payload.ReadAt(hdr[:], 0); err != nil {
			return fmt.Errorf("pxar: payload stream: %w", err)
		}
		if binary.LittleEndian.Uint64(hdr[:]) != PayloadStartMarker {
			return errors.New("pxar: payload stream has no start marker")
		}
		r.checked = true
	}
	if n.PayloadOffset > 1<<62 || n.Size > 1<<62 {
		return fmt.Errorf("pxar: payload ref for %q out of range", n.Path)
	}
	if _, err := r.payload.ReadAt(hdr[:], int64(n.PayloadOffset)); err != nil {
		return fmt.Errorf("pxar: payload of %q at %d: %w", n.Path, n.PayloadOffset, err)
	}
	if binary.LittleEndian.Uint64(hdr[:]) != TypePayload || binary.LittleEndian.Uint64(hdr[8:]) != HeaderSize+n.Size {
		return fmt.Errorf("pxar: payload ref for %q does not resolve to a %d-byte payload record", n.Path, n.Size)
	}
	return nil
}

// Read reads the content of the current regular file. Other entries have
// no content.
func (r *Reader) Read(p []byte) (int, error) {
	if r.left == 0 {
		return 0, io.EOF
	}
	if uint64(len(p)) > r.left {
		p = p[:r.left]
	}
	n, err := r.content.Read(p)
	r.left -= uint64(n)
	if r.inline {
		r.pos += uint64(n)
	}
	switch {
	case r.left == 0 || err == nil:
		return n, nil
	case err == io.EOF:
		err = io.ErrUnexpectedEOF
	}
	r.err = fmt.Errorf("pxar: reading content: %w", err)
	return n, r.err
}

type errReader struct{ err error }

func (e errReader) Read([]byte) (int, error) { return 0, e.err }

func (r *Reader) keep(n *Node, typ uint64, body []byte) {
	if r.keepMeta {
		n.meta = appendHeader(n.meta, typ, HeaderSize+uint64(len(body)))
		n.meta = append(n.meta, body...)
	}
}

// peek reads the next record header without consuming it.
func (r *Reader) peek() (typ, length uint64, err error) {
	if r.have {
		return r.typ, r.length, nil
	}
	var hdr [HeaderSize]byte
	if _, err := io.ReadFull(r.br, hdr[:]); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return 0, 0, fmt.Errorf("pxar: truncated archive at %d", r.pos)
		}
		return 0, 0, err
	}
	r.typ = binary.LittleEndian.Uint64(hdr[:])
	r.length = binary.LittleEndian.Uint64(hdr[8:])
	if r.length < HeaderSize {
		return 0, 0, fmt.Errorf("pxar: record %#x at %d: bad length %d", r.typ, r.pos, r.length)
	}
	r.have = true
	return r.typ, r.length, nil
}

// body consumes the peeked record and returns its body.
func (r *Reader) body(length uint64) ([]byte, error) {
	n := length - HeaderSize
	if n > maxRecordBody {
		return nil, fmt.Errorf("pxar: record %#x at %d too large (%d bytes)", r.typ, r.pos, n)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r.br, body); err != nil {
		return nil, fmt.Errorf("pxar: truncated record %#x at %d: %w", r.typ, r.pos, err)
	}
	r.have = false
	r.pos += length
	return body, nil
}

// skip consumes the peeked record without keeping its body.
func (r *Reader) skip(length uint64) error {
	n := length - HeaderSize
	if n > 1<<62 {
		return fmt.Errorf("pxar: record %#x at %d: bad length %d", r.typ, r.pos, length)
	}
	if _, err := io.CopyN(io.Discard, r.br, int64(n)); err != nil {
		return fmt.Errorf("pxar: truncated record %#x at %d: %w", r.typ, r.pos, err)
	}
	r.have = false
	r.pos += length
	return nil
}

func cstring(b []byte) (string, error) {
	if len(b) == 0 || b[len(b)-1] != 0 {
		return "", errors.New("not NUL-terminated")
	}
	return string(b[:len(b)-1]), nil
}

// validatePath accepts a relative slash-separated path of valid filenames.
func validatePath(p string) error {
	for name := range strings.SplitSeq(p, "/") {
		if err := ValidateFilename(name); err != nil {
			return err
		}
	}
	return nil
}
