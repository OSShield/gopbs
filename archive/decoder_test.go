package archive_test

// A minimal pxar stream decoder used to verify emitter output structurally:
// record framing, metadata ordering, payload content, and — most importantly —
// that every goodbye table's offsets and lengths resolve exactly to the
// children actually emitted. Handles both v1 archives and v2 split pairs
// (metadata stream with payload refs resolved against the payload stream).

import (
	"encoding/binary"
	"fmt"

	"github.com/osshield/gopbs/pxar"
	"github.com/osshield/gopbs/scan"
)

type decNode struct {
	name  string
	start uint64 // filename record start (0 for root)

	mode       uint64
	uid, gid   uint32
	mtimeSecs  int64
	mtimeNanos uint32

	xattrs   []scan.Xattr
	content  []byte // regular files
	symlink  string
	hardlink struct {
		offset uint64
		target string
	}
	device   pxar.Device
	children []*decNode
	prelude  []byte // v2 root: the prelude record body, nil when absent

	// gbExtra is what the parent's goodbye item adds on top of the node's
	// metadata-stream span: the payload content size for v2 regular files.
	gbExtra uint64
}

func (n *decNode) child(name string) *decNode {
	for _, c := range n.children {
		if c.name == name {
			return c
		}
	}
	return nil
}

// find resolves a slash-separated archive path.
func (n *decNode) find(path string) *decNode {
	cur := n
	for len(path) > 0 {
		i := 0
		for i < len(path) && path[i] != '/' {
			i++
		}
		cur = cur.child(path[:i])
		if cur == nil {
			return nil
		}
		if i == len(path) {
			break
		}
		path = path[i+1:]
	}
	return cur
}

type parser struct {
	data []byte
	pos  uint64

	// v2 split mode: payload refs are resolved against the payload stream,
	// which must be covered contiguously in ref order.
	v2         bool
	payload    []byte
	payloadPos uint64
}

func parseArchive(data []byte) (*decNode, error) {
	p := &parser{data: data}
	root, err := p.node("", 0, false, true)
	if err != nil {
		return nil, err
	}
	if p.pos != uint64(len(data)) {
		return nil, fmt.Errorf("trailing bytes: parsed %d of %d", p.pos, len(data))
	}
	return root, nil
}

// parseArchiveV2 parses a split archive pair, requiring the format version
// record, the payload stream markers, and contiguous in-order payload
// coverage by the metadata stream's refs.
func parseArchiveV2(meta, payload []byte) (*decNode, error) {
	p := &parser{data: meta, v2: true, payload: payload}

	typ, length, err := p.header()
	if err != nil {
		return nil, err
	}
	if typ != pxar.TypeFormatVersion || length != pxar.FormatVersionSize {
		return nil, fmt.Errorf("expected format version record, got %#x len %d", typ, length)
	}
	if v := binary.LittleEndian.Uint64(p.body()); v != 2 {
		return nil, fmt.Errorf("format version %d, want 2", v)
	}
	var prelude []byte
	if typ, _, err := p.header(); err != nil {
		return nil, err
	} else if typ == pxar.TypePrelude {
		prelude = p.body()
	}

	if uint64(len(payload)) < 2*pxar.MarkerSize {
		return nil, fmt.Errorf("payload stream too short: %d bytes", len(payload))
	}
	if typ := binary.LittleEndian.Uint64(payload); typ != pxar.PayloadStartMarker {
		return nil, fmt.Errorf("payload start marker: got %#x", typ)
	}
	if l := binary.LittleEndian.Uint64(payload[8:]); l != pxar.MarkerSize {
		return nil, fmt.Errorf("payload start marker length %d", l)
	}
	p.payloadPos = pxar.MarkerSize

	root, err := p.node("", 0, false, true)
	if err != nil {
		return nil, err
	}
	root.prelude = prelude
	if p.pos != uint64(len(meta)) {
		return nil, fmt.Errorf("trailing metadata bytes: parsed %d of %d", p.pos, len(meta))
	}

	tail := p.payloadPos
	if typ := binary.LittleEndian.Uint64(payload[tail:]); typ != pxar.PayloadTailMarker {
		return nil, fmt.Errorf("payload tail marker at %d: got %#x", tail, typ)
	}
	if l := binary.LittleEndian.Uint64(payload[tail+8:]); l != pxar.MarkerSize {
		return nil, fmt.Errorf("payload tail marker length %d", l)
	}
	if tail+pxar.MarkerSize != uint64(len(payload)) {
		return nil, fmt.Errorf("trailing payload bytes: refs cover %d of %d", tail+pxar.MarkerSize, len(payload))
	}
	return root, nil
}

func (p *parser) header() (typ, length uint64, err error) {
	if uint64(len(p.data))-p.pos < pxar.HeaderSize {
		return 0, 0, fmt.Errorf("truncated header at %d", p.pos)
	}
	typ = binary.LittleEndian.Uint64(p.data[p.pos:])
	length = binary.LittleEndian.Uint64(p.data[p.pos+8:])
	if length < pxar.HeaderSize || p.pos+length > uint64(len(p.data)) {
		return 0, 0, fmt.Errorf("record type %#x at %d: bad length %d", typ, p.pos, length)
	}
	return typ, length, nil
}

// body consumes the current record and returns its body bytes.
func (p *parser) body() []byte {
	_, length, _ := p.header()
	body := p.data[p.pos+pxar.HeaderSize : p.pos+length]
	p.pos += length
	return body
}

func (p *parser) node(name string, start uint64, mayHardlink, isRoot bool) (*decNode, error) {
	n := &decNode{name: name, start: start}

	typ, _, err := p.header()
	if err != nil {
		return nil, err
	}
	if typ == pxar.TypeHardlink {
		if !mayHardlink {
			return nil, fmt.Errorf("unexpected hardlink at %d", p.pos)
		}
		body := p.body()
		n.hardlink.offset = binary.LittleEndian.Uint64(body)
		n.hardlink.target = string(body[8 : len(body)-1]) // strip NUL
		n.mode = 0
		return n, nil
	}
	if typ != pxar.TypeEntry {
		return nil, fmt.Errorf("expected entry at %d, got %#x", p.pos, typ)
	}
	body := p.body()
	n.mode = binary.LittleEndian.Uint64(body)
	n.uid = binary.LittleEndian.Uint32(body[16:])
	n.gid = binary.LittleEndian.Uint32(body[20:])
	n.mtimeSecs = int64(binary.LittleEndian.Uint64(body[24:]))
	n.mtimeNanos = binary.LittleEndian.Uint32(body[32:])
	entryStart := p.pos - pxar.EntrySize

	// Metadata records in canonical order; the decoder just collects them.
	for {
		typ, _, err := p.header()
		if err != nil {
			return nil, err
		}
		switch typ {
		case pxar.TypeXAttr:
			body := p.body()
			for i, b := range body {
				if b == 0 {
					n.xattrs = append(n.xattrs, scan.Xattr{Name: string(body[:i]), Value: body[i+1:]})
					break
				}
			}
		case pxar.TypeACLUser, pxar.TypeACLGroup, pxar.TypeACLGroupObj, pxar.TypeACLDefault,
			pxar.TypeACLDefaultUser, pxar.TypeACLDefaultGroup, pxar.TypeFCaps, pxar.TypeQuotaProjID:
			p.body()
		default:
			goto meta_done
		}
	}
meta_done:

	switch n.mode & scan.ModeTypeMask {
	case scan.ModeDir:
		var positions []childPos
		for {
			typ, _, err := p.header()
			if err != nil {
				return nil, err
			}
			if typ == pxar.TypeGoodbye {
				goodbyeStart := p.pos
				body := p.body()
				// The v2 root tail marker points at the very start of the
				// stream (the format version record), not the root entry.
				tailTarget := entryStart
				if p.v2 && isRoot {
					tailTarget = 0
				}
				if err := verifyGoodbye(body, positions, tailTarget, goodbyeStart); err != nil {
					return nil, fmt.Errorf("dir %q: %w", name, err)
				}
				return n, nil
			}
			if typ != pxar.TypeFilename {
				return nil, fmt.Errorf("dir %q: expected filename or goodbye at %d, got %#x", name, p.pos, typ)
			}
			childStart := p.pos
			fname := p.body()
			child, err := p.node(string(fname[:len(fname)-1]), childStart, true, false)
			if err != nil {
				return nil, err
			}
			n.children = append(n.children, child)
			positions = append(positions, childPos{child.name, childStart, p.pos - childStart + child.gbExtra})
		}

	case scan.ModeRegular:
		typ, _, err := p.header()
		if err != nil {
			return nil, err
		}
		if p.v2 {
			if typ != pxar.TypePayloadRef {
				return nil, fmt.Errorf("file %q: expected payload ref, got %#x", name, typ)
			}
			body := p.body()
			offset := binary.LittleEndian.Uint64(body)
			size := binary.LittleEndian.Uint64(body[8:])
			if offset != p.payloadPos {
				return nil, fmt.Errorf("file %q: ref offset %d, next payload record at %d", name, offset, p.payloadPos)
			}
			if offset+pxar.HeaderSize+size > uint64(len(p.payload)) {
				return nil, fmt.Errorf("file %q: ref %d+%d beyond payload stream (%d)", name, offset, size, len(p.payload))
			}
			if typ := binary.LittleEndian.Uint64(p.payload[offset:]); typ != pxar.TypePayload {
				return nil, fmt.Errorf("file %q: ref resolves to record %#x", name, typ)
			}
			if l := binary.LittleEndian.Uint64(p.payload[offset+8:]); l != pxar.HeaderSize+size {
				return nil, fmt.Errorf("file %q: ref size %d, payload record length %d", name, size, l)
			}
			n.content = p.payload[offset+pxar.HeaderSize : offset+pxar.HeaderSize+size]
			n.gbExtra = size
			p.payloadPos = offset + pxar.HeaderSize + size
			return n, nil
		}
		if typ != pxar.TypePayload {
			return nil, fmt.Errorf("file %q: expected payload, got %#x", name, typ)
		}
		n.content = p.body()
		return n, nil

	case scan.ModeSymlink:
		typ, _, err := p.header()
		if err != nil {
			return nil, err
		}
		if typ != pxar.TypeSymlink {
			return nil, fmt.Errorf("symlink %q: got %#x", name, typ)
		}
		body := p.body()
		n.symlink = string(body[:len(body)-1])
		return n, nil

	case scan.ModeBlockDev, scan.ModeCharDev:
		typ, _, err := p.header()
		if err != nil {
			return nil, err
		}
		if typ != pxar.TypeDevice {
			return nil, fmt.Errorf("device %q: got %#x", name, typ)
		}
		body := p.body()
		n.device = pxar.Device{
			Major: binary.LittleEndian.Uint64(body),
			Minor: binary.LittleEndian.Uint64(body[8:]),
		}
		return n, nil

	case scan.ModeFifo, scan.ModeSocket:
		return n, nil // no type-specific record
	}

	return nil, fmt.Errorf("node %q: unsupported mode %o", name, n.mode)
}

type childPos struct {
	name          string
	start, length uint64
}

// verifyGoodbye checks that a goodbye record's items map one-to-one onto the
// emitted children and that the tail marker points back at tailTarget (the
// directory's entry record; the stream start for the v2 root).
func verifyGoodbye(body []byte, children []childPos, tailTarget, goodbyeStart uint64) error {
	if len(body)%24 != 0 || len(body) == 0 {
		return fmt.Errorf("goodbye body length %d", len(body))
	}
	nItems := len(body)/24 - 1
	if nItems != len(children) {
		return fmt.Errorf("goodbye has %d items for %d children", nItems, len(children))
	}

	type gbItem struct{ hash, offset, length uint64 }
	byHash := make(map[uint64]gbItem, nItems)
	for i := 0; i < nItems; i++ {
		it := gbItem{
			binary.LittleEndian.Uint64(body[i*24:]),
			binary.LittleEndian.Uint64(body[i*24+8:]),
			binary.LittleEndian.Uint64(body[i*24+16:]),
		}
		byHash[it.hash] = it
	}
	for _, c := range children {
		it, ok := byHash[pxar.Hash(c.name)]
		if !ok {
			return fmt.Errorf("child %q missing from goodbye table", c.name)
		}
		if goodbyeStart-it.offset != c.start {
			return fmt.Errorf("child %q: goodbye offset resolves to %d, emitted at %d",
				c.name, goodbyeStart-it.offset, c.start)
		}
		if it.length != c.length {
			return fmt.Errorf("child %q: goodbye length %d, emitted %d", c.name, it.length, c.length)
		}
	}

	tailOff := len(body) - 24
	if h := binary.LittleEndian.Uint64(body[tailOff:]); h != pxar.GoodbyeTailMarker {
		return fmt.Errorf("tail marker hash %#x", h)
	}
	if off := binary.LittleEndian.Uint64(body[tailOff+8:]); goodbyeStart-off != tailTarget {
		return fmt.Errorf("tail offset resolves to %d, want %d", goodbyeStart-off, tailTarget)
	}
	if l := binary.LittleEndian.Uint64(body[tailOff+16:]); l != uint64(len(body))+pxar.HeaderSize {
		return fmt.Errorf("tail length %d, record is %d", l, len(body)+pxar.HeaderSize)
	}
	return nil
}
