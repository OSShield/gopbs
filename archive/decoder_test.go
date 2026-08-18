package archive_test

// A minimal pxar v1 stream decoder used to verify emitter output
// structurally: record framing, metadata ordering, payload content, and —
// most importantly — that every goodbye table's offsets and lengths resolve
// exactly to the children actually emitted.

import (
	"encoding/binary"
	"fmt"

	"github.com/scheiblingco/gopbs/pxar"
	"github.com/scheiblingco/gopbs/scan"
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
}

func parseArchive(data []byte) (*decNode, error) {
	p := &parser{data: data}
	root, err := p.node("", 0, false)
	if err != nil {
		return nil, err
	}
	if p.pos != uint64(len(data)) {
		return nil, fmt.Errorf("trailing bytes: parsed %d of %d", p.pos, len(data))
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

func (p *parser) node(name string, start uint64, mayHardlink bool) (*decNode, error) {
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
				if err := verifyGoodbye(body, positions, entryStart, goodbyeStart); err != nil {
					return nil, fmt.Errorf("dir %q: %w", name, err)
				}
				return n, nil
			}
			if typ != pxar.TypeFilename {
				return nil, fmt.Errorf("dir %q: expected filename or goodbye at %d, got %#x", name, p.pos, typ)
			}
			childStart := p.pos
			fname := p.body()
			child, err := p.node(string(fname[:len(fname)-1]), childStart, true)
			if err != nil {
				return nil, err
			}
			n.children = append(n.children, child)
			positions = append(positions, childPos{child.name, childStart, p.pos - childStart})
		}

	case scan.ModeRegular:
		typ, _, err := p.header()
		if err != nil {
			return nil, err
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
// emitted children and that the tail marker points back at the directory's
// entry record.
func verifyGoodbye(body []byte, children []childPos, entryStart, goodbyeStart uint64) error {
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
	if off := binary.LittleEndian.Uint64(body[tailOff+8:]); goodbyeStart-off != entryStart {
		return fmt.Errorf("tail offset resolves to %d, entry at %d", goodbyeStart-off, entryStart)
	}
	if l := binary.LittleEndian.Uint64(body[tailOff+16:]); l != uint64(len(body))+pxar.HeaderSize {
		return fmt.Errorf("tail length %d, record is %d", l, len(body)+pxar.HeaderSize)
	}
	return nil
}
