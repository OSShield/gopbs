package archive

import (
	"context"
	"fmt"
	"io"

	"github.com/osshield/gopbs/pxar"
	"github.com/osshield/gopbs/scan"
)

// countWriter tracks the absolute stream position — the only offset state the
// emitter has. Offsets in emitted records (goodbye tables, hardlinks) are
// derived from positions actually written, never from the plan.
type countWriter struct {
	ctx     context.Context
	w       io.Writer
	pos     uint64
	scratch []byte // reused for metadata record rendering
}

func (cw *countWriter) Write(p []byte) (int, error) {
	if err := cw.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := cw.w.Write(p)
	cw.pos += uint64(n)
	return n, err
}

func (cw *countWriter) write(p []byte) error {
	_, err := cw.Write(p)
	return err
}

// emitter walks a node tree and streams the archive's metadata-bearing
// stream: the complete v1 archive, or — when refs is set — the v2 metadata
// stream, where payload records give way to PAYLOAD_REFs into the separately
// emitted payload stream.
type emitter struct {
	w    *countWriter
	src  payloadSource // v1 only; nil in v2 mode
	warn func(Warning)
	refs *refReader // v2 only; nil in v1 mode
	// prelude is the v2 prelude body (exclude patterns); nil emits no record.
	prelude []byte

	// linkTargets maps archive paths of emitted hardlink-target candidates
	// (regular files with nlink > 1) to the start of their filename record.
	linkTargets map[string]uint64
}

func (em *emitter) run(root *scan.Node) error {
	em.linkTargets = make(map[string]uint64)
	if em.refs != nil {
		if err := em.w.write(pxar.AppendFormatVersion(em.scratch(), 2)); err != nil {
			return err
		}
		if em.prelude != nil {
			if err := em.w.write(pxar.AppendPrelude(em.scratch(), em.prelude)); err != nil {
				return err
			}
		}
	}
	_, err := em.node(root, "", true)
	return err
}

// node emits one node's records. goodbyeExtra is what the parent must add to
// the node's emitted byte span in its goodbye item: in v2 mode a regular
// file's item counts the payload content as if it were inline (matching the
// upstream encoder), even though the metadata stream only holds the 32-byte
// ref. Zero for every other node kind, and always zero in v1.
func (em *emitter) node(n *scan.Node, apath string, isRoot bool) (goodbyeExtra uint64, err error) {
	start := em.w.pos

	if !isRoot {
		if err := em.w.write(pxar.AppendFilename(em.scratch(), n.Name)); err != nil {
			return 0, err
		}
	}

	if n.Kind == scan.KindHardlink {
		targetStart, ok := em.linkTargets[n.LinkTarget]
		if !ok {
			return 0, fmt.Errorf("archive: hardlink %s: target %q not emitted before the link", apath, n.LinkTarget)
		}
		return 0, em.w.write(pxar.AppendHardlink(em.scratch(), start-targetStart, n.LinkTarget))
	}

	// Bind payload size before any of the node's records are rendered: the
	// source opens the file and fstats the fd, so the size written into the
	// payload header is the freshest observable value. (v2: binding happens
	// on the payload stream's side; the ref arrives through em.refs below.)
	var pl payload
	if em.refs == nil && (n.Kind == scan.KindFile || n.Kind == scan.KindStream) {
		if pl, err = em.src.open(n); err != nil {
			return 0, err
		}
		defer pl.Close()
	}

	entryStart := em.w.pos
	if err := em.metadata(n); err != nil {
		return 0, err
	}

	switch n.Kind {
	case scan.KindDirectory:
		items := make([]pxar.GoodbyeItem, 0, len(n.Children))
		for _, child := range n.Children {
			childStart := em.w.pos
			extra, err := em.node(child, joinArchive(apath, child.Name), false)
			if err != nil {
				return 0, err
			}
			items = append(items, pxar.GoodbyeItem{
				Hash:   pxar.Hash(child.Name),
				Start:  childStart,
				Length: em.w.pos - childStart + extra,
			})
		}
		// The root goodbye's tail marker points back to the very start of
		// the stream: in v1 that is the root's entry; in v2 the format
		// version record precedes it (matching the upstream encoder).
		tailTarget := entryStart
		if isRoot {
			tailTarget = 0
		}
		return 0, em.w.write(pxar.AppendGoodbye(em.scratch(), items, tailTarget, em.w.pos))

	case scan.KindFile, scan.KindStream:
		if em.refs != nil {
			offset, size, err := em.refs.next()
			if err != nil {
				return 0, err
			}
			if err := em.w.write(pxar.AppendPayloadRef(em.scratch(), offset, size)); err != nil {
				return 0, err
			}
			goodbyeExtra = size
		} else {
			size := pl.Size()
			if err := em.w.write(pxar.AppendPayloadHeader(em.scratch(), uint64(size))); err != nil {
				return 0, err
			}
			if err := pl.Copy(em.w); err != nil {
				return 0, err
			}
			for _, w := range pl.Warnings() {
				em.warn(w)
			}
		}
		if n.Kind == scan.KindFile && n.Stat.Nlink > 1 {
			em.linkTargets[apath] = start
		}
		return goodbyeExtra, nil

	case scan.KindSymlink:
		return 0, em.w.write(pxar.AppendSymlink(em.scratch(), n.LinkTarget))

	case scan.KindBlockDevice, scan.KindCharDevice:
		return 0, em.w.write(pxar.AppendDevice(em.scratch(), n.Stat.Rdev))

	case scan.KindFifo, scan.KindSocket:
		return 0, nil // the type bits in the entry's mode say it all
	}

	return 0, fmt.Errorf("archive: unsupported node kind %d at %s", n.Kind, apath)
}

// metadata renders the ENTRY record and its metadata records in the canonical
// order: xattrs, ACL users, groups, group-obj, default, default users,
// default groups, fcaps, quota project id.
func (em *emitter) metadata(n *scan.Node) error {
	buf := pxar.AppendEntry(em.scratch(), pxar.Entry{
		Mode:       n.Stat.Mode,
		UID:        n.Stat.UID,
		GID:        n.Stat.GID,
		MtimeSecs:  n.Stat.MtimeSecs,
		MtimeNanos: n.Stat.MtimeNanos,
	})
	for _, x := range n.Xattrs {
		buf = pxar.AppendXAttr(buf, x.Name, x.Value)
	}
	if acl := n.ACL; acl != nil {
		for _, u := range acl.Users {
			buf = pxar.AppendACLUser(buf, u)
		}
		for _, g := range acl.Groups {
			buf = pxar.AppendACLGroup(buf, g)
		}
		if acl.GroupObj != nil {
			buf = pxar.AppendACLGroupObj(buf, *acl.GroupObj)
		}
		if acl.Default != nil {
			buf = pxar.AppendACLDefault(buf, *acl.Default)
		}
		for _, u := range acl.DefaultUsers {
			buf = pxar.AppendACLDefaultUser(buf, u)
		}
		for _, g := range acl.DefaultGroups {
			buf = pxar.AppendACLDefaultGroup(buf, g)
		}
	}
	if len(n.FCaps) > 0 {
		buf = pxar.AppendFCaps(buf, n.FCaps)
	}
	if n.QuotaProjID != 0 {
		buf = pxar.AppendQuotaProjID(buf, n.QuotaProjID)
	}
	return em.w.write(buf)
}

// scratch hands out the shared metadata rendering buffer, emptied.
func (em *emitter) scratch() []byte {
	if em.w.scratch == nil {
		em.w.scratch = make([]byte, 0, 4096)
	}
	return em.w.scratch[:0]
}

func joinArchive(prefix, name string) string {
	if prefix == "" {
		return name
	}
	return prefix + "/" + name
}
