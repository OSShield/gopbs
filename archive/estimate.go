package archive

import (
	"github.com/scheiblingco/gopbs/pxar"
	"github.com/scheiblingco/gopbs/scan"
)

// estimateV1 mirrors the emitter's record layout arithmetic using scan-time
// sizes. For an unchanged tree it equals the emitted byte count exactly —
// an invariant the tests enforce; divergence here is a bug.
func estimateV1(n *scan.Node, isRoot bool) uint64 {
	var s uint64
	if !isRoot {
		s += pxar.SizeFilename(n.Name)
	}

	if n.Kind == scan.KindHardlink {
		return s + pxar.SizeHardlink(n.LinkTarget)
	}

	s += pxar.EntrySize
	for _, x := range n.Xattrs {
		s += pxar.SizeXAttr(x.Name, x.Value)
	}
	if acl := n.ACL; acl != nil {
		s += uint64(len(acl.Users)) * pxar.ACLUserSize
		s += uint64(len(acl.Groups)) * pxar.ACLGroupSize
		if acl.GroupObj != nil {
			s += pxar.ACLGroupObjSize
		}
		if acl.Default != nil {
			s += pxar.ACLDefaultSize
		}
		s += uint64(len(acl.DefaultUsers)) * pxar.ACLUserSize
		s += uint64(len(acl.DefaultGroups)) * pxar.ACLGroupSize
	}
	if len(n.FCaps) > 0 {
		s += pxar.SizeFCaps(n.FCaps)
	}
	if n.QuotaProjID != 0 {
		s += pxar.QuotaProjIDSize
	}

	switch n.Kind {
	case scan.KindDirectory:
		for _, child := range n.Children {
			s += estimateV1(child, false)
		}
		s += pxar.SizeGoodbye(len(n.Children))
	case scan.KindFile, scan.KindStream:
		s += pxar.SizePayload(uint64(n.Stat.Size))
	case scan.KindSymlink:
		s += pxar.SizeSymlink(n.LinkTarget)
	case scan.KindBlockDevice, scan.KindCharDevice:
		s += pxar.DeviceSize
	}
	return s
}
