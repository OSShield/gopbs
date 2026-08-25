package archive

import (
	"github.com/osshield/gopbs/pxar"
	"github.com/osshield/gopbs/scan"
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

	s += sizeMetadata(n)

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

// estimateV2 does the same for the two v2 streams: meta is the .mpxar size
// (payload records become fixed-size refs, plus the leading format version
// record), payload the .ppxar size (start marker, framed contents, tail
// marker).
func estimateV2(n *scan.Node, isRoot bool) (meta, payload uint64) {
	if isRoot {
		meta += pxar.FormatVersionSize
		payload += 2 * pxar.MarkerSize
	} else {
		meta += pxar.SizeFilename(n.Name)
	}

	if n.Kind == scan.KindHardlink {
		return meta + pxar.SizeHardlink(n.LinkTarget), payload
	}

	meta += sizeMetadata(n)

	switch n.Kind {
	case scan.KindDirectory:
		for _, child := range n.Children {
			m, p := estimateV2(child, false)
			meta += m
			payload += p
		}
		meta += pxar.SizeGoodbye(len(n.Children))
	case scan.KindFile, scan.KindStream:
		meta += pxar.PayloadRefSize
		payload += pxar.SizePayload(uint64(n.Stat.Size))
	case scan.KindSymlink:
		meta += pxar.SizeSymlink(n.LinkTarget)
	case scan.KindBlockDevice, scan.KindCharDevice:
		meta += pxar.DeviceSize
	}
	return meta, payload
}

// sizeMetadata is the encoded size of a node's ENTRY record plus its metadata
// records — identical in both formats.
func sizeMetadata(n *scan.Node) uint64 {
	s := uint64(pxar.EntrySize)
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
	return s
}
