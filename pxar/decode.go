package pxar

import (
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
	pr := NewReaderV1(r)
	pr.version, pr.keepMeta = 0, true
	for {
		n, err := pr.Next()
		if err == io.EOF {
			return pr.version, nil
		}
		if err != nil {
			return 0, err
		}
		if n.Hardlink || n.Mode&modeTypeMask != modeRegular || visit == nil {
			continue
		}
		if err := visit(MetaFile{Path: n.Path, Meta: n.meta, Size: n.Size, PayloadOffset: n.PayloadOffset}); err != nil {
			return 0, err
		}
	}
}
