package pbs

import (
	"encoding/binary"
	"hash/crc32"

	"github.com/klauspost/compress/zstd"
)

// Blob wire format: 8-byte magic, CRC32-IEEE (little-endian) over the
// payload that follows, then the payload — zstd-compressed or raw depending
// on the magic.
var (
	blobUncompressedMagic = [8]byte{66, 171, 56, 7, 190, 131, 112, 161}
	blobCompressedMagic   = [8]byte{49, 185, 88, 66, 111, 182, 163, 127}
)

const blobHeaderSize = 12

// BlobEncoder frames chunk and blob payloads. It owns a reusable zstd
// encoder (allocating one per chunk is a reference-client mistake worth not
// repeating); use one BlobEncoder per goroutine.
type BlobEncoder struct {
	zstd    *zstd.Encoder
	scratch []byte
}

// NewBlobEncoder returns an encoder with zstd at the default level (what PBS
// clients use).
func NewBlobEncoder() *BlobEncoder {
	enc, err := zstd.NewWriter(nil)
	if err != nil {
		panic("pbs: zstd encoder with default options: " + err.Error())
	}
	return &BlobEncoder{zstd: enc}
}

// Encode frames plain as a blob. With compress set it compresses first and
// keeps the smaller representation — the decision is made before framing, so
// nothing is framed twice. The returned slice is reused by the next Encode
// call on this encoder.
func (e *BlobEncoder) Encode(plain []byte, compress bool) []byte {
	payload := plain
	magic := blobUncompressedMagic
	if compress {
		e.scratch = e.zstd.EncodeAll(plain, e.scratch[:0])
		if len(e.scratch) < len(plain) {
			payload, magic = e.scratch, blobCompressedMagic
		}
	}

	out := make([]byte, blobHeaderSize+len(payload))
	copy(out, magic[:])
	binary.LittleEndian.PutUint32(out[8:], crc32.ChecksumIEEE(payload))
	copy(out[blobHeaderSize:], payload)
	return out
}
