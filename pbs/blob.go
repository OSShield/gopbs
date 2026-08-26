package pbs

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"hash/crc32"

	"github.com/klauspost/compress/zstd"
)

// Blob wire format: 8-byte magic, CRC32-IEEE (little-endian) over the
// payload that follows, then the payload — zstd-compressed or raw depending
// on the magic. Encrypted blobs extend the header with the AES-256-GCM IV
// and tag; their CRC covers the ciphertext only.
var (
	blobUncompressedMagic   = [8]byte{66, 171, 56, 7, 190, 131, 112, 161}
	blobCompressedMagic     = [8]byte{49, 185, 88, 66, 111, 182, 163, 127}
	blobEncryptedMagic      = [8]byte{123, 103, 133, 190, 34, 45, 76, 240}
	blobEncryptedComprMagic = [8]byte{230, 89, 27, 191, 11, 191, 216, 11}
)

const (
	blobHeaderSize    = 12 // magic(8) + crc32(4)
	blobEncHeaderSize = 44 // magic(8) + crc32(4) + iv(16) + tag(16)
)

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

// encodeEncrypted frames plain as an encrypted blob: magic, CRC32 over the
// ciphertext, a fresh random 16-byte IV, the 16-byte GCM tag, then the
// ciphertext. Compression happens before encryption and the compressed
// payload is kept only when smaller, mirroring Encode; the magic records the
// choice. The returned slice is freshly allocated per call.
func (e *BlobEncoder) encodeEncrypted(plain []byte, compress bool, aead cipher.AEAD) ([]byte, error) {
	payload := plain
	magic := blobEncryptedMagic
	if compress {
		e.scratch = e.zstd.EncodeAll(plain, e.scratch[:0])
		if len(e.scratch) < len(plain) {
			payload, magic = e.scratch, blobEncryptedComprMagic
		}
	}

	// Seal writes ciphertext||tag; the extra 16 bytes at the end hold the
	// tag until it is moved into the header, so sealing works in place with
	// a single allocation.
	out := make([]byte, blobEncHeaderSize+len(payload)+16)
	copy(out, magic[:])
	iv := out[12:28]
	if _, err := rand.Read(iv); err != nil {
		return nil, fmt.Errorf("pbs: generating blob IV: %w", err)
	}
	sealed := aead.Seal(out[blobEncHeaderSize:blobEncHeaderSize], iv, payload, nil)
	copy(out[28:44], sealed[len(payload):])
	out = out[:blobEncHeaderSize+len(payload)]
	binary.LittleEndian.PutUint32(out[8:], crc32.ChecksumIEEE(out[blobEncHeaderSize:]))
	return out, nil
}
