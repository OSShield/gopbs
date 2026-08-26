package pbs

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"time"

	"github.com/klauspost/compress/zstd"
)

// Test-only exports: compiled only for tests, keeping internals reachable
// from the external pbs_test package without widening the public API.

type (
	BackupManifest = backupManifest
	ManifestFile   = manifestFile
)

var CanonicalManifestJSON = canonicalManifestJSON

// CryptDigest returns the keyed chunk digest for data under c.
func CryptDigest(c *CryptConfig, data []byte) ([32]byte, error) {
	cs, err := newCryptState(c)
	if err != nil {
		return [32]byte{}, err
	}
	return cs.computeDigest(data), nil
}

// CryptSignature returns HMAC-SHA256(id_key, data) for the key in c.
func CryptSignature(c *CryptConfig, data []byte) ([32]byte, error) {
	cs, err := newCryptState(c)
	if err != nil {
		return [32]byte{}, err
	}
	return cs.authTag(data), nil
}

// CryptFingerprint returns the colon-hex key fingerprint for the key in c.
func CryptFingerprint(c *CryptConfig) (string, error) {
	cs, err := newCryptState(c)
	if err != nil {
		return "", err
	}
	return cs.fingerprintHex(), nil
}

// WrapKeyConfig returns the RSA-wrapped key-config document for the key and
// master public key in c.
func WrapKeyConfig(c *CryptConfig, now time.Time) ([]byte, error) {
	cs, err := newCryptState(c)
	if err != nil {
		return nil, err
	}
	return wrapKeyConfig(cs, now)
}

// EncodeEncrypted frames plain as an encrypted blob for the key in c.
func (e *BlobEncoder) EncodeEncrypted(plain []byte, compress bool, c *CryptConfig) ([]byte, error) {
	cs, err := newCryptState(c)
	if err != nil {
		return nil, err
	}
	return e.encodeEncrypted(plain, compress, cs.aead)
}

// DecryptBlob decodes an encrypted blob frame: it checks the CRC over the
// ciphertext, opens the AES-256-GCM seal and decompresses when the magic
// says so. Test-only — the shipped library is backup-side only.
func DecryptBlob(framed []byte, key [32]byte) ([]byte, error) {
	if len(framed) < blobEncHeaderSize {
		return nil, fmt.Errorf("frame too short: %d", len(framed))
	}
	var magic [8]byte
	copy(magic[:], framed)
	if magic != blobEncryptedMagic && magic != blobEncryptedComprMagic {
		return nil, fmt.Errorf("not an encrypted blob magic: %x", magic)
	}
	iv, tag, ct := framed[12:28], framed[28:44], framed[blobEncHeaderSize:]
	if crc := binary.LittleEndian.Uint32(framed[8:12]); crc != crc32.ChecksumIEEE(ct) {
		return nil, fmt.Errorf("crc mismatch")
	}
	cs, err := newCryptState(&CryptConfig{Key: key})
	if err != nil {
		return nil, err
	}
	sealed := make([]byte, 0, len(ct)+len(tag))
	sealed = append(append(sealed, ct...), tag...)
	payload, err := cs.aead.Open(nil, iv, sealed, nil)
	if err != nil {
		return nil, fmt.Errorf("opening seal: %w", err)
	}
	if magic == blobEncryptedComprMagic {
		dec, err := zstd.NewReader(nil)
		if err != nil {
			return nil, err
		}
		defer dec.Close()
		return dec.DecodeAll(payload, nil)
	}
	return payload, nil
}
