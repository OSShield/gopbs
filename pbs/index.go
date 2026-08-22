package pbs

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// didxMagic identifies a dynamic index file; the header is a fixed 4096
// bytes, followed by 40-byte records of LE u64 end-offset + sha256 digest.
var didxMagic = [8]byte{28, 145, 78, 165, 25, 186, 179, 205}

const (
	didxHeaderSize = 4096
	didxRecordSize = 40
)

// IndexEntry is one dynamic-index record.
type IndexEntry struct {
	EndOffset uint64
	Digest    [32]byte
}

// ParseDynamicIndex decodes a raw .didx file (as returned by
// DownloadPrevious) with full length validation — the reference client
// panics on short bodies and mis-slices trailing bytes.
func ParseDynamicIndex(data []byte) ([]IndexEntry, error) {
	if len(data) < didxHeaderSize {
		return nil, fmt.Errorf("pbs: dynamic index truncated: %d bytes", len(data))
	}
	if !bytes.Equal(data[:8], didxMagic[:]) {
		return nil, fmt.Errorf("pbs: bad dynamic index magic %x", data[:8])
	}
	records := data[didxHeaderSize:]
	if len(records)%didxRecordSize != 0 {
		return nil, fmt.Errorf("pbs: dynamic index records truncated: %d trailing bytes",
			len(records)%didxRecordSize)
	}

	entries := make([]IndexEntry, 0, len(records)/didxRecordSize)
	for i := 0; i < len(records); i += didxRecordSize {
		var e IndexEntry
		e.EndOffset = binary.LittleEndian.Uint64(records[i:])
		copy(e.Digest[:], records[i+8:i+didxRecordSize])
		entries = append(entries, e)
	}
	return entries, nil
}
