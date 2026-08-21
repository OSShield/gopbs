package catalog

import "errors"

// The catalog's variable-length integer formats, ported from
// proxmox-backup's catalog_encode_u64/i64: 7 bits per byte, a set bit 8
// means the sequence continues. Negative i64 values encode their magnitude
// (-v) with the final group's continuation bit forced, terminated by 0x00.

func appendU64(dst []byte, v uint64) []byte {
	for v >= 128 {
		dst = append(dst, byte(128|(v&127)))
		v >>= 7
	}
	return append(dst, byte(v))
}

func appendI64(dst []byte, v int64) []byte {
	if v >= 0 {
		return appendU64(dst, uint64(v))
	}
	d := uint64(-v)
	for d >= 128 {
		dst = append(dst, byte(128|(d&127)))
		d >>= 7
	}
	return append(dst, byte(128|d), 0)
}

var errVarint = errors.New("catalog: invalid varint")

// decodeU64 reads at most 10 bytes.
func decodeU64(data []byte) (uint64, int, error) {
	var v uint64
	for i := 0; i < 10 && i < len(data); i++ {
		t := data[i]
		if t < 128 {
			return v | uint64(t)<<(i*7), i + 1, nil
		}
		v |= uint64(t&127) << (i * 7)
	}
	return 0, 0, errVarint
}

// decodeI64 reads at most 11 bytes.
func decodeI64(data []byte) (int64, int, error) {
	var v uint64
	for i := 0; i < 11 && i < len(data); i++ {
		t := data[i]
		switch {
		case t == 0:
			if v == 0 {
				return 0, i + 1, nil
			}
			return -int64(v-1) - 1, i + 1, nil
		case t < 128:
			return int64(v | uint64(t)<<(i*7)), i + 1, nil
		default:
			v |= uint64(t&127) << (i * 7)
		}
	}
	return 0, 0, errVarint
}
