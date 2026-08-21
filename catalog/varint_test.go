package catalog_test

import (
	"bytes"
	"math"
	"testing"

	"github.com/scheiblingco/gopbs/catalog"
)

func TestVarintU64Vectors(t *testing.T) {
	vectors := []struct {
		v    uint64
		want []byte
	}{
		{0, []byte{0x00}},
		{127, []byte{0x7f}},
		{128, []byte{0x80, 0x01}},
		{300, []byte{0xac, 0x02}},
		{16383, []byte{0xff, 0x7f}},
		{16384, []byte{0x80, 0x80, 0x01}},
		{math.MaxUint64, []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01}},
	}
	for _, tc := range vectors {
		got := catalog.AppendU64(nil, tc.v)
		if !bytes.Equal(got, tc.want) {
			t.Errorf("encode %d = %x, want %x", tc.v, got, tc.want)
		}
		dec, n, err := catalog.DecodeU64(got)
		if err != nil || dec != tc.v || n != len(got) {
			t.Errorf("decode %x = (%d, %d, %v), want (%d, %d, nil)", got, dec, n, err, tc.v, len(got))
		}
	}
}

func TestVarintI64Vectors(t *testing.T) {
	vectors := []struct {
		v    int64
		want []byte
	}{
		{0, []byte{0x00}},
		{1, []byte{0x01}},
		{100, []byte{0x64}},
		// Negative values: magnitude with forced continuation, 0x00 terminator.
		{-1, []byte{0x81, 0x00}},
		{-100, []byte{0xe4, 0x00}},
		{-300, []byte{0xac, 0x82, 0x00}},
	}
	for _, tc := range vectors {
		got := catalog.AppendI64(nil, tc.v)
		if !bytes.Equal(got, tc.want) {
			t.Errorf("encode %d = %x, want %x", tc.v, got, tc.want)
		}
		dec, n, err := catalog.DecodeI64(got)
		if err != nil || dec != tc.v || n != len(got) {
			t.Errorf("decode %x = (%d, %d, %v), want (%d, %d, nil)", got, dec, n, err, tc.v, len(got))
		}
	}

	// Positive i64 values must encode identically to u64 (the reference
	// implementations rely on this for non-negative mtimes).
	for _, v := range []int64{0, 1, 127, 128, 1721422554, math.MaxInt64} {
		if !bytes.Equal(catalog.AppendI64(nil, v), catalog.AppendU64(nil, uint64(v))) {
			t.Errorf("i64(%d) and u64 encodings differ", v)
		}
	}
}

func TestVarintRoundtripExtremes(t *testing.T) {
	for _, v := range []int64{math.MinInt64, math.MinInt64 + 1, -1, 0, 1, math.MaxInt64} {
		enc := catalog.AppendI64(nil, v)
		dec, _, err := catalog.DecodeI64(enc)
		if err != nil || dec != v {
			t.Errorf("i64 roundtrip %d -> %x -> (%d, %v)", v, enc, dec, err)
		}
	}
}

func TestVarintDecodeErrors(t *testing.T) {
	all80 := bytes.Repeat([]byte{0x80}, 12)
	if _, _, err := catalog.DecodeU64(all80); err == nil {
		t.Error("u64 without end marker must fail")
	}
	if _, _, err := catalog.DecodeI64(all80); err == nil {
		t.Error("i64 without end marker must fail")
	}
	if _, _, err := catalog.DecodeU64(nil); err == nil {
		t.Error("empty input must fail")
	}
}
