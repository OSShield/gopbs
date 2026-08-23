package pxar_test

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/scheiblingco/gopbs/pxar"
)

func le64(v uint64) []byte { return binary.LittleEndian.AppendUint64(nil, v) }
func le32(v uint32) []byte { return binary.LittleEndian.AppendUint32(nil, v) }

func golden(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

func checkRecord(t *testing.T, name string, got, want []byte) {
	t.Helper()
	if !bytes.Equal(got, want) {
		t.Errorf("%s:\n got  %x\n want %x", name, got, want)
	}
	if len(got) >= pxar.HeaderSize {
		if l := binary.LittleEndian.Uint64(got[8:16]); l != uint64(len(got)) {
			t.Errorf("%s: header length %d != encoded length %d", name, l, len(got))
		}
	}
}

func TestAppendEntry(t *testing.T) {
	e := pxar.Entry{
		Mode:       0o40755, // directory bits are part of Mode; raw value used as-is
		Flags:      0,
		UID:        1000,
		GID:        1001,
		MtimeSecs:  1721422554,
		MtimeNanos: 123456789,
	}
	want := golden(
		le64(pxar.TypeEntry), le64(56),
		le64(e.Mode), le64(e.Flags),
		le32(1000), le32(1001),
		le64(uint64(e.MtimeSecs)), le32(123456789), le32(0),
	)
	checkRecord(t, "entry", pxar.AppendEntry(nil, e), want)
}

func TestAppendEntryNegativeMtime(t *testing.T) {
	got := pxar.AppendEntry(nil, pxar.Entry{MtimeSecs: -1})
	if v := binary.LittleEndian.Uint64(got[40:48]); v != ^uint64(0) {
		t.Errorf("negative mtime secs encoded as %x, want all-ones two's complement", v)
	}
}

func TestAppendFilename(t *testing.T) {
	want := golden(le64(pxar.TypeFilename), le64(16+5+1), []byte("hello"), []byte{0})
	got := pxar.AppendFilename(nil, "hello")
	checkRecord(t, "filename", got, want)
	if pxar.SizeFilename("hello") != uint64(len(got)) {
		t.Errorf("SizeFilename = %d, want %d", pxar.SizeFilename("hello"), len(got))
	}
}

func TestValidateFilename(t *testing.T) {
	for _, ok := range []string{"a", "with space", "üñïçödé", "trailing.dot."} {
		if err := pxar.ValidateFilename(ok); err != nil {
			t.Errorf("ValidateFilename(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{"", ".", "..", "a/b", "nul\x00byte"} {
		if err := pxar.ValidateFilename(bad); err == nil {
			t.Errorf("ValidateFilename(%q) = nil, want error", bad)
		}
	}
}

func TestAppendSymlink(t *testing.T) {
	target := "../target/file"
	want := golden(le64(pxar.TypeSymlink), le64(16+uint64(len(target))+1), []byte(target), []byte{0})
	got := pxar.AppendSymlink(nil, target)
	checkRecord(t, "symlink", got, want)
	if pxar.SizeSymlink(target) != uint64(len(got)) {
		t.Errorf("SizeSymlink = %d, want %d", pxar.SizeSymlink(target), len(got))
	}
}

func TestAppendDevice(t *testing.T) {
	want := golden(le64(pxar.TypeDevice), le64(32), le64(8), le64(1))
	checkRecord(t, "device", pxar.AppendDevice(nil, pxar.Device{Major: 8, Minor: 1}), want)
}

func TestAppendHardlink(t *testing.T) {
	target := "dir/original"
	want := golden(
		le64(pxar.TypeHardlink), le64(16+8+uint64(len(target))+1),
		le64(4242), []byte(target), []byte{0},
	)
	got := pxar.AppendHardlink(nil, 4242, target)
	checkRecord(t, "hardlink", got, want)
	if pxar.SizeHardlink(target) != uint64(len(got)) {
		t.Errorf("SizeHardlink = %d, want %d", pxar.SizeHardlink(target), len(got))
	}
}

func TestAppendXAttr(t *testing.T) {
	value := []byte{0xde, 0xad, 0x00, 0xbe, 0xef} // values may contain NUL
	want := golden(
		le64(pxar.TypeXAttr), le64(16+9+1+5),
		[]byte("user.test"), []byte{0}, value,
	)
	got := pxar.AppendXAttr(nil, "user.test", value)
	checkRecord(t, "xattr", got, want)
	if pxar.SizeXAttr("user.test", value) != uint64(len(got)) {
		t.Errorf("SizeXAttr = %d, want %d", pxar.SizeXAttr("user.test", value), len(got))
	}
}

func TestAppendACLRecords(t *testing.T) {
	checkRecord(t, "acl user",
		pxar.AppendACLUser(nil, pxar.ACLUser{UID: 1000, Permissions: pxar.ACLRead | pxar.ACLWrite}),
		golden(le64(pxar.TypeACLUser), le64(32), le64(1000), le64(6)))

	checkRecord(t, "acl default user",
		pxar.AppendACLDefaultUser(nil, pxar.ACLUser{UID: 7, Permissions: pxar.ACLExecute}),
		golden(le64(pxar.TypeACLDefaultUser), le64(32), le64(7), le64(1)))

	checkRecord(t, "acl group",
		pxar.AppendACLGroup(nil, pxar.ACLGroup{GID: 2000, Permissions: pxar.ACLRead}),
		golden(le64(pxar.TypeACLGroup), le64(32), le64(2000), le64(4)))

	checkRecord(t, "acl default group",
		pxar.AppendACLDefaultGroup(nil, pxar.ACLGroup{GID: 9, Permissions: pxar.ACLRead | pxar.ACLExecute}),
		golden(le64(pxar.TypeACLDefaultGroup), le64(32), le64(9), le64(5)))

	checkRecord(t, "acl group obj",
		pxar.AppendACLGroupObj(nil, pxar.ACLRead|pxar.ACLWrite|pxar.ACLExecute),
		golden(le64(pxar.TypeACLGroupObj), le64(24), le64(7)))

	checkRecord(t, "acl default",
		pxar.AppendACLDefault(nil, pxar.ACLDefault{
			UserObjPermissions:  pxar.ACLRead | pxar.ACLWrite,
			GroupObjPermissions: pxar.ACLRead,
			OtherPermissions:    0,
			MaskPermissions:     pxar.ACLNoMask,
		}),
		golden(le64(pxar.TypeACLDefault), le64(48), le64(6), le64(4), le64(0), le64(^uint64(0))))
}

func TestAppendFCaps(t *testing.T) {
	data := []byte{1, 0, 0, 2, 0x20}
	want := golden(le64(pxar.TypeFCaps), le64(16+5), data)
	got := pxar.AppendFCaps(nil, data)
	checkRecord(t, "fcaps", got, want)
	if pxar.SizeFCaps(data) != uint64(len(got)) {
		t.Errorf("SizeFCaps = %d, want %d", pxar.SizeFCaps(data), len(got))
	}
}

func TestAppendQuotaProjID(t *testing.T) {
	want := golden(le64(pxar.TypeQuotaProjID), le64(24), le64(555))
	checkRecord(t, "quota projid", pxar.AppendQuotaProjID(nil, 555), want)
}

func TestAppendPayloadHeader(t *testing.T) {
	got := pxar.AppendPayloadHeader(nil, 1024)
	want := golden(le64(pxar.TypePayload), le64(16+1024))
	if !bytes.Equal(got, want) {
		t.Errorf("payload header:\n got  %x\n want %x", got, want)
	}
	if pxar.SizePayload(1024) != 16+1024 {
		t.Errorf("SizePayload = %d, want %d", pxar.SizePayload(1024), 16+1024)
	}
}

func TestAppendFormatVersion(t *testing.T) {
	want := golden(le64(pxar.TypeFormatVersion), le64(24), le64(2))
	checkRecord(t, "format version", pxar.AppendFormatVersion(nil, 2), want)
}

func TestAppendPayloadRef(t *testing.T) {
	want := golden(le64(pxar.TypePayloadRef), le64(32), le64(4096), le64(777))
	checkRecord(t, "payload ref", pxar.AppendPayloadRef(nil, 4096, 777), want)
}

func TestAppendPayloadMarkers(t *testing.T) {
	checkRecord(t, "payload start marker", pxar.AppendPayloadStartMarker(nil),
		golden(le64(pxar.PayloadStartMarker), le64(16)))
	checkRecord(t, "payload tail marker", pxar.AppendPayloadTailMarker(nil),
		golden(le64(pxar.PayloadTailMarker), le64(16)))
}
