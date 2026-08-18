//go:build linux

package scan_test

import (
	"encoding/binary"
	"testing"

	"github.com/scheiblingco/gopbs/pxar"
	"github.com/scheiblingco/gopbs/scan"
)

func aclXattr(entries ...[3]uint32) []byte {
	buf := binary.LittleEndian.AppendUint32(nil, scan.ACLXattrVersion)
	for _, e := range entries {
		buf = binary.LittleEndian.AppendUint16(buf, uint16(e[0])) // tag
		buf = binary.LittleEndian.AppendUint16(buf, uint16(e[1])) // perm
		buf = binary.LittleEndian.AppendUint32(buf, e[2])         // id
	}
	return buf
}

const aclNoID = 0xffffffff

func TestParseACLXattrAccess(t *testing.T) {
	// user::rw-, user:1000:rw-, user:500:r--, group::r--, group:2000:rw-,
	// mask::rw-, other::r--
	data := aclXattr(
		[3]uint32{scan.ACLTagUserObj, 6, aclNoID},
		[3]uint32{scan.ACLTagUser, 6, 1000},
		[3]uint32{scan.ACLTagUser, 4, 500},
		[3]uint32{scan.ACLTagGroupObj, 4, aclNoID},
		[3]uint32{scan.ACLTagGroup, 6, 2000},
		[3]uint32{scan.ACLTagMask, 6, aclNoID},
		[3]uint32{scan.ACLTagOther, 4, aclNoID},
	)
	var out scan.ACLs
	if err := scan.ParseACLXattr(data, &out, false); err != nil {
		t.Fatal(err)
	}
	// Named users sorted by uid.
	if len(out.Users) != 2 || out.Users[0] != (pxar.ACLUser{UID: 500, Permissions: 4}) ||
		out.Users[1] != (pxar.ACLUser{UID: 1000, Permissions: 6}) {
		t.Errorf("users = %+v", out.Users)
	}
	if len(out.Groups) != 1 || out.Groups[0] != (pxar.ACLGroup{GID: 2000, Permissions: 6}) {
		t.Errorf("groups = %+v", out.Groups)
	}
	// Mask present: the owning group's real permissions surface as GroupObj.
	if out.GroupObj == nil || *out.GroupObj != 4 {
		t.Errorf("groupObj = %v, want 4", out.GroupObj)
	}
	if out.Default != nil {
		t.Error("access ACL must not populate Default")
	}
}

func TestParseACLXattrAccessNoMask(t *testing.T) {
	data := aclXattr(
		[3]uint32{scan.ACLTagUserObj, 7, aclNoID},
		[3]uint32{scan.ACLTagUser, 6, 1000},
		[3]uint32{scan.ACLTagGroupObj, 5, aclNoID},
		[3]uint32{scan.ACLTagOther, 0, aclNoID},
	)
	var out scan.ACLs
	if err := scan.ParseACLXattr(data, &out, false); err != nil {
		t.Fatal(err)
	}
	if out.GroupObj != nil {
		t.Error("without a mask, GroupObj must stay nil (mode group bits are authoritative)")
	}
}

func TestParseACLXattrDefault(t *testing.T) {
	data := aclXattr(
		[3]uint32{scan.ACLTagUserObj, 7, aclNoID},
		[3]uint32{scan.ACLTagGroupObj, 5, aclNoID},
		[3]uint32{scan.ACLTagOther, 1, aclNoID},
		[3]uint32{scan.ACLTagUser, 6, 42},
		[3]uint32{scan.ACLTagGroup, 4, 43},
	)
	var out scan.ACLs
	if err := scan.ParseACLXattr(data, &out, true); err != nil {
		t.Fatal(err)
	}
	want := pxar.ACLDefault{
		UserObjPermissions:  7,
		GroupObjPermissions: 5,
		OtherPermissions:    1,
		MaskPermissions:     pxar.ACLNoMask, // no mask entry
	}
	if out.Default == nil || *out.Default != want {
		t.Errorf("default = %+v, want %+v", out.Default, want)
	}
	if len(out.DefaultUsers) != 1 || out.DefaultUsers[0].UID != 42 {
		t.Errorf("defaultUsers = %+v", out.DefaultUsers)
	}
	if len(out.DefaultGroups) != 1 || out.DefaultGroups[0].GID != 43 {
		t.Errorf("defaultGroups = %+v", out.DefaultGroups)
	}
}

func TestParseACLXattrRejectsGarbage(t *testing.T) {
	var out scan.ACLs
	if err := scan.ParseACLXattr([]byte{1, 2, 3}, &out, false); err == nil {
		t.Error("short data must error")
	}
	bad := binary.LittleEndian.AppendUint32(nil, 99) // wrong version
	if err := scan.ParseACLXattr(bad, &out, false); err == nil {
		t.Error("wrong version must error")
	}
	trailing := append(aclXattr([3]uint32{scan.ACLTagUserObj, 7, aclNoID}), 0xff)
	if err := scan.ParseACLXattr(trailing, &out, false); err == nil {
		t.Error("non-multiple-of-8 entry data must error")
	}
}
