//go:build linux

package scan_test

import (
	"testing"

	"github.com/scheiblingco/gopbs/scan"
)

// FuzzParseACLXattr throws arbitrary bytes at the POSIX ACL xattr parser —
// it consumes raw filesystem data, so it must reject malformed input with an
// error, never a panic, in both access and default modes.
func FuzzParseACLXattr(f *testing.F) {
	// A well-formed access ACL: version header + user_obj/user/group_obj/
	// mask/other entries (id 0xffffffff where unused).
	valid := []byte{
		2, 0, 0, 0, // version 2
		1, 0, 7, 0, 0xff, 0xff, 0xff, 0xff, // ACL_USER_OBJ rwx
		2, 0, 6, 0, 42, 0, 0, 0, // ACL_USER uid 42 rw-
		4, 0, 4, 0, 0xff, 0xff, 0xff, 0xff, // ACL_GROUP_OBJ r--
		16, 0, 7, 0, 0xff, 0xff, 0xff, 0xff, // ACL_MASK rwx
		32, 0, 4, 0, 0xff, 0xff, 0xff, 0xff, // ACL_OTHER r--
	}
	f.Add(valid, false)
	f.Add(valid, true)
	f.Add([]byte{}, false)
	f.Add([]byte{2, 0, 0, 0}, true)

	f.Fuzz(func(t *testing.T, data []byte, isDefault bool) {
		var acls scan.ACLs
		if err := scan.ParseACLXattr(data, &acls, isDefault); err != nil {
			return
		}
		// Accepted input must parse identically on a second pass.
		var again scan.ACLs
		if err := scan.ParseACLXattr(data, &again, isDefault); err != nil {
			t.Fatalf("second parse failed: %v", err)
		}
		if len(again.Users) != len(acls.Users) || len(again.Groups) != len(acls.Groups) ||
			len(again.DefaultUsers) != len(acls.DefaultUsers) || len(again.DefaultGroups) != len(acls.DefaultGroups) {
			t.Fatal("parse is not deterministic")
		}
	})
}
