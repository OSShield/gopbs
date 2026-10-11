//go:build linux

package restore

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"

	"github.com/osshield/gopbs/pxar"
	"golang.org/x/sys/unix"
)

// DefaultWriter returns the platform MetadataWriter.
func DefaultWriter() MetadataWriter { return linuxWriter{} }

// linuxWriter applies full metadata through *at calls on the entry's parent
// directory, never following a final symlink. Xattrs, ACLs and file
// capabilities need an open file, so they are applied to regular files and
// directories only.
type linuxWriter struct{}

func validName(string) error { return nil }

// openParent opens the directory holding name ("." for the root itself).
func openParent(root *os.Root, name string) (*os.File, string, error) {
	parent, base := path.Dir(name), path.Base(name)
	if name == "." {
		parent = "."
	}
	dir, err := root.Open(filepath.FromSlash(parent))
	return dir, base, err
}

func (linuxWriter) Mknod(root *os.Root, name string, n *pxar.Node) error {
	dir, base, err := openParent(root, name)
	if err != nil {
		return err
	}
	defer dir.Close()
	dev := unix.Mkdev(uint32(n.Device.Major), uint32(n.Device.Minor))
	return unix.Mknodat(int(dir.Fd()), base, uint32(n.Mode&(typeMask|0o777)), int(dev))
}

func (linuxWriter) Apply(root *os.Root, name string, n *pxar.Node, warn func(error)) {
	dir, base, err := openParent(root, name)
	if err != nil {
		warn(err)
		return
	}
	defer dir.Close()
	dfd := int(dir.Fd())
	typ := n.Mode & typeMask

	if err := unix.Fchownat(dfd, base, int(n.UID), int(n.GID), unix.AT_SYMLINK_NOFOLLOW); err != nil {
		warn(fmt.Errorf("chown %d:%d: %w", n.UID, n.GID, err))
	}
	// After chown, which clears file capabilities and setuid bits.
	if len(n.Xattrs) > 0 || n.ACL != nil || n.FCaps != nil {
		if typ == modeRegular || typ == modeDir {
			setXattrs(dfd, base, n, warn)
		} else {
			warn(errors.New("xattrs, ACLs and file capabilities are not restored on this file type"))
		}
	}
	if n.QuotaProjID != 0 {
		warn(errors.New("quota project id not restored"))
	}
	if typ != modeSymlink {
		if err := unix.Fchmodat(dfd, base, uint32(n.Mode&0o7777), 0); err != nil {
			warn(fmt.Errorf("chmod: %w", err))
		}
	}
	mtime := unix.NsecToTimespec(n.MtimeSecs*1e9 + int64(n.MtimeNanos))
	if err := unix.UtimesNanoAt(dfd, base, []unix.Timespec{mtime, mtime}, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		warn(fmt.Errorf("setting mtime: %w", err))
	}
}

func setXattrs(dfd int, base string, n *pxar.Node, warn func(error)) {
	fd, err := unix.Openat(dfd, base, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		warn(fmt.Errorf("opening for xattrs: %w", err))
		return
	}
	defer unix.Close(fd)
	set := func(name string, value []byte) {
		if err := unix.Fsetxattr(fd, name, value, 0); err != nil {
			warn(fmt.Errorf("xattr %s: %w", name, err))
		}
	}
	for _, x := range n.Xattrs {
		set(x.Name, x.Value)
	}
	if acl := n.ACL; acl != nil {
		if len(acl.Users) > 0 || len(acl.Groups) > 0 || acl.GroupObj != nil {
			set("system.posix_acl_access", accessACL(n.Mode, acl))
		}
		if acl.Default != nil {
			set("system.posix_acl_default", defaultACL(acl))
		}
	}
	if n.FCaps != nil {
		set("security.capability", n.FCaps)
	}
}

// POSIX ACL xattr encoding (linux/posix_acl_xattr.h): a version header,
// then (tag, perm, id) entries in tag order.
const (
	aclVersion     = 2
	aclTagUserObj  = 0x01
	aclTagUser     = 0x02
	aclTagGroupObj = 0x04
	aclTagGroup    = 0x08
	aclTagMask     = 0x10
	aclTagOther    = 0x20
	aclUndefinedID = 0xffffffff
)

func appendACLEntry(b []byte, tag uint16, perm uint64, id uint32) []byte {
	b = binary.LittleEndian.AppendUint16(b, tag)
	b = binary.LittleEndian.AppendUint16(b, uint16(perm))
	return binary.LittleEndian.AppendUint32(b, id)
}

// accessACL inverts the scanner's mapping: with a mask, the stat group bits
// carry the mask and GroupObj the owning group's permissions.
func accessACL(mode uint64, acl *pxar.ACLs) []byte {
	b := binary.LittleEndian.AppendUint32(nil, aclVersion)
	b = appendACLEntry(b, aclTagUserObj, mode>>6&7, aclUndefinedID)
	for _, u := range acl.Users {
		b = appendACLEntry(b, aclTagUser, u.Permissions, uint32(u.UID))
	}
	groupObj := mode >> 3 & 7
	if acl.GroupObj != nil {
		groupObj = *acl.GroupObj
	}
	b = appendACLEntry(b, aclTagGroupObj, groupObj, aclUndefinedID)
	for _, g := range acl.Groups {
		b = appendACLEntry(b, aclTagGroup, g.Permissions, uint32(g.GID))
	}
	if acl.GroupObj != nil {
		b = appendACLEntry(b, aclTagMask, mode>>3&7, aclUndefinedID)
	}
	return appendACLEntry(b, aclTagOther, mode&7, aclUndefinedID)
}

func defaultACL(acl *pxar.ACLs) []byte {
	d := acl.Default
	b := binary.LittleEndian.AppendUint32(nil, aclVersion)
	b = appendACLEntry(b, aclTagUserObj, d.UserObjPermissions, aclUndefinedID)
	for _, u := range acl.DefaultUsers {
		b = appendACLEntry(b, aclTagUser, u.Permissions, uint32(u.UID))
	}
	b = appendACLEntry(b, aclTagGroupObj, d.GroupObjPermissions, aclUndefinedID)
	for _, g := range acl.DefaultGroups {
		b = appendACLEntry(b, aclTagGroup, g.Permissions, uint32(g.GID))
	}
	if d.MaskPermissions != pxar.ACLNoMask {
		b = appendACLEntry(b, aclTagMask, d.MaskPermissions, aclUndefinedID)
	}
	return appendACLEntry(b, aclTagOther, d.OtherPermissions, aclUndefinedID)
}
