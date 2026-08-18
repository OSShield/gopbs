//go:build linux

package scan

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"unsafe"

	"github.com/scheiblingco/gopbs/pxar"
	"golang.org/x/sys/unix"
)

// DefaultReader returns the platform MetadataReader.
func DefaultReader() (MetadataReader, error) { return linuxReader{}, nil }

type linuxReader struct{}

func (linuxReader) Lstat(path string) (Stat, error) {
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return Stat{}, &os.PathError{Op: "lstat", Path: path, Err: err}
	}
	return Stat{
		Mode:       uint64(st.Mode),
		UID:        st.Uid,
		GID:        st.Gid,
		MtimeSecs:  st.Mtim.Sec,
		MtimeNanos: uint32(st.Mtim.Nsec),
		Size:       st.Size,
		Nlink:      uint64(st.Nlink),
		Dev:        uint64(st.Dev),
		Ino:        st.Ino,
		Rdev: pxar.Device{
			Major: uint64(unix.Major(uint64(st.Rdev))),
			Minor: uint64(unix.Minor(uint64(st.Rdev))),
		},
	}, nil
}

func (linuxReader) ReadDirNames(path string) ([]string, error) {
	entries, err := os.ReadDir(path) // sorted by filename byte order
	if err != nil {
		return nil, err
	}
	names := make([]string, len(entries))
	for i, e := range entries {
		names[i] = e.Name()
	}
	return names, nil
}

func (linuxReader) Readlink(path string) (string, error) {
	return os.Readlink(path)
}

const (
	xattrACLAccess  = "system.posix_acl_access"
	xattrACLDefault = "system.posix_acl_default"
	xattrFCaps      = "security.capability"
)

func (linuxReader) Xattrs(path string) ([]Xattr, error) {
	names, err := listXattrNames(path)
	if err != nil || len(names) == 0 {
		return nil, err
	}
	var out []Xattr
	for _, name := range names {
		// ACLs and fcaps have dedicated pxar records; kernel-internal
		// system.* attributes are not archivable.
		if strings.HasPrefix(name, "system.") || name == xattrFCaps {
			continue
		}
		value, err := getXattr(path, name)
		if err != nil {
			if isNoData(err) {
				continue // removed between list and get
			}
			return nil, fmt.Errorf("xattr %s: %w", name, err)
		}
		out = append(out, Xattr{Name: name, Value: value})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (linuxReader) FCaps(path string) ([]byte, error) {
	value, err := getXattr(path, xattrFCaps)
	if err != nil {
		if isNoData(err) || isNotSupported(err) {
			return nil, nil
		}
		return nil, err
	}
	return value, nil
}

func (linuxReader) ACLs(path string) (*ACLs, error) {
	var out ACLs

	access, err := getXattr(path, xattrACLAccess)
	if err != nil && !isNoData(err) && !isNotSupported(err) {
		return nil, err
	}
	if access != nil {
		if err := parseACLXattr(access, &out, false); err != nil {
			return nil, fmt.Errorf("%s: %w", xattrACLAccess, err)
		}
	}

	deflt, err := getXattr(path, xattrACLDefault)
	if err != nil && !isNoData(err) && !isNotSupported(err) {
		return nil, err
	}
	if deflt != nil {
		if err := parseACLXattr(deflt, &out, true); err != nil {
			return nil, fmt.Errorf("%s: %w", xattrACLDefault, err)
		}
	}

	if len(out.Users) == 0 && len(out.Groups) == 0 && out.GroupObj == nil &&
		out.Default == nil && len(out.DefaultUsers) == 0 && len(out.DefaultGroups) == 0 {
		return nil, nil
	}
	return &out, nil
}

// POSIX ACL xattr wire format: u32 LE version (2), then 8-byte entries of
// {tag u16, perm u16, id u32}, all little-endian.
const (
	aclVersion     = 2
	aclTagUserObj  = 0x01
	aclTagUser     = 0x02
	aclTagGroupObj = 0x04
	aclTagGroup    = 0x08
	aclTagMask     = 0x10
	aclTagOther    = 0x20
)

// parseACLXattr decodes one system.posix_acl_* value into out. The access
// ACL contributes named users/groups, plus the owning-group permissions when
// a mask exists (the mode's group bits then carry the mask instead). The
// default ACL always contributes an ACLDefault record plus its named entries.
func parseACLXattr(data []byte, out *ACLs, isDefault bool) error {
	if len(data) < 4 || (len(data)-4)%8 != 0 {
		return fmt.Errorf("invalid acl xattr length %d", len(data))
	}
	if v := binary.LittleEndian.Uint32(data); v != aclVersion {
		return fmt.Errorf("unsupported acl version %d", v)
	}

	var (
		users    []pxar.ACLUser
		groups   []pxar.ACLGroup
		userObj  uint64
		groupObj uint64
		other    uint64
		mask     uint64
		haveMask bool
	)
	for rest := data[4:]; len(rest) >= 8; rest = rest[8:] {
		tag := binary.LittleEndian.Uint16(rest)
		perm := uint64(binary.LittleEndian.Uint16(rest[2:]))
		id := binary.LittleEndian.Uint32(rest[4:])
		switch tag {
		case aclTagUserObj:
			userObj = perm
		case aclTagUser:
			users = append(users, pxar.ACLUser{UID: uint64(id), Permissions: perm})
		case aclTagGroupObj:
			groupObj = perm
		case aclTagGroup:
			groups = append(groups, pxar.ACLGroup{GID: uint64(id), Permissions: perm})
		case aclTagMask:
			mask, haveMask = perm, true
		case aclTagOther:
			other = perm
		default:
			return fmt.Errorf("unknown acl tag %#x", tag)
		}
	}
	sort.Slice(users, func(i, j int) bool { return users[i].UID < users[j].UID })
	sort.Slice(groups, func(i, j int) bool { return groups[i].GID < groups[j].GID })

	if isDefault {
		d := pxar.ACLDefault{
			UserObjPermissions:  userObj,
			GroupObjPermissions: groupObj,
			OtherPermissions:    other,
			MaskPermissions:     pxar.ACLNoMask,
		}
		if haveMask {
			d.MaskPermissions = mask
		}
		out.Default = &d
		out.DefaultUsers = users
		out.DefaultGroups = groups
		return nil
	}

	out.Users = users
	out.Groups = groups
	if haveMask {
		g := groupObj
		out.GroupObj = &g
	}
	return nil
}

// fsxattr layout from linux/uapi/fs.h; FS_IOC_FSGETXATTR = _IOR('X', 31, fsxattr).
type fsxattr struct {
	Xflags     uint32
	Extsize    uint32
	Nextents   uint32
	Projid     uint32
	Cowextsize uint32
	Pad        [8]byte
}

const fsIocFsGetXattr = 0x801c581f

func (linuxReader) QuotaProjID(path string) (uint64, bool, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return 0, false, &os.PathError{Op: "open", Path: path, Err: err}
	}
	defer unix.Close(fd)

	var fsx fsxattr
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), fsIocFsGetXattr, uintptr(unsafe.Pointer(&fsx)))
	if errno != 0 {
		// Filesystems without project quota support are not an error.
		if errno == unix.ENOTTY || errno == unix.EOPNOTSUPP || errno == unix.EINVAL || errno == unix.ENOSYS {
			return 0, false, nil
		}
		return 0, false, &os.PathError{Op: "ioctl FS_IOC_FSGETXATTR", Path: path, Err: errno}
	}
	return uint64(fsx.Projid), fsx.Projid != 0, nil
}

func listXattrNames(path string) ([]string, error) {
	for {
		size, err := unix.Llistxattr(path, nil)
		if err != nil {
			if isNotSupported(err) {
				return nil, nil
			}
			return nil, &os.PathError{Op: "llistxattr", Path: path, Err: err}
		}
		if size == 0 {
			return nil, nil
		}
		buf := make([]byte, size)
		size, err = unix.Llistxattr(path, buf)
		if err != nil {
			if errors.Is(err, unix.ERANGE) {
				continue // list grew between calls
			}
			return nil, &os.PathError{Op: "llistxattr", Path: path, Err: err}
		}
		var names []string
		for _, name := range strings.Split(string(buf[:size]), "\x00") {
			if name != "" {
				names = append(names, name)
			}
		}
		return names, nil
	}
}

func getXattr(path, name string) ([]byte, error) {
	for {
		size, err := unix.Lgetxattr(path, name, nil)
		if err != nil {
			return nil, &os.PathError{Op: "lgetxattr " + name, Path: path, Err: err}
		}
		buf := make([]byte, size)
		size, err = unix.Lgetxattr(path, name, buf)
		if err != nil {
			if errors.Is(err, unix.ERANGE) {
				continue // value grew between calls
			}
			return nil, &os.PathError{Op: "lgetxattr " + name, Path: path, Err: err}
		}
		return buf[:size], nil
	}
}

func isNoData(err error) bool {
	return errors.Is(err, unix.ENODATA)
}

func isNotSupported(err error) bool {
	return errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.ENOTSUP)
}
