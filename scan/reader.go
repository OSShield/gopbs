package scan

import "github.com/osshield/gopbs/pxar"

// Stat is the lstat subset the scanner needs, in encoder-ready form.
type Stat struct {
	Mode       uint64 // full st_mode: type + permission bits
	UID        uint32
	GID        uint32
	MtimeSecs  int64
	MtimeNanos uint32
	Size       int64  // regular files: byte size at scan time
	Nlink      uint64 // hardlink count
	Dev        uint64 // containing device (hardlink identity)
	Ino        uint64 // inode number (hardlink identity)
	Rdev       pxar.Device
}

// Xattr is one extended attribute. Values may contain arbitrary bytes.
type Xattr struct {
	Name  string
	Value []byte
}

// ACLs holds a node's POSIX ACL entries in encoder-ready form. A nil *ACLs
// means the node has no ACL records to emit (a trivial ACL that only mirrors
// the mode bits does not count).
type ACLs struct {
	Users    []pxar.ACLUser  // named users (access ACL)
	Groups   []pxar.ACLGroup // named groups (access ACL)
	GroupObj *uint64         // owning-group permissions; set only when a mask entry exists

	Default       *pxar.ACLDefault // default ACL object permissions (directories)
	DefaultUsers  []pxar.ACLUser
	DefaultGroups []pxar.ACLGroup
}

// MetadataReader is the platform seam: everything the scanner asks of the
// filesystem. The full-fidelity implementation targets Linux; other platforms
// can supply degraded implementations without touching the walk or encoders.
//
// All methods must resolve the path without following a final symlink
// (l-variants). Absent metadata (no xattrs, no ACL, no fcaps) is a nil/empty
// result, not an error.
type MetadataReader interface {
	Lstat(path string) (Stat, error)
	// ReadDirNames returns the child names of a directory sorted in byte
	// order — the order pxar archives require.
	ReadDirNames(path string) ([]string, error)
	Readlink(path string) (string, error)
	// Xattrs returns generic extended attributes sorted by name, excluding
	// those represented by dedicated records (POSIX ACLs, security.capability).
	Xattrs(path string) ([]Xattr, error)
	ACLs(path string) (*ACLs, error)
	FCaps(path string) ([]byte, error)
	// QuotaProjID returns the filesystem quota project id and whether one is
	// set (project id 0 counts as unset).
	QuotaProjID(path string) (uint64, bool, error)
	// ReadFile returns the contents of a regular file (the scanner reads
	// .pxarexclude files with it). A missing file must be reported with an
	// error satisfying errors.Is(err, fs.ErrNotExist).
	ReadFile(path string) ([]byte, error)
}
