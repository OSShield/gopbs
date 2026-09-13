//go:build windows

package scan

import (
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// DefaultReader returns the platform MetadataReader.
//
// The Windows reader maps NTFS metadata onto the POSIX-shaped Stat the
// archive format expects: directories, regular files and symbolic links
// (including junctions) keep their type; the mode's permission bits are
// synthesised (0755 for directories, 0644 for files, 0444 for read-only
// files, 0777 for links) and ownership is recorded as uid/gid 0. Hardlinks
// are detected through the volume serial and file index. Extended
// attributes, ACLs, capabilities and quota ids are not archived.
func DefaultReader() (MetadataReader, error) { return windowsReader{}, nil }

type windowsReader struct{}

// Reparse tags that behave like symbolic links; every other reparse point
// (deduplicated files, cloud placeholders, …) is treated by its base type.
const (
	reparseTagSymlink    = 0xA000000C
	reparseTagMountPoint = 0xA0000003
)

// fileAttributeTagInfo is FILE_ATTRIBUTE_TAG_INFO
type fileAttributeTagInfo struct {
	FileAttributes uint32
	ReparseTag     uint32
}

// winPath turns a clean absolute path into its extended-length form so paths
// longer than MAX_PATH work: \\?\C:\dir and \\?\UNC\server\share\dir
func winPath(path string) string {
	switch {
	case strings.HasPrefix(path, `\\?\`) || strings.HasPrefix(path, `\\.\`):
		return path
	case strings.HasPrefix(path, `\\`):
		return `\\?\UNC\` + strings.TrimPrefix(path, `\\`)
	case len(path) >= 2 && path[1] == ':':
		return `\\?\` + path
	}
	return path
}

func (windowsReader) Lstat(path string) (Stat, error) {
	return winStat(path, true)
}

// Stat follows a final symlink or junction (Follower)
func (windowsReader) Stat(path string) (Stat, error) {
	return winStat(path, false)
}

func winStat(path string, noFollow bool) (Stat, error) {
	op := "stat"
	flags := uint32(windows.FILE_FLAG_BACKUP_SEMANTICS)
	if noFollow {
		op = "lstat"
		flags |= windows.FILE_FLAG_OPEN_REPARSE_POINT
	}
	name, err := windows.UTF16PtrFromString(winPath(path))
	if err != nil {
		return Stat{}, &os.PathError{Op: op, Path: path, Err: err}
	}
	// Attribute-only access with full sharing: locked files must still be
	// stat-able; BACKUP_SEMANTICS opens directories, OPEN_REPARSE_POINT keeps
	// links from being followed
	h, err := windows.CreateFile(name, windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, flags, 0)
	if err != nil {
		return Stat{}, &os.PathError{Op: op, Path: path, Err: err}
	}
	defer windows.CloseHandle(h)

	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return Stat{}, &os.PathError{Op: op, Path: path, Err: err}
	}
	attrs := info.FileAttributes
	var mode uint64
	switch {
	case attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 && isLinkReparse(h):
		mode = ModeSymlink | 0o777
	case attrs&windows.FILE_ATTRIBUTE_DIRECTORY != 0:
		mode = ModeDir | 0o755
	case attrs&windows.FILE_ATTRIBUTE_READONLY != 0:
		mode = ModeRegular | 0o444
	default:
		mode = ModeRegular | 0o644
	}
	secs, nanos := splitNanos(info.LastWriteTime.Nanoseconds())
	st := Stat{
		Mode:       mode,
		MtimeSecs:  secs,
		MtimeNanos: nanos,
		Nlink:      uint64(info.NumberOfLinks),
		Dev:        uint64(info.VolumeSerialNumber),
		Ino:        uint64(info.FileIndexHigh)<<32 | uint64(info.FileIndexLow),
	}
	if mode&ModeTypeMask == ModeRegular {
		st.Size = int64(info.FileSizeHigh)<<32 | int64(info.FileSizeLow)
	}
	return st, nil
}

// isLinkReparse reports whether an open reparse point is a symbolic link or a
// junction (mount point)
func isLinkReparse(h windows.Handle) bool {
	var tag fileAttributeTagInfo
	if err := windows.GetFileInformationByHandleEx(h, windows.FileAttributeTagInfo, (*byte)(unsafe.Pointer(&tag)), uint32(unsafe.Sizeof(tag))); err != nil {
		return false
	}
	return tag.ReparseTag == reparseTagSymlink || tag.ReparseTag == reparseTagMountPoint
}

// splitNanos splits Unix nanoseconds into seconds and a non-negative
// nanosecond remainder (times before 1970 are negative)
func splitNanos(ns int64) (int64, uint32) {
	secs := ns / 1e9
	rem := ns % 1e9
	if rem < 0 {
		secs--
		rem += 1e9
	}
	return secs, uint32(rem)
}

func (windowsReader) ReadDirNames(path string) ([]string, error) {
	entries, err := os.ReadDir(path) // sorted by name: byte order for UTF-8
	if err != nil {
		return nil, err
	}
	names := make([]string, len(entries))
	for i, e := range entries {
		names[i] = e.Name()
	}
	return names, nil
}

// Readlink returns the link target with forward slashes, so a relative link
// restored on any platform still resolves within the archive
func (windowsReader) Readlink(path string) (string, error) {
	target, err := os.Readlink(path)
	if err != nil {
		return "", err
	}
	return strings.ReplaceAll(target, `\`, "/"), nil
}

func (windowsReader) ReadFile(path string) ([]byte, error) { return os.ReadFile(path) }

func (windowsReader) Xattrs(string) ([]Xattr, error) { return nil, nil }
func (windowsReader) ACLs(string) (*ACLs, error)     { return nil, nil }
func (windowsReader) FCaps(string) ([]byte, error)   { return nil, nil }
func (windowsReader) QuotaProjID(string) (uint64, bool, error) {
	return 0, false, nil
}
