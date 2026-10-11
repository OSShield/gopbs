//go:build !linux

package restore

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/osshield/gopbs/pxar"
)

// DefaultWriter returns the platform MetadataWriter.
func DefaultWriter() MetadataWriter { return portableWriter{} }

// portableWriter restores permissions (on Windows only the read-only bit
// means anything) and mtimes. Owners are silently left as they are — a
// Linux archive has them on every entry — while xattrs, ACLs and file
// capabilities are reported.
type portableWriter struct{}

func (portableWriter) Mknod(*os.Root, string, *pxar.Node) error {
	return fmt.Errorf("device, fifo and socket entries are not supported on %s", runtime.GOOS)
}

func (portableWriter) Apply(root *os.Root, name string, n *pxar.Node, warn func(error)) {
	if len(n.Xattrs) > 0 || n.ACL != nil || n.FCaps != nil {
		warn(fmt.Errorf("xattrs, ACLs and file capabilities are not restored on %s", runtime.GOOS))
	}
	if n.Mode&typeMask == modeSymlink {
		return
	}
	osName := filepath.FromSlash(name)
	if err := root.Chmod(osName, fs.FileMode(n.Mode&0o777)); err != nil {
		warn(fmt.Errorf("chmod: %w", err))
	}
	t := time.Unix(n.MtimeSecs, int64(n.MtimeNanos))
	if err := root.Chtimes(osName, t, t); err != nil {
		warn(fmt.Errorf("setting mtime: %w", err))
	}
}

// validName rejects names Windows cannot create: reserved characters,
// a trailing dot or space, and the reserved device names.
func validName(name string) error {
	if runtime.GOOS != "windows" {
		return nil
	}
	if strings.ContainsFunc(name, func(r rune) bool { return r < 32 || strings.ContainsRune(`<>:"\|?*`, r) }) ||
		strings.HasSuffix(name, ".") || strings.HasSuffix(name, " ") {
		return errors.New("name is not valid on Windows; entry skipped")
	}
	base, _, _ := strings.Cut(strings.ToUpper(name), ".")
	switch base {
	case "CON", "PRN", "AUX", "NUL",
		"COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
		"LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9":
		return errors.New("name is reserved on Windows; entry skipped")
	}
	return nil
}
