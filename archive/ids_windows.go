//go:build windows

package archive

// processIDs: Windows has no numeric uid/gid; the entry is recorded as root's
// (os.Getuid would return -1 there)
func processIDs() (uid, gid uint32) { return 0, 0 }
