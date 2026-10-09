//go:build !windows

package archive

import "os"

// processIDs is the real uid/gid recorded on the .pxarexclude-cli entry
func processIDs() (uid, gid uint32) { return uint32(os.Getuid()), uint32(os.Getgid()) }
