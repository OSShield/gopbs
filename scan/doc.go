// Package scan walks filesystem trees into immutable node trees carrying the
// full metadata a PXAR archive needs: mode, ownership, timestamps, symlink
// targets, hardlink identity, device numbers, xattrs, POSIX ACLs, file
// capabilities and quota project IDs.
//
// Metadata is captured at scan time; file contents are deliberately not read
// here — they are streamed later by the archive emitter. Platform specifics
// live behind the MetadataReader interface; the full implementation
// targets Linux via golang.org/x/sys/unix.
package scan
