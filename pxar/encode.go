package pxar

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// Encoders are append-style and infallible: they extend dst with the record's
// exact bytes and return the result. Every variable-length record has a
// matching Size function; the archive planner uses those, so planned and
// emitted sizes come from one source of truth.

func appendHeader(dst []byte, typ, length uint64) []byte {
	dst = binary.LittleEndian.AppendUint64(dst, typ)
	return binary.LittleEndian.AppendUint64(dst, length)
}

// Entry is the stat record body (TypeEntry).
type Entry struct {
	Mode       uint64 // full st_mode: type bits + permission bits
	Flags      uint64
	UID        uint32
	GID        uint32
	MtimeSecs  int64  // seconds since epoch (may be negative)
	MtimeNanos uint32 // nanoseconds within MtimeSecs
}

// EntrySize is the full encoded size of an Entry record.
const EntrySize = HeaderSize + 40

// AppendEntry encodes e as a TypeEntry record.
func AppendEntry(dst []byte, e Entry) []byte {
	dst = appendHeader(dst, TypeEntry, EntrySize)
	dst = binary.LittleEndian.AppendUint64(dst, e.Mode)
	dst = binary.LittleEndian.AppendUint64(dst, e.Flags)
	dst = binary.LittleEndian.AppendUint32(dst, e.UID)
	dst = binary.LittleEndian.AppendUint32(dst, e.GID)
	dst = binary.LittleEndian.AppendUint64(dst, uint64(e.MtimeSecs))
	dst = binary.LittleEndian.AppendUint32(dst, e.MtimeNanos)
	return binary.LittleEndian.AppendUint32(dst, 0) // struct padding, always zero
}

// SizeFilename returns the encoded size of a TypeFilename record.
func SizeFilename(name string) uint64 { return HeaderSize + uint64(len(name)) + 1 }

// AppendFilename encodes a directory child's name (NUL-terminated).
func AppendFilename(dst []byte, name string) []byte {
	dst = appendHeader(dst, TypeFilename, SizeFilename(name))
	dst = append(dst, name...)
	return append(dst, 0)
}

// ValidateFilename reports whether name is usable as a pxar directory child
// name: non-empty, no '/', no NUL, and not "." or "..".
func ValidateFilename(name string) error {
	switch {
	case name == "":
		return errors.New("pxar: empty filename")
	case name == "." || name == "..":
		return fmt.Errorf("pxar: invalid filename %q", name)
	case strings.ContainsRune(name, '/'):
		return fmt.Errorf("pxar: filename %q contains '/'", name)
	case strings.ContainsRune(name, 0):
		return fmt.Errorf("pxar: filename %q contains NUL", name)
	}
	return nil
}

// SizeSymlink returns the encoded size of a TypeSymlink record.
func SizeSymlink(target string) uint64 { return HeaderSize + uint64(len(target)) + 1 }

// AppendSymlink encodes a symlink target (NUL-terminated).
func AppendSymlink(dst []byte, target string) []byte {
	dst = appendHeader(dst, TypeSymlink, SizeSymlink(target))
	dst = append(dst, target...)
	return append(dst, 0)
}

// Device is the body of a TypeDevice record.
type Device struct {
	Major uint64
	Minor uint64
}

// DeviceSize is the full encoded size of a Device record.
const DeviceSize = HeaderSize + 16

// AppendDevice encodes d as a TypeDevice record.
func AppendDevice(dst []byte, d Device) []byte {
	dst = appendHeader(dst, TypeDevice, DeviceSize)
	dst = binary.LittleEndian.AppendUint64(dst, d.Major)
	return binary.LittleEndian.AppendUint64(dst, d.Minor)
}

// SizeHardlink returns the encoded size of a TypeHardlink record.
func SizeHardlink(target string) uint64 { return HeaderSize + 8 + uint64(len(target)) + 1 }

// AppendHardlink encodes a hardlink record: offset is the distance in bytes
// from the start of this hardlink's own TypeFilename record back to the start
// of the link target's TypeFilename record (the upstream encoder's
// current_position - target_position); target is the archive-relative path of
// the target (NUL-terminated).
func AppendHardlink(dst []byte, offset uint64, target string) []byte {
	dst = appendHeader(dst, TypeHardlink, SizeHardlink(target))
	dst = binary.LittleEndian.AppendUint64(dst, offset)
	dst = append(dst, target...)
	return append(dst, 0)
}

// SizeXAttr returns the encoded size of a TypeXAttr record.
func SizeXAttr(name string, value []byte) uint64 {
	return HeaderSize + uint64(len(name)) + 1 + uint64(len(value))
}

// AppendXAttr encodes one extended attribute: name + NUL + value.
func AppendXAttr(dst []byte, name string, value []byte) []byte {
	dst = appendHeader(dst, TypeXAttr, SizeXAttr(name, value))
	dst = append(dst, name...)
	dst = append(dst, 0)
	return append(dst, value...)
}

// ACL permission bits (per entry, rwx as in POSIX ACLs).
const (
	ACLRead    uint64 = 4
	ACLWrite   uint64 = 2
	ACLExecute uint64 = 1
	// ACLNoMask marks an absent mask in ACLDefault.
	ACLNoMask uint64 = ^uint64(0)
)

// ACLUser is the body of TypeACLUser and TypeACLDefaultUser records.
type ACLUser struct {
	UID         uint64
	Permissions uint64
}

// ACLGroup is the body of TypeACLGroup and TypeACLDefaultGroup records.
type ACLGroup struct {
	GID         uint64
	Permissions uint64
}

// ACLDefault is the body of a TypeACLDefault record.
type ACLDefault struct {
	UserObjPermissions  uint64
	GroupObjPermissions uint64
	OtherPermissions    uint64
	MaskPermissions     uint64 // ACLNoMask when no mask entry exists
}

// Encoded sizes of the fixed-layout ACL records.
const (
	ACLUserSize     = HeaderSize + 16
	ACLGroupSize    = HeaderSize + 16
	ACLGroupObjSize = HeaderSize + 8
	ACLDefaultSize  = HeaderSize + 32
)

// AppendACLUser encodes a named-user ACL entry (TypeACLUser).
func AppendACLUser(dst []byte, a ACLUser) []byte {
	return appendUserBody(dst, TypeACLUser, a)
}

// AppendACLDefaultUser encodes a default named-user ACL entry (TypeACLDefaultUser).
func AppendACLDefaultUser(dst []byte, a ACLUser) []byte {
	return appendUserBody(dst, TypeACLDefaultUser, a)
}

func appendUserBody(dst []byte, typ uint64, a ACLUser) []byte {
	dst = appendHeader(dst, typ, ACLUserSize)
	dst = binary.LittleEndian.AppendUint64(dst, a.UID)
	return binary.LittleEndian.AppendUint64(dst, a.Permissions)
}

// AppendACLGroup encodes a named-group ACL entry (TypeACLGroup).
func AppendACLGroup(dst []byte, a ACLGroup) []byte {
	return appendGroupBody(dst, TypeACLGroup, a)
}

// AppendACLDefaultGroup encodes a default named-group ACL entry (TypeACLDefaultGroup).
func AppendACLDefaultGroup(dst []byte, a ACLGroup) []byte {
	return appendGroupBody(dst, TypeACLDefaultGroup, a)
}

func appendGroupBody(dst []byte, typ uint64, a ACLGroup) []byte {
	dst = appendHeader(dst, typ, ACLGroupSize)
	dst = binary.LittleEndian.AppendUint64(dst, a.GID)
	return binary.LittleEndian.AppendUint64(dst, a.Permissions)
}

// AppendACLGroupObj encodes the owning-group permissions (TypeACLGroupObj),
// present when a mask entry makes the stat group bits carry the mask instead.
func AppendACLGroupObj(dst []byte, permissions uint64) []byte {
	dst = appendHeader(dst, TypeACLGroupObj, ACLGroupObjSize)
	return binary.LittleEndian.AppendUint64(dst, permissions)
}

// AppendACLDefault encodes the default-ACL object permissions (TypeACLDefault).
func AppendACLDefault(dst []byte, a ACLDefault) []byte {
	dst = appendHeader(dst, TypeACLDefault, ACLDefaultSize)
	dst = binary.LittleEndian.AppendUint64(dst, a.UserObjPermissions)
	dst = binary.LittleEndian.AppendUint64(dst, a.GroupObjPermissions)
	dst = binary.LittleEndian.AppendUint64(dst, a.OtherPermissions)
	return binary.LittleEndian.AppendUint64(dst, a.MaskPermissions)
}

// SizeFCaps returns the encoded size of a TypeFCaps record.
func SizeFCaps(data []byte) uint64 { return HeaderSize + uint64(len(data)) }

// AppendFCaps encodes the raw security.capability xattr value.
func AppendFCaps(dst []byte, data []byte) []byte {
	dst = appendHeader(dst, TypeFCaps, SizeFCaps(data))
	return append(dst, data...)
}

// QuotaProjIDSize is the full encoded size of a TypeQuotaProjID record.
const QuotaProjIDSize = HeaderSize + 8

// AppendQuotaProjID encodes a filesystem quota project id.
func AppendQuotaProjID(dst []byte, projid uint64) []byte {
	dst = appendHeader(dst, TypeQuotaProjID, QuotaProjIDSize)
	return binary.LittleEndian.AppendUint64(dst, projid)
}

// SizePayload returns the full encoded size of a payload record whose content
// is size bytes: the header plus the raw content that follows it.
func SizePayload(size uint64) uint64 { return HeaderSize + size }

// AppendPayloadHeader encodes the header of a TypePayload record. The size
// bytes of raw file content follow the header in the stream; they are written
// by the emitter, not by this package.
func AppendPayloadHeader(dst []byte, size uint64) []byte {
	return appendHeader(dst, TypePayload, SizePayload(size))
}
