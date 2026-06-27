package pxar

import "github.com/dchest/siphash"

// Record type identifiers. Every item in a pxar stream is framed as a 16-byte
// header — type (u64 LE) followed by length (u64 LE, including the header) —
// and a body. Values match proxmox/pxar src/format/mod.rs.
const (
	// TypeEntry is the stat record: mode, flags, uid, gid, mtime.
	TypeEntry uint64 = 0xd5956474e588acef
	// TypeEntryV1 is the obsolete stat record layout of early pxar versions.
	// Decode-only concern; never emitted.
	TypeEntryV1 uint64 = 0x11da850a1c1cceff
	// TypeFilename precedes each directory child: name bytes + NUL.
	TypeFilename uint64 = 0x16701121063917b3
	// TypeSymlink carries the link target: target bytes + NUL.
	TypeSymlink uint64 = 0x27f971e7dbf5dc5f
	// TypeDevice carries major/minor numbers for block and char devices.
	TypeDevice uint64 = 0x9fc9e906586d5ce9
	// TypeXAttr carries one extended attribute: name + NUL + value.
	TypeXAttr uint64 = 0x0dab0229b57dcd03
	// ACL record types; bodies are defined in encode.go.
	TypeACLUser         uint64 = 0x2ce8540a457d55b8
	TypeACLGroup        uint64 = 0x136e3eceb04c03ab
	TypeACLGroupObj     uint64 = 0x10868031e9582876
	TypeACLDefault      uint64 = 0xbbbb13415a6896f5
	TypeACLDefaultUser  uint64 = 0xc89357b40532cd1f
	TypeACLDefaultGroup uint64 = 0xf90a8a5816038ffe
	// TypeFCaps carries the raw security.capability xattr value.
	TypeFCaps uint64 = 0x2da9dd9db5f7fb67
	// TypeQuotaProjID carries the filesystem quota project id.
	TypeQuotaProjID uint64 = 0xe07540e82f7d1cbb
	// TypeHardlink references an earlier entry: offset (u64) + path + NUL.
	TypeHardlink uint64 = 0x51269c8422bd7275
	// TypePayload frames regular file content.
	TypePayload uint64 = 0x28147a1b0b7c1a25
	// TypeGoodbye terminates a directory: a BST of per-child items.
	TypeGoodbye uint64 = 0x2fec4fa642d5731d
	// GoodbyeTailMarker is the hash value of the final goodbye item.
	GoodbyeTailMarker uint64 = 0xef5eed5b753e1555

	// v2 (split archive) additions.
	TypeFormatVersion  uint64 = 0x730f6c75df16a40d
	TypePrelude        uint64 = 0xe309d79d9f7b771b
	TypePayloadRef     uint64 = 0x419d3d6bc4ba977e
	PayloadStartMarker uint64 = 0x834c68c2194a4ed2
	PayloadTailMarker  uint64 = 0x6c72b78b984c81b5
)

// SipHash-2-4 keys for goodbye-table name hashing:
//
//	$ echo -n 'PROXMOX ARCHIVE FORMAT' | sha1sum
const (
	hashKey1 uint64 = 0x83ac3f1cfbb450db
	hashKey2 uint64 = 0xaa4f1b6879369fbd
)

// HeaderSize is the size of the type+length framing of every record.
const HeaderSize = 16

// Hash returns the goodbye-table hash of a directory child's basename.
func Hash(name string) uint64 {
	return siphash.Hash(hashKey1, hashKey2, []byte(name))
}
