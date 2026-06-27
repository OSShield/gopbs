// Package pbs is a Proxmox Backup Server client for creating backups.
//
// It supports API-token and username/password (ticket) authentication,
// SHA-256 certificate fingerprint pinning, and the HTTP/2 backup protocol
// (proxmox-backup-protocol-v1): dynamic indexes, content-defined chunk upload
// with zstd compression and deduplication against the previous snapshot,
// blobs, manifest and finish. Chunk uploads run on a parallel pipeline while
// index order is preserved by sequence numbers.
package pbs
