// Package gopbs creates PXAR archives (Proxmox archive format, versions 1 and 2)
// and uploads them to Proxmox Backup Server.
//
// The subpackages are usable independently:
//
//   - pxar: the pure PXAR format layer (record encoders, goodbye tables)
//   - catalog: the .pcat1 catalog encoder (v1 archives)
//   - scan: filesystem scanning with full metadata recording (Linux only currently)
//   - archive: archive planning and (async) stream generation
//   - chunker: the buzhash chunker used by PBS
//   - pbs: the Proxmox Backup Server client (backup sessions, chunk upload)
//
// This package ties them together with a one-call Backup orchestrator that
// streams data directly into upload with no intermediate files.
package gopbs
