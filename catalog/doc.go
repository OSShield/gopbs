// Package catalog encodes the Proxmox .pcat1 catalog format used alongside
// PXAR v1 archives. Catalogs are written bottom-up (children's tables before
// their parents) so directory entries can reference child tables by backward
// delta, and terminated by a root pointer trailer (fixed little-endian u64).
//
// PXAR v2 split archives do not use a catalog; the metadata stream serves
// that role.
package catalog
