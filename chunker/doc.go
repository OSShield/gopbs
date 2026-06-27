// Package chunker implements the buzhash content-defined chunker used by
// Proxmox Backup Server (a port of pbs-datastore's chunker): a 64-byte rolling
// window over the casync hash table, cutting chunks between min (avg/4) and
// max (avg*4) with a 4 MiB default average.
package chunker
