// Package pxar implements the PXAR archive format: record framing constants,
// encoders for every entry type (v1 and the v2 split-archive additions), and
// the goodbye-table construction (siphash naming hash plus the casync implicit
// binary search tree layout).
//
// The package is used for byte encoding and size calculation only, no filesystem
// access and no I/O. Every encoder has a matching size function used by
// the archive planner, so planned and emitted sizes can't diverge.
package pxar
