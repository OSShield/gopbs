// Package pxar implements the PXAR archive format: record framing constants,
// encoders for every entry type (v1 and the v2 split-archive additions), and
// the goodbye-table construction (siphash naming hash plus the casync implicit
// binary search tree layout), and Reader, a validating decoder for v1
// archives and v2 split pairs.
//
// The package does no filesystem access and has no I/O policy: encoders
// append bytes, Reader consumes the io.Reader/io.ReaderAt it is given. Every
// encoder has a matching size function used by the archive planner, so
// planned and emitted sizes can't diverge.
package pxar
