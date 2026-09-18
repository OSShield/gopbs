// Package archive turns scanned node trees into PXAR archive streams.
//
// A planner determines the archive structure and entry order up front from
// scan-time metadata; byte offsets are bound as late as possible
// via fstat when a file is dispatched for reading,
// goodbye tables and hardlink offsets from actually-emitted positions. File
// contents are read by a pool of workers and reassembled in plan order through
// a bounded reorder buffer, so generation is asynchronous by default while the
// output stream stays byte-identical to synchronous mode.
//
// Supports single-stream v1 output (plus a .pcat1 catalog) and split v2
// output (.mpxar metadata + .ppxar payload). Exclude patterns given via
// Options.Scan.Exclude are recorded in the archive the way the official
// client records --exclude (a .pxarexclude-cli root file in v1, the prelude
// record in v2).
package archive
