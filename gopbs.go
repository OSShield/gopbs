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
// This package ties them together with Backup: one call that scans, plans,
// generates, chunks, deduplicates and uploads with no intermediate files.
package gopbs

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/scheiblingco/gopbs/archive"
	"github.com/scheiblingco/gopbs/pbs"
)

// Format selects the pxar archive format.
type Format int

const (
	// FormatV1 is the classic single-stream pxar plus a .pcat1 catalog.
	FormatV1 Format = iota
	// FormatV2 is the split .mpxar/.ppxar format (not implemented yet).
	FormatV2
)

// BackupOptions configures one Backup call.
type BackupOptions struct {
	// Client configures the PBS connection (server, auth, datastore,
	// namespace, upload workers, chunk size).
	Client pbs.Config
	// Archive configures generation (name, workers, buffer, scan policy).
	// Its OnWarn is honored in addition to warnings being collected into
	// the result.
	Archive archive.Options
	// Ref identifies the snapshot; zero-value fields get the usual defaults
	// (type "host", hostname id, current time).
	Ref pbs.SnapshotRef
	// Format selects the archive format; only FormatV1 is implemented.
	Format Format
	// Paths are the directories and files to back up. A single directory
	// becomes the archive root; any other combination lives under a virtual
	// root named Archive.Name.
	Paths []string
	// Streams are virtual files backed by readers, placed under the virtual
	// root alongside Paths. Readers are consumed during the backup, so a
	// BackupOptions value with streams is good for one call.
	Streams []Stream
	// SkipCatalog omits the .pcat1 upload (the snapshot will not be
	// browsable in the PBS UI).
	SkipCatalog bool
	// OnProgress, when set, receives live upload progress: one call per
	// committed chunk plus a final call with Done=true per index. Setting it
	// costs one extra metadata scan (the size estimate for Total). Called
	// from the uploading goroutine; keep it fast.
	OnProgress func(Progress)
}

// Stream is a virtual file for BackupOptions.Streams. Size must be declared
// up front (the archive layout commits to it); a reader yielding a different
// byte count is padded or truncated to Size with a warning.
type Stream struct {
	Name   string
	Size   int64
	Reader io.Reader
}

// Progress is one live progress report during Backup.
type Progress struct {
	// Archive is the index being uploaded (e.g. "root.pxar.didx" or
	// "catalog.pcat1.didx").
	Archive string
	// Total is the estimated byte size of this index from scan metadata
	// (0 = unknown; the catalog has no estimate). The actual size may
	// differ slightly when files change during the backup.
	Total uint64
	// Stats carries the live counters; Stats.Size is the number of bytes
	// committed so far and grows monotonically per index.
	Stats pbs.UploadStats
	// Done marks the final report for this index.
	Done bool
}

// BackupResult reports a finished backup.
type BackupResult struct {
	// Ref is the snapshot identity as written (defaults resolved) — what a
	// restore addresses.
	Ref pbs.SnapshotRef
	// ArchiveName is the uploaded index name (e.g. "root.pxar.didx").
	ArchiveName string
	Archive     pbs.UploadStats
	Catalog     pbs.UploadStats
	// Warnings collects the non-fatal generation events (skipped entries,
	// padded/truncated files, torn reads).
	Warnings []archive.Warning
}

// Backup performs one complete backup: scan → plan → generate → chunk →
// deduplicate → upload → catalog → manifest → finish, fully streamed.
func Backup(ctx context.Context, opts BackupOptions) (*BackupResult, error) {
	if opts.Format != FormatV1 {
		return nil, fmt.Errorf("gopbs: format %d not implemented (only FormatV1)", opts.Format)
	}
	if len(opts.Paths) == 0 && len(opts.Streams) == 0 {
		return nil, fmt.Errorf("gopbs: nothing to back up")
	}

	result := &BackupResult{}

	archOpts := opts.Archive
	userWarn := archOpts.OnWarn
	archOpts.OnWarn = func(w archive.Warning) {
		result.Warnings = append(result.Warnings, w)
		if userWarn != nil {
			userWarn(w)
		}
	}
	arch, err := archive.New(archOpts)
	if err != nil {
		return nil, err
	}
	for _, path := range opts.Paths {
		info, err := os.Lstat(path)
		if err != nil {
			return nil, fmt.Errorf("gopbs: %w", err)
		}
		if info.IsDir() {
			err = arch.AddDirectory(path)
		} else {
			err = arch.AddFile(path)
		}
		if err != nil {
			return nil, err
		}
	}
	for _, s := range opts.Streams {
		if err := arch.AddStream(s.Name, s.Size, s.Reader); err != nil {
			return nil, err
		}
	}

	result.ArchiveName = arch.CatalogEntryName()

	clientCfg := opts.Client
	if opts.OnProgress != nil {
		archiveTotal, _ := arch.EstimatedSizeV1() // best effort; 0 on error
		userProgress := clientCfg.OnUploadProgress
		clientCfg.OnUploadProgress = func(name string, stats pbs.UploadStats, done bool) {
			if userProgress != nil {
				userProgress(name, stats, done)
			}
			p := Progress{Archive: name, Stats: stats, Done: done}
			if name == result.ArchiveName && archiveTotal > 0 {
				p.Total = uint64(archiveTotal)
			}
			opts.OnProgress(p)
		}
	}

	client, err := pbs.NewClient(clientCfg)
	if err != nil {
		return nil, err
	}
	sess, err := client.StartBackup(ctx, opts.Ref)
	if err != nil {
		return nil, err
	}
	defer sess.Abort() // no-op after a successful Finish
	result.Ref = sess.Ref()

	stream, err := arch.GenerateV1(ctx)
	if err != nil {
		return nil, err
	}
	result.Archive, err = sess.UploadPXARv1(ctx, result.ArchiveName, stream)
	stream.Close()
	if err != nil {
		return nil, err
	}

	if !opts.SkipCatalog {
		catStream, err := arch.GenerateCatalog(ctx)
		if err != nil {
			return nil, err
		}
		result.Catalog, err = sess.UploadCatalog(ctx, catStream)
		catStream.Close()
		if err != nil {
			return nil, err
		}
	}

	if err := sess.Finish(ctx); err != nil {
		return nil, err
	}
	return result, nil
}
