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
	"strings"

	"github.com/osshield/gopbs/archive"
	"github.com/osshield/gopbs/pbs"
)

// Format selects the pxar archive format.
type Format int

const (
	// FormatV1 is the classic single-stream pxar plus a .pcat1 catalog.
	FormatV1 Format = iota
	// FormatV2 is the split format: a metadata stream (.mpxar) and a payload
	// stream (.ppxar) uploaded as two dynamic indexes. No catalog — the
	// metadata stream itself serves browsing. Requires proxmox-backup-client
	// >= 3.2 to restore.
	FormatV2
)

// BackupOptions configures one Backup call.
type BackupOptions struct {
	// Client configures the PBS connection (server, auth, datastore,
	// namespace, upload workers, chunk size). Set Client.Crypt to encrypt
	// the backup client-side (or sign its manifest); see pbs.CryptConfig.
	Client pbs.Config
	// Archive configures generation (name, workers, buffer, scan policy).
	// Its OnWarn is honored in addition to warnings being collected into
	// the result.
	Archive archive.Options
	// Ref identifies the snapshot; zero-value fields get the usual defaults
	// (type "host", hostname id, current time).
	Ref pbs.SnapshotRef
	// Format selects the archive format (FormatV1 or FormatV2).
	Format Format
	// Paths are the directories and files to back up. A single directory
	// becomes the archive root; any other combination lives under a virtual
	// root named Archive.Name.
	Paths []string
	// Streams are virtual files backed by readers, placed under the virtual
	// root alongside Paths. Readers are consumed during the backup, so a
	// BackupOptions value with streams is good for one call.
	Streams []Stream
	// Blobs are uploaded as separate blob files in the snapshot, alongside
	// the archive indexes and listed in the manifest — they are not part of
	// the archive. Use them for backup metadata PBS has no native place for
	// (application state, retention hints, tool versions, …). Contents are
	// downloaded back with `proxmox-backup-client restore <snapshot>
	// <name>.blob <target>`.
	Blobs []Blob
	// SkipCatalog omits the .pcat1 upload (the snapshot will not be
	// browsable in the PBS UI). FormatV1 only; v2 has no catalog.
	SkipCatalog bool
	// OnProgress, when set, receives live upload progress: one call per
	// committed chunk plus a final call with Done=true per index. Setting it
	// costs one extra metadata scan (the size estimate for Total). Called
	// from the uploading goroutine; keep it fast. FormatV2 uploads its two
	// indexes concurrently, so calls can arrive from two goroutines at once —
	// synchronize any shared state.
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

// Blob is a metadata file for BackupOptions.Blobs: stored in the snapshot as
// "<Name>.blob" (the suffix is appended when missing), zstd-compressed when
// that is smaller. Data is held in memory — blobs are for small metadata;
// bulk content belongs in the archive or a Stream. The name "index.json" is
// reserved for the manifest, "rsa-encrypted.key" for the wrapped encryption
// key. Blobs are encrypted when Client.Crypt is in encrypt mode.
type Blob struct {
	Name string
	Data []byte
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
	// ArchiveName is the uploaded index name: "<base>.pxar.didx" for v1, the
	// metadata stream's "<base>.mpxar.didx" for v2.
	ArchiveName string
	// Archive is the pxar index's upload stats (the metadata stream's, for
	// v2).
	Archive pbs.UploadStats
	// Catalog is the .pcat1 index's upload stats (v1 only).
	Catalog pbs.UploadStats
	// Payload is the payload stream's ("<base>.ppxar.didx") upload stats
	// (v2 only).
	Payload pbs.UploadStats
	// Warnings collects the non-fatal generation events (skipped entries,
	// padded/truncated files, torn reads).
	Warnings []archive.Warning
}

// Backup performs one complete backup: scan → plan → generate → chunk →
// deduplicate → upload → catalog → manifest → finish, fully streamed.
func Backup(ctx context.Context, opts BackupOptions) (*BackupResult, error) {
	if opts.Format != FormatV1 && opts.Format != FormatV2 {
		return nil, fmt.Errorf("gopbs: unknown format %d", opts.Format)
	}
	if len(opts.Paths) == 0 && len(opts.Streams) == 0 {
		return nil, fmt.Errorf("gopbs: nothing to back up")
	}
	blobNames, err := blobFileNames(opts.Blobs)
	if err != nil {
		return nil, err
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

	metaName, payloadName := pbs.SplitIndexNames(arch.CatalogEntryName())
	if opts.Format == FormatV2 {
		result.ArchiveName = metaName
	} else {
		result.ArchiveName = arch.CatalogEntryName()
	}

	clientCfg := opts.Client
	if opts.OnProgress != nil {
		// Best-effort totals per index name; 0 (unknown) on estimate errors.
		totals := make(map[string]uint64)
		if opts.Format == FormatV2 {
			if m, p, err := arch.EstimatedSizeV2(); err == nil {
				totals[metaName], totals[payloadName] = uint64(m), uint64(p)
			}
		} else if t, err := arch.EstimatedSizeV1(); err == nil {
			totals[result.ArchiveName] = uint64(t)
		}
		userProgress := clientCfg.OnUploadProgress
		clientCfg.OnUploadProgress = func(name string, stats pbs.UploadStats, done bool) {
			if userProgress != nil {
				userProgress(name, stats, done)
			}
			opts.OnProgress(Progress{Archive: name, Total: totals[name], Stats: stats, Done: done})
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

	switch opts.Format {
	case FormatV2:
		meta, payload, err := arch.GenerateV2(ctx)
		if err != nil {
			return nil, err
		}
		result.Archive, result.Payload, err = sess.UploadPXARv2(ctx, result.ArchiveName, meta, payload)
		meta.Close()
		payload.Close()
		if err != nil {
			return nil, err
		}

	default: // FormatV1
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
	}

	if len(opts.Blobs) > 0 {
		enc := pbs.NewBlobEncoder()
		for i, b := range opts.Blobs {
			if err := sess.UploadBlob(ctx, enc, blobNames[i], b.Data, true); err != nil {
				return nil, err
			}
		}
	}

	if err := sess.Finish(ctx); err != nil {
		return nil, err
	}
	return result, nil
}

// blobFileNames validates BackupOptions.Blobs and returns the snapshot file
// names ("<name>.blob") in input order.
func blobFileNames(blobs []Blob) ([]string, error) {
	if len(blobs) == 0 {
		return nil, nil
	}
	names := make([]string, len(blobs))
	seen := make(map[string]bool, len(blobs))
	for i, b := range blobs {
		name := b.Name
		switch {
		case name == "":
			return nil, fmt.Errorf("gopbs: blob %d has an empty name", i)
		case strings.ContainsAny(name, "/\x00"):
			return nil, fmt.Errorf("gopbs: invalid blob name %q", name)
		}
		if !strings.HasSuffix(name, ".blob") {
			name += ".blob"
		}
		if name == "index.json.blob" {
			return nil, fmt.Errorf("gopbs: blob name %q is reserved for the manifest", name)
		}
		if name == "rsa-encrypted.key.blob" {
			return nil, fmt.Errorf("gopbs: blob name %q is reserved for the master-key-wrapped encryption key", name)
		}
		if seen[name] {
			return nil, fmt.Errorf("gopbs: duplicate blob name %q", name)
		}
		seen[name] = true
		names[i] = name
	}
	return names, nil
}
