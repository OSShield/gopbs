package gopbs

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"slices"
	"strings"

	"github.com/osshield/gopbs/catalog"
	"github.com/osshield/gopbs/pbs"
	"github.com/osshield/gopbs/pxar"
	"github.com/osshield/gopbs/restore"
)

// RestoreOptions configures one Restore call.
type RestoreOptions struct {
	// Client configures the PBS connection. For an encrypted backup set
	// Client.Crypt to its key, or MasterKey.
	Client pbs.Config
	// MasterKey, used when Client.Crypt is nil, recovers the encryption key
	// from the snapshot's master-key wrapped copy (see pbs.LoadMasterKey).
	MasterKey *rsa.PrivateKey
	// Ref selects the snapshot: Type defaults to "host", ID to the
	// hostname, and a zero Time selects the group's newest snapshot.
	Ref pbs.SnapshotRef
	// Archive is the archive name as given to Backup (Archive.Name; empty
	// means "backup"); v1 and v2 are told apart by the snapshot manifest.
	Archive string
	// Target is the directory to restore into. It must be missing or
	// empty unless Restore.Overwrite is set.
	Target string
	// Paths restricts the restore to these archive paths and their
	// subtrees, read by random access (hardlinks become copies). Empty
	// restores the whole archive in one streamed pass.
	Paths []string
	// Restore configures writing: Overwrite, the MetadataWriter, and
	// OnWarn, which is called in addition to warnings being collected into
	// the result.
	Restore restore.Options
}

// RestoreResult reports what Restore did.
type RestoreResult struct {
	// Ref is the snapshot restored, with defaults resolved.
	Ref pbs.SnapshotRef
	// Format is the archive's format.
	Format Format
	// Warnings collects the non-fatal events: metadata that could not be
	// applied, entries the platform cannot create.
	Warnings []restore.Warning
}

// Restore restores one archive of a snapshot into a directory.
//
// A full restore streams the archive once, fetching Client.Workers chunks
// in parallel (the payload stream of a v2 archive is read by random access).
// Everything read is verified: the manifest (and its signature, with a key),
// every index against the manifest, every chunk against its digest.
func Restore(ctx context.Context, opts RestoreOptions) (*RestoreResult, error) {
	if opts.Target == "" {
		return nil, errors.New("gopbs: RestoreOptions.Target is required")
	}
	sess, err := OpenSnapshot(ctx, opts.Client, opts.Ref, opts.MasterKey)
	if err != nil {
		return nil, err
	}
	defer sess.Close()
	format, meta, payload, err := archiveIndexes(ctx, sess, opts.Archive)
	if err != nil {
		return nil, err
	}

	result := &RestoreResult{Ref: sess.Ref(), Format: format}
	ropts := opts.Restore
	ropts.OnWarn = func(w restore.Warning) {
		result.Warnings = append(result.Warnings, w)
		if opts.Restore.OnWarn != nil {
			opts.Restore.OnWarn(w)
		}
	}

	if len(opts.Paths) > 0 {
		fsys, err := openArchive(ctx, sess, format, meta, payload)
		if err != nil {
			return nil, err
		}
		return result, restore.ExtractPaths(ctx, fsys, opts.Paths, opts.Target, ropts)
	}

	rc, err := sess.OpenDynamicIndex(ctx, meta)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	var r *pxar.Reader
	if format == FormatV1 {
		r = pxar.NewReaderV1(rc)
	} else {
		p, err := sess.OpenDynamicIndexAt(ctx, payload)
		if err != nil {
			return nil, err
		}
		r = pxar.NewReaderV2(rc, p)
	}
	return result, restore.Extract(ctx, r, opts.Target, ropts)
}

// OpenSnapshot opens a reader session on a snapshot. Type defaults to
// "host", ID to the hostname, and a zero Time selects the group's newest
// snapshot. With masterKey set and cfg.Crypt nil, the encryption key is
// recovered from the snapshot first (see pbs.ReaderSession.RecoverKey) and
// the returned session reads with it. Close the session when done.
func OpenSnapshot(ctx context.Context, cfg pbs.Config, ref pbs.SnapshotRef, masterKey *rsa.PrivateKey) (*pbs.ReaderSession, error) {
	if ref.Type == "" {
		ref.Type = "host"
	}
	if ref.ID == "" {
		host, err := os.Hostname()
		if err != nil {
			return nil, fmt.Errorf("gopbs: default backup id: %w", err)
		}
		ref.ID = host
	}
	client, err := pbs.NewClient(cfg)
	if err != nil {
		return nil, err
	}
	if ref.Time.IsZero() {
		snaps, err := client.ListSnapshots(ctx, ref.Type, ref.ID)
		if err != nil {
			return nil, err
		}
		if len(snaps) == 0 {
			return nil, fmt.Errorf("gopbs: no snapshots of %s/%s: %w", ref.Type, ref.ID, pbs.ErrNotFound)
		}
		ref = snaps[0].Ref
	}
	if masterKey != nil && cfg.Crypt == nil {
		sess, err := client.StartReader(ctx, ref)
		if err != nil {
			return nil, err
		}
		info, err := sess.RecoverKey(ctx, masterKey)
		sess.Close()
		if err != nil {
			return nil, err
		}
		cfg.Crypt = info.CryptConfig(pbs.CryptModeEncrypt)
		if client, err = pbs.NewClient(cfg); err != nil {
			return nil, err
		}
	}
	return client.StartReader(ctx, ref)
}

// OpenArchive opens one archive of a snapshot as a file system, for
// browsing and reading single files; only the chunks a lookup or read
// touches are downloaded. name is the archive name as given to Backup.
func OpenArchive(ctx context.Context, sess *pbs.ReaderSession, name string) (*pxar.FS, error) {
	format, meta, payload, err := archiveIndexes(ctx, sess, name)
	if err != nil {
		return nil, err
	}
	return openArchive(ctx, sess, format, meta, payload)
}

// Browse returns an archive's directory tree with names, types, and file
// sizes and mtimes, without reading file contents: from the .pcat1 catalog
// for a v1 archive that has one, otherwise from the archive's metadata (for
// v2 the metadata stream alone). The returned root is the archive root,
// named by its index file ("root.pxar.didx", "root.mpxar.didx").
func Browse(ctx context.Context, sess *pbs.ReaderSession, name string) (*catalog.Entry, error) {
	format, meta, payload, err := archiveIndexes(ctx, sess, name)
	if err != nil {
		return nil, err
	}
	m, err := sess.Manifest(ctx)
	if err != nil {
		return nil, err
	}
	if format == FormatV1 && slices.ContainsFunc(m.Files, func(f pbs.ManifestFile) bool { return f.Filename == "catalog.pcat1.didx" }) {
		rc, err := sess.OpenDynamicIndex(ctx, "catalog.pcat1")
		if err != nil {
			return nil, err
		}
		defer rc.Close()
		data, err := io.ReadAll(rc)
		if err != nil {
			return nil, err
		}
		cat, err := catalog.Decode(data)
		if err != nil {
			return nil, err
		}
		// The catalog's synthetic root holds the archive, by index name.
		if root := cat.Child(meta); root != nil {
			return root, nil
		}
		return nil, fmt.Errorf("gopbs: catalog has no entry for %s", meta)
	}

	if format == FormatV2 {
		payload = "" // listing needs the metadata stream only
	}
	fsys, err := openArchive(ctx, sess, format, meta, payload)
	if err != nil {
		return nil, err
	}
	root := &catalog.Entry{Name: meta, Type: catalog.TypeDirectory}
	dirs := map[string]*catalog.Entry{".": root}
	err = fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || p == "." {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		e := &catalog.Entry{Name: d.Name(), Type: catalogType(info.Mode())}
		if info.Mode().IsRegular() {
			e.Size, e.MtimeSecs = uint64(info.Size()), info.ModTime().Unix()
		}
		parent := dirs[path.Dir(p)]
		parent.Children = append(parent.Children, e)
		if d.IsDir() {
			dirs[p] = e
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return root, nil
}

func catalogType(m fs.FileMode) byte {
	switch {
	case m.IsDir():
		return catalog.TypeDirectory
	case m&fs.ModeSymlink != 0:
		return catalog.TypeSymlink
	case m&fs.ModeCharDevice != 0:
		return catalog.TypeCharDevice
	case m&fs.ModeDevice != 0:
		return catalog.TypeBlockDevice
	case m&fs.ModeNamedPipe != 0:
		return catalog.TypeFifo
	case m&fs.ModeSocket != 0:
		return catalog.TypeSocket
	}
	return catalog.TypeFile
}

// archiveIndexes finds an archive's index files in the manifest and with
// them its format.
func archiveIndexes(ctx context.Context, sess *pbs.ReaderSession, name string) (format Format, meta, payload string, err error) {
	m, err := sess.Manifest(ctx)
	if err != nil {
		return 0, "", "", err
	}
	has := func(file string) bool {
		return slices.ContainsFunc(m.Files, func(f pbs.ManifestFile) bool { return f.Filename == file })
	}
	meta, payload = pbs.SplitIndexNames(name)
	v1 := strings.TrimSuffix(meta, ".mpxar.didx") + ".pxar.didx"
	switch {
	case has(v1):
		return FormatV1, v1, "", nil
	case has(meta) && has(payload):
		return FormatV2, meta, payload, nil
	}
	return 0, "", "", fmt.Errorf("gopbs: archive %s is not in the snapshot: %w", strings.TrimSuffix(v1, ".pxar.didx"), pbs.ErrNotFound)
}

// openArchive opens the archive's indexes for random access; an empty
// payload name opens a v2 archive for metadata only.
func openArchive(ctx context.Context, sess *pbs.ReaderSession, format Format, meta, payload string) (*pxar.FS, error) {
	m, err := sess.OpenDynamicIndexAt(ctx, meta)
	if err != nil {
		return nil, err
	}
	if format == FormatV1 {
		return pxar.OpenV1(m, m.Size())
	}
	if payload == "" {
		return pxar.OpenV2(m, m.Size(), nil)
	}
	p, err := sess.OpenDynamicIndexAt(ctx, payload)
	if err != nil {
		return nil, err
	}
	return pxar.OpenV2(m, m.Size(), p)
}
