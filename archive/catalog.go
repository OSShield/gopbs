package archive

import (
	"context"
	"fmt"
	"io"

	"github.com/scheiblingco/gopbs/catalog"
	"github.com/scheiblingco/gopbs/scan"
)

// CatalogEntryName returns the name the catalog's top-level entry carries:
// the archive's dynamic index name.
func (a *Archive) CatalogEntryName() string {
	name := a.opts.Name
	if name == "" {
		name = "backup"
	}
	return name + ".pxar.didx"
}

// GenerateCatalog builds the node tree and returns the .pcat1 catalog as a
// stream. It uses scan-time metadata: sizes of files that change afterwards
// may differ from the archive's late-bound payload sizes (the catalog is a
// lookup aid, not the archive's source of truth).
func (a *Archive) GenerateCatalog(ctx context.Context) (io.ReadCloser, error) {
	root, err := a.buildTree()
	if err != nil {
		return nil, err
	}

	pr, pw := io.Pipe()
	go func() {
		pw.CloseWithError(writeCatalog(&countWriter{ctx: ctx, w: pw}, root, a.CatalogEntryName()))
	}()
	return pr, nil
}

func writeCatalog(w io.Writer, root *scan.Node, entryName string) error {
	cw, err := catalog.NewWriter(w)
	if err != nil {
		return err
	}
	if err := cw.StartDirectory(entryName); err != nil {
		return err
	}
	for _, child := range root.Children {
		if err := catalogNode(cw, child); err != nil {
			return err
		}
	}
	if err := cw.EndDirectory(); err != nil {
		return err
	}
	return cw.Finish()
}

func catalogNode(cw *catalog.Writer, n *scan.Node) error {
	switch n.Kind {
	case scan.KindDirectory:
		if err := cw.StartDirectory(n.Name); err != nil {
			return err
		}
		for _, child := range n.Children {
			if err := catalogNode(cw, child); err != nil {
				return err
			}
		}
		return cw.EndDirectory()
	case scan.KindFile, scan.KindStream:
		return cw.AddFile(n.Name, uint64(n.Stat.Size), n.Stat.MtimeSecs)
	case scan.KindSymlink:
		return cw.AddSymlink(n.Name)
	case scan.KindHardlink:
		return cw.AddHardlink(n.Name)
	case scan.KindBlockDevice:
		return cw.AddBlockDevice(n.Name)
	case scan.KindCharDevice:
		return cw.AddCharDevice(n.Name)
	case scan.KindFifo:
		return cw.AddFifo(n.Name)
	case scan.KindSocket:
		return cw.AddSocket(n.Name)
	}
	return fmt.Errorf("archive: catalog: unsupported node kind %d for %q", n.Kind, n.Name)
}
