// Command gopbs-pxar creates a PXAR v1 archive from a directory tree.
// It exists for the integration harness and manual testing:
//
//	gopbs-pxar <output.pxar> <source-dir>
package main

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/scheiblingco/gopbs/archive"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "usage: %s <output.pxar> <source-dir>\n", os.Args[0])
		os.Exit(2)
	}
	if err := run(os.Args[1], os.Args[2]); err != nil {
		fmt.Fprintln(os.Stderr, "gopbs-pxar:", err)
		os.Exit(1)
	}
}

func run(out, src string) error {
	a, err := archive.New(archive.Options{
		OnWarn: func(w archive.Warning) {
			fmt.Fprintf(os.Stderr, "warning: kind=%d path=%s err=%v bound=%d actual=%d\n",
				w.Kind, w.Path, w.Err, w.Bound, w.Actual)
		},
	})
	if err != nil {
		return err
	}
	if err := a.AddDirectory(src); err != nil {
		return err
	}

	rc, err := a.GenerateV1(context.Background())
	if err != nil {
		return err
	}
	defer rc.Close()

	f, err := os.OpenFile(out, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	n, err := io.Copy(f, rc)
	if err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	fmt.Printf("wrote %d bytes to %s\n", n, out)
	return nil
}
