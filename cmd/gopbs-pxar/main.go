// Command gopbs-pxar creates a PXAR archive from a directory tree.
// It exists for the integration harness and manual testing:
//
//	gopbs-pxar <output.pxar> <source-dir>                        # v1
//	gopbs-pxar -payload out.ppxar <output.mpxar> <source-dir>    # v2 split
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/osshield/gopbs/archive"
)

func main() {
	catalogOut := flag.String("catalog", "", "also write a .pcat1 catalog to this path (v1 only)")
	payloadOut := flag.String("payload", "", "write a v2 split archive: metadata to <output>, payloads to this path")
	flag.Parse()
	if flag.NArg() != 2 {
		fmt.Fprintf(os.Stderr, "usage: %s [-catalog out.pcat1] [-payload out.ppxar] <output.pxar> <source-dir>\n", os.Args[0])
		os.Exit(2)
	}
	var err error
	if *payloadOut != "" {
		err = runV2(flag.Arg(0), *payloadOut, flag.Arg(1))
	} else {
		err = run(flag.Arg(0), flag.Arg(1), *catalogOut)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "gopbs-pxar:", err)
		os.Exit(1)
	}
}

func run(out, src, catalogOut string) error {
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

	if catalogOut == "" {
		return nil
	}
	crc, err := a.GenerateCatalog(context.Background())
	if err != nil {
		return err
	}
	defer crc.Close()
	cf, err := os.OpenFile(catalogOut, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	cn, err := io.Copy(cf, crc)
	if err != nil {
		cf.Close()
		return err
	}
	if err := cf.Close(); err != nil {
		return err
	}
	fmt.Printf("wrote %d bytes to %s\n", cn, catalogOut)
	return nil
}

// runV2 writes a split archive. The two streams must be consumed
// concurrently — metadata emission awaits payload dispatch progress.
func runV2(metaOut, payloadOut, src string) error {
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

	meta, payload, err := a.GenerateV2(context.Background())
	if err != nil {
		return err
	}
	defer meta.Close()
	defer payload.Close()

	var wg sync.WaitGroup
	var payloadN int64
	var payloadErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		payloadN, payloadErr = writeStream(payloadOut, payload)
	}()
	metaN, metaErr := writeStream(metaOut, meta)
	wg.Wait()
	if metaErr != nil {
		return metaErr
	}
	if payloadErr != nil {
		return payloadErr
	}
	fmt.Printf("wrote %d bytes to %s\n", metaN, metaOut)
	fmt.Printf("wrote %d bytes to %s\n", payloadN, payloadOut)
	return nil
}

func writeStream(path string, r io.Reader) (int64, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return 0, err
	}
	n, err := io.Copy(f, r)
	if err != nil {
		f.Close()
		return n, err
	}
	return n, f.Close()
}
