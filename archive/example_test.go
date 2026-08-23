package archive_test

import (
	"context"
	"io"
	"log"
	"os"

	"github.com/scheiblingco/gopbs/archive"
)

// Archive-only use: generate a pxar v1 stream from a directory tree and
// write it to a file. The returned stream is
// produced concurrently with consumption, so it can just as well be piped,
// chunked, or uploaded elsewhere.
func ExampleArchive_GenerateV1() {
	a, err := archive.New(archive.Options{})
	if err != nil {
		log.Fatal(err)
	}
	if err := a.AddDirectory("/etc"); err != nil {
		log.Fatal(err)
	}

	stream, err := a.GenerateV1(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	defer stream.Close()

	out, err := os.Create("/tmp/etc.pxar")
	if err != nil {
		log.Fatal(err)
	}
	defer out.Close()
	if _, err := io.Copy(out, stream); err != nil {
		log.Fatal(err)
	}
}
