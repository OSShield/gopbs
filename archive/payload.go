package archive

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/osshield/gopbs/scan"
)

// payloadSource is the seam between the emitter and payload I/O. The
// synchronous source opens files inline; the async source hands out
// prefetched buffers from the worker pool. In both cases open happens
// at dispatch time and binds the payload size the archive commits to.
type payloadSource interface {
	open(n *scan.Node) (payload, error)
}

type payload interface {
	// Size is the bound byte count; the emitter writes it into the payload
	// header before copying content.
	Size() int64
	// Copy writes exactly Size bytes: short sources are zero-padded, long
	// ones truncated.
	Copy(w *countWriter) error
	// Warnings reports pad/truncate and torn-content events observed during
	// Copy.
	Warnings() []Warning
	Close() error
}

type syncSource struct{}

func (syncSource) open(n *scan.Node) (payload, error) {
	if n.Kind == scan.KindStream {
		return &streamPayload{node: n}, nil
	}
	f, err := os.Open(n.Path)
	if err != nil {
		return nil, fmt.Errorf("archive: %w", err)
	}
	info, err := f.Stat() // fstat on the open fd: no path race
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("archive: %w", err)
	}
	return &filePayload{node: n, f: f, size: info.Size(), mtime: info.ModTime()}, nil
}

const copyChunk = 1 << 20

type filePayload struct {
	node  *scan.Node
	f     *os.File
	size  int64
	mtime time.Time
	warns []Warning
}

func (p *filePayload) Size() int64         { return p.size }
func (p *filePayload) Warnings() []Warning { return p.warns }
func (p *filePayload) Close() error        { return p.f.Close() }

func (p *filePayload) Copy(w *countWriter) error {
	written, err := copyExactly(w, p.f, p.size)
	if err != nil {
		return err
	}
	if written < p.size {
		// The file shrank mid-read; the remainder was zero-padded by
		// copyExactly and the mismatch is reported below.
		p.warns = append(p.warns, Warning{
			Kind: WarnSizeChanged, Path: p.node.Path, Bound: p.size, Actual: written,
		})
	}
	info, err := p.f.Stat()
	switch {
	case err != nil:
		p.warns = append(p.warns, Warning{Kind: WarnTorn, Path: p.node.Path, Err: err})
	case info.Size() != p.size || !info.ModTime().Equal(p.mtime):
		p.warns = append(p.warns, Warning{
			Kind: WarnTorn, Path: p.node.Path, Bound: p.size, Actual: info.Size(),
		})
	}
	return nil
}

type streamPayload struct {
	node  *scan.Node
	warns []Warning
}

func (p *streamPayload) Size() int64         { return p.node.Stat.Size }
func (p *streamPayload) Warnings() []Warning { return p.warns }
func (p *streamPayload) Close() error        { return nil }

func (p *streamPayload) Copy(w *countWriter) error {
	size := p.node.Stat.Size
	written, err := copyExactly(w, p.node.Stream, size)
	if err != nil {
		return err
	}
	if written < size {
		p.warns = append(p.warns, Warning{
			Kind: WarnSizeChanged, Path: p.node.Name, Bound: size, Actual: written,
		})
		return nil
	}
	// Probe one byte past the declared size to detect (and report) a
	// truncated over-long stream. The excess is not consumed further.
	var probe [1]byte
	if n, _ := io.ReadFull(p.node.Stream, probe[:]); n > 0 {
		p.warns = append(p.warns, Warning{
			Kind: WarnSizeChanged, Path: p.node.Name, Bound: size, Actual: size + 1,
		})
	}
	return nil
}

// copyExactly writes exactly size bytes to w: up to size bytes from r, then
// zero padding if r ends early. Returns how many bytes actually came from r.
// Read errors other than EOF abort the archive (they are I/O failures, not
// size races).
func copyExactly(w *countWriter, r io.Reader, size int64) (int64, error) {
	buf := make([]byte, copyChunk)
	var fromSource int64
	for fromSource < size {
		want := size - fromSource
		if want > copyChunk {
			want = copyChunk
		}
		n, err := r.Read(buf[:want])
		if n > 0 {
			if werr := w.write(buf[:n]); werr != nil {
				return fromSource, werr
			}
			fromSource += int64(n)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return fromSource, fmt.Errorf("archive: reading payload: %w", err)
		}
	}
	// Zero-fill whatever the source did not deliver.
	for pad := size - fromSource; pad > 0; {
		n := pad
		if n > copyChunk {
			n = copyChunk
		}
		zeros := make([]byte, n)
		if err := w.write(zeros); err != nil {
			return fromSource, err
		}
		pad -= n
	}
	return fromSource, nil
}
