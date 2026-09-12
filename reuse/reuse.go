// Package reuse carries previously uploaded payload chunks through a v2
// payload stream. With metadata change detection the archive generator does
// not re-read files whose metadata matches the previous snapshot; instead the
// payload stream tells the uploader which chunks of the previous payload
// archive to reference at that point. The stream is framed so that data and
// chunk injections stay in order without any side channel.
//
// Framing: an 8-byte magic ("GOPBSRU1"), then frames of a 1-byte kind and an
// 8-byte little-endian body length. KindData bodies are payload bytes to be
// chunked and uploaded; KindInject bodies hold 40-byte entries (32-byte
// digest + u64 size) of chunks to append to the index as-is, in order.
package reuse

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Magic starts a framed payload stream
const Magic = "GOPBSRU1"

// Frame kinds
const (
	KindData   byte = 0
	KindInject byte = 1
)

const entrySize = 40

// Chunk is a previously uploaded chunk referenced by digest
type Chunk struct {
	Digest [32]byte
	Size   uint64
}

// Writer frames a payload stream
type Writer struct {
	w     io.Writer
	begun bool
	hdr   [9]byte
}

// NewWriter returns a framing writer; the magic is written with the first frame
func NewWriter(w io.Writer) *Writer { return &Writer{w: w} }

func (fw *Writer) begin() error {
	if fw.begun {
		return nil
	}
	fw.begun = true
	_, err := io.WriteString(fw.w, Magic)
	return err
}

func (fw *Writer) frame(kind byte, n uint64) error {
	if err := fw.begin(); err != nil {
		return err
	}
	fw.hdr[0] = kind
	binary.LittleEndian.PutUint64(fw.hdr[1:], n)
	_, err := fw.w.Write(fw.hdr[:])
	return err
}

// Write emits payload bytes as one data frame
func (fw *Writer) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if err := fw.frame(KindData, uint64(len(p))); err != nil {
		return 0, err
	}
	return fw.w.Write(p)
}

// Inject emits a chunk injection frame
func (fw *Writer) Inject(chunks []Chunk) error {
	if len(chunks) == 0 {
		return nil
	}
	if err := fw.frame(KindInject, uint64(len(chunks)*entrySize)); err != nil {
		return err
	}
	buf := make([]byte, 0, len(chunks)*entrySize)
	for _, c := range chunks {
		buf = append(buf, c.Digest[:]...)
		buf = binary.LittleEndian.AppendUint64(buf, c.Size)
	}
	_, err := fw.w.Write(buf)
	return err
}

// Reader demultiplexes a framed payload stream
type Reader struct {
	r   io.Reader
	hdr [9]byte
	buf []byte
}

// ErrNotFramed reports a stream that does not start with the magic
var ErrNotFramed = errors.New("reuse: stream is not framed")

// NewReader checks the magic and returns a frame reader. When the stream is
// not framed, the bytes already read are returned in prefix and the error is
// ErrNotFramed, so a caller can fall back to plain chunking of prefix+r.
func NewReader(r io.Reader) (fr *Reader, prefix []byte, err error) {
	var magic [len(Magic)]byte
	n, err := io.ReadFull(r, magic[:])
	if err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, magic[:n], ErrNotFramed
		}
		return nil, magic[:n], err
	}
	if string(magic[:]) != Magic {
		return nil, magic[:], ErrNotFramed
	}
	return &Reader{r: r}, nil, nil
}

// Next returns the next frame: data bytes (valid until the next call) or the
// chunks to inject. io.EOF ends the stream.
func (fr *Reader) Next() (kind byte, data []byte, chunks []Chunk, err error) {
	if _, err := io.ReadFull(fr.r, fr.hdr[:]); err != nil {
		if errors.Is(err, io.EOF) {
			return 0, nil, nil, io.EOF
		}
		return 0, nil, nil, fmt.Errorf("reuse: truncated frame header: %w", err)
	}
	kind = fr.hdr[0]
	n := binary.LittleEndian.Uint64(fr.hdr[1:])
	if n > 1<<31 {
		return 0, nil, nil, fmt.Errorf("reuse: frame of %d bytes is too large", n)
	}
	if uint64(cap(fr.buf)) < n {
		fr.buf = make([]byte, n)
	}
	fr.buf = fr.buf[:n]
	if _, err := io.ReadFull(fr.r, fr.buf); err != nil {
		return 0, nil, nil, fmt.Errorf("reuse: truncated frame body: %w", err)
	}
	switch kind {
	case KindData:
		return kind, fr.buf, nil, nil
	case KindInject:
		if n%entrySize != 0 {
			return 0, nil, nil, fmt.Errorf("reuse: inject frame of %d bytes is not a whole number of entries", n)
		}
		chunks = make([]Chunk, 0, n/entrySize)
		for i := uint64(0); i < n; i += entrySize {
			var c Chunk
			copy(c.Digest[:], fr.buf[i:i+32])
			c.Size = binary.LittleEndian.Uint64(fr.buf[i+32:])
			chunks = append(chunks, c)
		}
		return kind, nil, chunks, nil
	}
	return 0, nil, nil, fmt.Errorf("reuse: unknown frame kind %d", kind)
}
