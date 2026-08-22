package chunker

import (
	"fmt"
	"io"
	"iter"
	"math/bits"
)

// DefaultAvg is the chunk size target Proxmox Backup Server uses.
const DefaultAvg = 4 << 20

// windowSize is the rolling-hash window (fixed by the format).
const windowSize = 64

// Chunker is the buzhash content-defined chunker used by Proxmox Backup
// Server (a port of pbs-datastore's chunker.rs). Boundaries depend only on
// content, so a changed byte resynchronizes within roughly one window.
//
// Chunks are cut between min (avg/4) and max (avg*4): below min no boundary
// is considered, above max one is forced, in between a boundary falls where
// hash & (2*avg-1) lands in the top three values — matching the reference
// implementation bit for bit.
type Chunker struct {
	h         uint32
	winFill   uint64 // bytes of the window filled for the current chunk
	chunkSize uint64
	min, max  uint64
	breakMask uint32
	breakMin  uint32
	window    [windowSize]byte
}

// New returns a Chunker with the given average chunk size; 0 means
// DefaultAvg (4 MiB). The average must be a power of two of at least 4×the
// window (the break mask arithmetic depends on it).
func New(avg uint64) (*Chunker, error) {
	if avg == 0 {
		avg = DefaultAvg
	}
	if avg&(avg-1) != 0 || avg < 4*windowSize {
		return nil, fmt.Errorf("chunker: average %d must be a power of two >= %d", avg, 4*windowSize)
	}
	mask := uint32(avg*2 - 1)
	return &Chunker{
		min:       avg >> 2,
		max:       avg << 2,
		breakMask: mask,
		breakMin:  mask - 2,
	}, nil
}

// Reset discards the current chunk state.
func (c *Chunker) Reset() {
	c.h, c.winFill, c.chunkSize = 0, 0, 0
}

// Scan consumes data and returns the position just past the next chunk
// boundary, or 0 if data ends without one. State carries across calls, so a
// stream may be fed in arbitrary segments; after a non-zero return, continue
// scanning from that position.
func (c *Chunker) Scan(data []byte) int {
	pos := 0

	// Fill the window at the start of a chunk; no boundary can occur here.
	if c.winFill < windowSize {
		n := int(windowSize - c.winFill)
		if n > len(data) {
			n = len(data)
		}
		for _, b := range data[:n] {
			c.window[c.winFill] = b
			c.h = bits.RotateLeft32(c.h, 1) ^ table[b]
			c.winFill++
		}
		c.chunkSize += uint64(n)
		pos = n
		if c.winFill < windowSize {
			return 0
		}
	}

	idx := c.chunkSize & (windowSize - 1)
	for pos < len(data) {
		enter := data[pos]
		leave := c.window[idx]
		c.h = bits.RotateLeft32(c.h, 1) ^ table[leave] ^ table[enter]
		c.chunkSize++
		pos++
		c.window[idx] = enter

		if c.shallBreak() {
			c.Reset()
			return pos
		}
		idx = c.chunkSize & (windowSize - 1)
	}
	return 0
}

func (c *Chunker) shallBreak() bool {
	if c.chunkSize >= c.max {
		return true
	}
	if c.chunkSize < c.min {
		return false
	}
	return c.h&c.breakMask >= c.breakMin
}

// Chunk is one content-defined chunk of a stream.
type Chunk struct {
	Data   []byte // owned by the consumer
	Offset uint64 // start offset within the stream
}

// Split reads r to EOF and yields its content-defined chunks in order. The
// final chunk may be shorter than the minimum. A read error is yielded as
// the last element with a zero Chunk.
func Split(r io.Reader, avg uint64) iter.Seq2[Chunk, error] {
	return func(yield func(Chunk, error) bool) {
		c, err := New(avg)
		if err != nil {
			yield(Chunk{}, err)
			return
		}

		var (
			current []byte
			offset  uint64
			buf     = make([]byte, 64<<10)
		)
		for {
			n, err := r.Read(buf)
			seg := buf[:n]
			for len(seg) > 0 {
				pos := c.Scan(seg)
				if pos == 0 {
					current = append(current, seg...)
					break
				}
				current = append(current, seg[:pos]...)
				if !yield(Chunk{Data: current, Offset: offset}, nil) {
					return
				}
				offset += uint64(len(current))
				current = nil
				seg = seg[pos:]
			}
			if err == io.EOF {
				break
			}
			if err != nil {
				yield(Chunk{}, fmt.Errorf("chunker: %w", err))
				return
			}
		}
		if len(current) > 0 {
			yield(Chunk{Data: current, Offset: offset}, nil)
		}
	}
}
