package pbs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"sync"
)

// ponytail: a fixed-size LRU, about 32 MiB at the default chunk size; add
// sequential read-ahead if large restores through ReadAt prove slow.
const indexCacheChunks = 8

// IndexFile is random access to the content of a dynamic index: an
// io.ReaderAt over the plain, verified byte stream. Chunks are fetched when
// a read first touches them and kept in a small LRU cache; concurrent reads
// of the same chunk share one download. It is safe for concurrent use.
//
// Each chunk is checked like OpenDynamicIndex checks it (size and digest);
// a failure is returned from ReadAt, never io.EOF.
type IndexFile struct {
	ctx     context.Context
	r       *ReaderSession
	name    string
	entries []IndexEntry
	keyed   bool

	mu    sync.Mutex
	cache map[int]*cachedChunk
	clock uint64
}

type cachedChunk struct {
	done chan struct{}
	data []byte
	err  error
	used uint64
}

// OpenDynamicIndexAt opens a .didx file for random access, verified against
// the manifest. ".didx" is appended to name when missing. ctx bounds every
// later read.
func (r *ReaderSession) OpenDynamicIndexAt(ctx context.Context, name string) (*IndexFile, error) {
	f, entries, keyed, err := r.loadIndex(ctx, name)
	if err != nil {
		return nil, err
	}
	var size uint64
	if len(entries) > 0 {
		size = entries[len(entries)-1].EndOffset
	}
	if size != f.Size {
		return nil, fmt.Errorf("pbs: %s: index covers %d bytes, manifest says %d", f.Filename, size, f.Size)
	}
	return &IndexFile{
		ctx: ctx, r: r, name: f.Filename, entries: entries, keyed: keyed,
		cache: make(map[int]*cachedChunk),
	}, nil
}

// Size returns the content size in bytes.
func (f *IndexFile) Size() int64 {
	if len(f.entries) == 0 {
		return 0
	}
	return int64(f.entries[len(f.entries)-1].EndOffset)
}

// ReadAt implements io.ReaderAt.
func (f *IndexFile) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("pbs: negative offset")
	}
	size := f.Size()
	i := sort.Search(len(f.entries), func(i int) bool { return f.entries[i].EndOffset > uint64(off) })
	n := 0
	for n < len(p) && off < size {
		data, err := f.chunk(i)
		if err != nil {
			return n, err
		}
		start := int64(f.entries[i].EndOffset) - int64(len(data))
		k := copy(p[n:], data[off-start:])
		n += k
		off += int64(k)
		i++
	}
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func (f *IndexFile) chunk(i int) ([]byte, error) {
	f.mu.Lock()
	f.clock++
	c, ok := f.cache[i]
	if ok {
		c.used = f.clock
		f.mu.Unlock()
		<-c.done
		return c.data, c.err
	}
	c = &cachedChunk{done: make(chan struct{}), used: f.clock}
	f.cache[i] = c
	f.evict()
	f.mu.Unlock()

	var start uint64
	if i > 0 {
		start = f.entries[i-1].EndOffset
	}
	e := f.entries[i]
	c.data, c.err = f.r.fetchChunk(f.ctx, f.name, e, e.EndOffset-start, f.keyed)
	close(c.done)
	if c.err != nil {
		// Not cached: a transient failure may succeed on the next read.
		f.mu.Lock()
		if f.cache[i] == c {
			delete(f.cache, i)
		}
		f.mu.Unlock()
	}
	return c.data, c.err
}

// evict drops the least recently used finished chunks beyond the cache
// size. Callers hold f.mu.
func (f *IndexFile) evict() {
	for len(f.cache) > indexCacheChunks {
		victim := -1
		for i, c := range f.cache {
			select {
			case <-c.done:
				if victim < 0 || c.used < f.cache[victim].used {
					victim = i
				}
			default: // in flight
			}
		}
		if victim < 0 {
			return
		}
		delete(f.cache, victim)
	}
}
