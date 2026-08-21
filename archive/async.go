package archive

import (
	"context"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/scheiblingco/gopbs/scan"
)

// The async payload source. A dispatcher opens payloads in plan order (each
// open+fstat binds the size the archive commits to), workers read contents
// into pooled buffers under a shared byte budget, and the emitter — walking
// the tree in the same plan order — consumes them through the payloadSource
// seam, so sync and async emission share every byte of rendering logic.
//
// Two bounds keep it safe:
//   - a dispatch window caps how far open fds run ahead of emission;
//   - the byte budget caps buffered content, with head-of-line priority: the
//     payload the emitter is currently draining may always allocate one more
//     chunk, so prefetched future payloads can never starve it into deadlock.

type chunk struct {
	buf []byte
	n   int
}

type asyncSource struct {
	ctx      context.Context
	delivery chan *asyncPayload // dispatch order; emitter pops from here
	work     chan *asyncPayload // consumed by workers
	window   chan struct{}      // dispatch-window slots
	budget   *chunkBudget
	pool     sync.Pool
	wg       sync.WaitGroup
}

func newAsyncSource(ctx context.Context, payloads []*scan.Node, workers int, budgetBytes int64) *asyncSource {
	if budgetBytes <= 0 {
		budgetBytes = 64 << 20
	}
	budgetChunks := int(budgetBytes / copyChunk)
	if budgetChunks < 2 {
		budgetChunks = 2
	}
	window := 2 * workers
	if window < 8 {
		window = 8
	}

	s := &asyncSource{
		ctx:      ctx,
		delivery: make(chan *asyncPayload, window),
		work:     make(chan *asyncPayload, window),
		window:   make(chan struct{}, window),
		budget:   newChunkBudget(ctx, budgetChunks),
		pool:     sync.Pool{New: func() any { return make([]byte, copyChunk) }},
	}

	s.wg.Add(1)
	go s.dispatch(payloads)
	for i := 0; i < workers; i++ {
		s.wg.Add(1)
		go s.worker()
	}
	return s
}

// wait blocks until all source goroutines exited. Callers cancel ctx first.
func (s *asyncSource) wait() { s.wg.Wait() }

// dispatch binds payload sizes in plan order and hands the open payloads to
// the workers and to the in-order delivery queue.
func (s *asyncSource) dispatch(payloads []*scan.Node) {
	defer s.wg.Done()
	defer close(s.work)
	for seq, n := range payloads {
		select {
		case s.window <- struct{}{}:
		case <-s.ctx.Done():
			return
		}

		p := s.bind(n, seq)

		select {
		case s.delivery <- p:
		case <-s.ctx.Done():
			if p.f != nil {
				p.f.Close()
			}
			return
		}
		if p.openErr != nil {
			close(p.chunks)
			continue
		}
		select {
		case s.work <- p:
		case <-s.ctx.Done():
			p.f.Close()
			return
		}
	}
}

// bind opens a payload and fixes the size the archive commits to (fstat on
// the open fd for files, the declared size for streams).
func (s *asyncSource) bind(n *scan.Node, seq int) *asyncPayload {
	p := &asyncPayload{src: s, node: n, seq: seq, chunks: make(chan chunk, 2)}
	if n.Kind == scan.KindStream {
		p.size = n.Stat.Size
		return p
	}
	f, err := os.Open(n.Path)
	if err != nil {
		p.openErr = fmt.Errorf("archive: %w", err)
		return p
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		p.openErr = fmt.Errorf("archive: %w", err)
		return p
	}
	p.f, p.size, p.mtime = f, info.Size(), info.ModTime()
	return p
}

func (s *asyncSource) worker() {
	defer s.wg.Done()
	for p := range s.work {
		s.read(p)
	}
}

// read streams exactly p.size bytes into p.chunks: file/stream content, then
// zero padding if the source came up short. Read errors (not EOF) surface via
// p.err; pad/truncate and torn-content warnings are recorded on the payload.
func (s *asyncSource) read(p *asyncPayload) {
	defer close(p.chunks)
	if p.f != nil {
		defer p.f.Close()
	}

	var fromSource int64
	remaining := p.size
	for remaining > 0 {
		buf, ok := s.take(p.seq)
		if !ok {
			p.err = s.ctx.Err()
			return
		}
		want := int64(len(buf))
		if want > remaining {
			want = remaining
		}
		var (
			n   int
			err error
		)
		if p.f != nil {
			n, err = p.f.Read(buf[:want])
		} else {
			n, err = p.node.Stream.Read(buf[:want])
		}
		if n > 0 {
			if !p.send(chunk{buf, n}) {
				p.err = s.ctx.Err()
				return
			}
			fromSource += int64(n)
			remaining -= int64(n)
		} else {
			s.putBack(buf)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			p.err = fmt.Errorf("archive: reading payload %s: %w", p.node.Path, err)
			return
		}
	}

	if remaining > 0 {
		// Source ended early: zero-pad to the bound size.
		p.warns = append(p.warns, Warning{
			Kind: WarnSizeChanged, Path: p.warnPath(), Bound: p.size, Actual: fromSource,
		})
		for remaining > 0 {
			buf, ok := s.take(p.seq)
			if !ok {
				p.err = s.ctx.Err()
				return
			}
			n := int64(len(buf))
			if n > remaining {
				n = remaining
			}
			clear(buf[:n])
			if !p.send(chunk{buf, int(n)}) {
				p.err = s.ctx.Err()
				return
			}
			remaining -= n
		}
	}

	switch {
	case p.f != nil:
		// Torn-content check: the file changing while we read it.
		info, err := p.f.Stat()
		switch {
		case err != nil:
			p.warns = append(p.warns, Warning{Kind: WarnTorn, Path: p.node.Path, Err: err})
		case info.Size() != p.size || !info.ModTime().Equal(p.mtime):
			p.warns = append(p.warns, Warning{
				Kind: WarnTorn, Path: p.node.Path, Bound: p.size, Actual: info.Size(),
			})
		}
	case fromSource == p.size:
		// Probe one byte past the declared size to report a truncated
		// over-long stream (pointless when the stream already came up short).
		var probe [1]byte
		if n, _ := io.ReadFull(p.node.Stream, probe[:]); n > 0 {
			p.warns = append(p.warns, Warning{
				Kind: WarnSizeChanged, Path: p.warnPath(), Bound: p.size, Actual: p.size + 1,
			})
		}
	}
}

func (s *asyncSource) take(seq int) ([]byte, bool) {
	if !s.budget.acquire(seq) {
		return nil, false
	}
	return s.pool.Get().([]byte), true
}

func (s *asyncSource) putBack(buf []byte) {
	s.pool.Put(buf) //nolint:staticcheck // fixed-size slices
	s.budget.release()
}

// open implements payloadSource: the next payload in plan order.
func (s *asyncSource) open(n *scan.Node) (payload, error) {
	select {
	case p := <-s.delivery:
		if p.node != n {
			return nil, fmt.Errorf("archive: internal: payload order mismatch (%q vs %q)", p.node.Name, n.Name)
		}
		if p.openErr != nil {
			<-s.window // the slot the dispatcher took for it
			return nil, p.openErr
		}
		s.budget.setHead(p.seq)
		return p, nil
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	}
}

type asyncPayload struct {
	src     *asyncSource
	node    *scan.Node
	seq     int
	size    int64
	mtime   time.Time
	f       *os.File
	openErr error
	chunks  chan chunk
	err     error // read failure; set before chunks is closed
	warns   []Warning
}

func (p *asyncPayload) Size() int64         { return p.size }
func (p *asyncPayload) Warnings() []Warning { return p.warns }

func (p *asyncPayload) send(c chunk) bool {
	select {
	case p.chunks <- c:
		return true
	case <-p.src.ctx.Done():
		p.src.putBack(c.buf)
		return false
	}
}

func (p *asyncPayload) Copy(w *countWriter) error {
	for c := range p.chunks {
		err := w.write(c.buf[:c.n])
		p.src.putBack(c.buf)
		if err != nil {
			return err
		}
	}
	return p.err
}

func (p *asyncPayload) Close() error {
	<-p.src.window // release the dispatch-window slot
	return nil
}

func (p *asyncPayload) warnPath() string {
	if p.node.Path != "" {
		return p.node.Path
	}
	return p.node.Name
}

// chunkBudget is a counting semaphore over ~1 MiB buffer credits with
// head-of-line priority: acquire(seq) for the payload the emitter currently
// drains never blocks (it may drive the count negative by bounded amounts),
// guaranteeing forward progress no matter what the prefetchers hold.
type chunkBudget struct {
	mu    sync.Mutex
	cond  *sync.Cond
	avail int
	head  int
	done  <-chan struct{}
}

func newChunkBudget(ctx context.Context, chunks int) *chunkBudget {
	b := &chunkBudget{avail: chunks, head: -1, done: ctx.Done()}
	b.cond = sync.NewCond(&b.mu)
	go func() {
		<-ctx.Done()
		b.cond.Broadcast()
	}()
	return b
}

func (b *chunkBudget) acquire(seq int) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	for b.avail < 1 && seq != b.head {
		select {
		case <-b.done:
			return false
		default:
		}
		b.cond.Wait()
	}
	select {
	case <-b.done:
		return false
	default:
	}
	b.avail--
	return true
}

func (b *chunkBudget) release() {
	b.mu.Lock()
	b.avail++
	b.mu.Unlock()
	b.cond.Broadcast()
}

func (b *chunkBudget) setHead(seq int) {
	b.mu.Lock()
	b.head = seq
	b.mu.Unlock()
	b.cond.Broadcast()
}

// collectPayloads lists file/stream nodes in exactly the order the emitter
// walks them — the dispatch order the delivery queue promises.
func collectPayloads(n *scan.Node, into []*scan.Node) []*scan.Node {
	switch n.Kind {
	case scan.KindFile, scan.KindStream:
		return append(into, n)
	case scan.KindDirectory:
		for _, c := range n.Children {
			into = collectPayloads(c, into)
		}
	}
	return into
}
