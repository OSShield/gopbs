package archive

import (
	"fmt"
	"sync"

	"github.com/scheiblingco/gopbs/pxar"
)

// refLedger coordinates the two v2 streams: whoever binds payload sizes (the
// async dispatcher, or the payload emitter in synchronous mode) publishes them
// in plan order, and the metadata emitter consumes them to render PAYLOAD_REF
// records. Publishing happens at size-binding time — open+fstat — so metadata
// emission awaits dispatch progress, never payload read completion.
type refLedger struct {
	mu    sync.Mutex
	cond  *sync.Cond
	sizes []int64
	err   error // terminal: a bind failure or a failed payload stream
	done  <-chan struct{}
}

func newRefLedger(done <-chan struct{}) *refLedger {
	l := &refLedger{done: done}
	l.cond = sync.NewCond(&l.mu)
	go func() {
		<-done
		l.cond.Broadcast()
	}()
	return l
}

// publish records the bound size of the next payload in plan order, or
// poisons the ledger when binding failed (the failed payload gets no size —
// generation is aborting).
func (l *refLedger) publish(size int64, err error) {
	l.mu.Lock()
	switch {
	case l.err != nil:
		// Already poisoned; whatever binds after the failure is void.
	case err != nil:
		l.err = err
	default:
		l.sizes = append(l.sizes, size)
	}
	l.mu.Unlock()
	l.cond.Broadcast()
}

// fail poisons the ledger; blocked and future get calls return err.
func (l *refLedger) fail(err error) {
	l.mu.Lock()
	if l.err == nil {
		l.err = err
	}
	l.mu.Unlock()
	l.cond.Broadcast()
}

// get blocks until payload i's size is bound (or the ledger failed) and
// returns it.
func (l *refLedger) get(i int) (int64, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for len(l.sizes) <= i && l.err == nil {
		select {
		case <-l.done:
			return 0, fmt.Errorf("archive: generation canceled")
		default:
		}
		l.cond.Wait()
	}
	if l.err != nil && len(l.sizes) <= i {
		return 0, l.err
	}
	return l.sizes[i], nil
}

// refReader hands the metadata emitter one PAYLOAD_REF per regular file in
// plan order, deriving payload-stream offsets from the bound sizes: payload i
// starts right after the start marker and the i preceding payload records.
type refReader struct {
	ledger *refLedger
	seq    int
	offset uint64 // next payload record's header position in the payload stream
}

func newRefReader(l *refLedger) *refReader {
	return &refReader{ledger: l, offset: pxar.MarkerSize}
}

// next returns the payload-stream offset and bound size for the next regular
// file, blocking until its size is bound.
func (r *refReader) next() (offset, size uint64, err error) {
	s, err := r.ledger.get(r.seq)
	if err != nil {
		return 0, 0, err
	}
	offset = r.offset
	r.seq++
	r.offset += pxar.HeaderSize + uint64(s)
	return offset, uint64(s), nil
}
