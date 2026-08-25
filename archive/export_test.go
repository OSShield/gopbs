package archive

import (
	"bytes"
	"context"
	"sync"

	"github.com/osshield/gopbs/scan"
)

// Test-only exports: compiled only for tests, keeping internals reachable
// from the external archive_test package without widening the public API.

// SyncPayloadRun binds n's payload via the synchronous source, runs mutate
// (simulating the file changing between bind and read), then copies. Returns
// the bound size, the emitted bytes, and the collected warnings.
func SyncPayloadRun(n *scan.Node, mutate func()) (int64, []byte, []Warning, error) {
	pl, err := syncSource{}.open(n)
	if err != nil {
		return 0, nil, nil, err
	}
	defer pl.Close()
	if mutate != nil {
		mutate()
	}
	var buf bytes.Buffer
	err = pl.Copy(&countWriter{ctx: context.Background(), w: &buf})
	return pl.Size(), buf.Bytes(), pl.Warnings(), err
}

// AsyncPayloadRun does the same through the async worker's read path.
func AsyncPayloadRun(n *scan.Node, mutate func()) (int64, []byte, []Warning, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // lets the budget's ctx watcher exit
	s := &asyncSource{
		ctx:    ctx,
		budget: newChunkBudget(ctx, 4),
		pool:   sync.Pool{New: func() any { return make([]byte, copyChunk) }},
	}
	p := s.bind(n, 0)
	if p.openErr != nil {
		return 0, nil, nil, p.openErr
	}
	if mutate != nil {
		mutate()
	}
	s.budget.setHead(0)
	go s.read(p)
	var buf bytes.Buffer
	err := p.Copy(&countWriter{ctx: ctx, w: &buf})
	return p.size, buf.Bytes(), p.warns, err
}
