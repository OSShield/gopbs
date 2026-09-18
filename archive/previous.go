package archive

import (
	"bytes"
	"fmt"
	"io"
	"sort"

	"github.com/osshield/gopbs/pxar"
	"github.com/osshield/gopbs/reuse"
	"github.com/osshield/gopbs/scan"
)

// DefaultPaddingThreshold is the share of reused chunk bytes that may belong
// to files not referenced by the new archive (the previous chunks at the
// edges of a run of unchanged files carry bytes of neighbouring files).
// Above it the run is read and chunked again. Matches the upstream client.
const DefaultPaddingThreshold = 0.1

// PayloadChunk is one entry of the previous payload stream's dynamic index:
// the chunk's end offset in that stream and its digest.
type PayloadChunk struct {
	EndOffset uint64
	Digest    [32]byte
}

// Previous is the previous snapshot's split archive as needed for metadata
// change detection: every regular file's encoded metadata and payload
// reference, plus the payload stream's chunk layout.
type Previous struct {
	files  map[string]prevFile
	chunks []PayloadChunk
}

type prevFile struct {
	meta   []byte
	size   uint64
	offset uint64
}

// LoadPrevious indexes a previous v2 metadata stream (as uploaded, e.g. a
// local copy) against its payload stream's index. Files, sizes and offsets
// come from the metadata stream; chunk boundaries from the index.
func LoadPrevious(meta io.Reader, chunks []PayloadChunk) (*Previous, error) {
	p := &Previous{files: make(map[string]prevFile), chunks: chunks}
	version, err := pxar.DecodeMetadata(meta, func(f pxar.MetaFile) error {
		p.files[f.Path] = prevFile{meta: f.Meta, size: f.Size, offset: f.PayloadOffset}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if version != 2 {
		return nil, fmt.Errorf("archive: previous archive is format version %d; change detection needs a v2 split archive", version)
	}
	for i := 1; i < len(chunks); i++ {
		if chunks[i].EndOffset <= chunks[i-1].EndOffset {
			return nil, fmt.Errorf("archive: previous payload index is not ascending at entry %d", i)
		}
	}
	return p, nil
}

// Files is the number of regular files known from the previous snapshot
func (p *Previous) Files() int { return len(p.files) }

// chunksFor returns the previous chunks covering the payload range
// [start, end) plus the covered span [cStart, cEnd). ok is false when the
// range lies beyond the index.
func (p *Previous) chunksFor(start, end uint64) (cs []reuse.Chunk, cStart, cEnd uint64, ok bool) {
	if end <= start || len(p.chunks) == 0 || end > p.chunks[len(p.chunks)-1].EndOffset {
		return nil, 0, 0, false
	}
	first := sort.Search(len(p.chunks), func(i int) bool { return p.chunks[i].EndOffset > start })
	prevEnd := uint64(0)
	if first > 0 {
		prevEnd = p.chunks[first-1].EndOffset
	}
	cStart = prevEnd
	for i := first; i < len(p.chunks); i++ {
		c := p.chunks[i]
		cs = append(cs, reuse.Chunk{Digest: c.Digest, Size: c.EndOffset - prevEnd})
		prevEnd = c.EndOffset
		if c.EndOffset >= end {
			break
		}
	}
	return cs, cStart, prevEnd, true
}

// ReuseStats reports what metadata change detection achieved for one
// generation.
type ReuseStats struct {
	// Files is the number of regular files in the archive
	Files int
	// ReusedFiles were not read: their payload was referenced from the
	// previous snapshot's chunks
	ReusedFiles int
	// ReusedBytes is the content size of the reused files
	ReusedBytes uint64
	// InjectedBytes is the size of the previous chunks referenced, including
	// padding (bytes of neighbouring files inside boundary chunks)
	InjectedBytes uint64
	// RejectedRuns counts runs of unchanged files that were read anyway
	// because the boundary padding exceeded the threshold
	RejectedRuns int
}

// payloadPlan is the per-payload decision, in plan order
type payloadPlan struct {
	node  *scan.Node
	reuse bool
	// reuse: offset of the file's payload record relative to the injected
	// span, and its size; the run's first entry carries the chunks to inject,
	// the last one the span's total size
	rel      uint64
	size     uint64
	inject   []reuse.Chunk
	runEnd   bool
	runTotal uint64
	// read: index into the read list (the ledger's sequence)
	readSeq int
}

// collectPayloadPaths lists the payload nodes in plan order with their
// archive paths (the emitter's walk order and naming)
func collectPayloadPaths(n *scan.Node, apath string, nodes []*scan.Node, paths []string) ([]*scan.Node, []string) {
	switch n.Kind {
	case scan.KindFile, scan.KindStream:
		return append(nodes, n), append(paths, apath)
	case scan.KindDirectory:
		for _, c := range n.Children {
			nodes, paths = collectPayloadPaths(c, joinArchive(apath, c.Name), nodes, paths)
		}
	}
	return nodes, paths
}

// planReuse decides, for every payload in plan order, whether its content
// is read or referenced from the previous snapshot. Consecutive unchanged
// files whose previous payload records are in ascending order form a run;
// a run is reused when the previous chunks covering it carry at most
// threshold padding, and is read otherwise. Returns the plan and the nodes
// that will be read, in order.
func planReuse(nodes []*scan.Node, paths []string, prev *Previous, threshold float64) ([]payloadPlan, []*scan.Node, ReuseStats) {
	plan := make([]payloadPlan, len(nodes))
	stats := ReuseStats{Files: len(nodes)}
	read := make([]*scan.Node, 0, len(nodes))
	markRead := func(i int) {
		plan[i] = payloadPlan{node: nodes[i], readSeq: len(read)}
		read = append(read, nodes[i])
	}
	if prev == nil {
		for i := range nodes {
			markRead(i)
		}
		return plan, read, stats
	}
	if threshold <= 0 {
		threshold = DefaultPaddingThreshold
	}
	var scratch []byte
	unchanged := func(i int) (prevFile, bool) {
		n := nodes[i]
		if n.Kind != scan.KindFile {
			return prevFile{}, false
		}
		pf, ok := prev.files[paths[i]]
		if !ok || pf.size != uint64(n.Stat.Size) {
			return prevFile{}, false
		}
		scratch = metadataBytes(scratch[:0], n)
		if !bytes.Equal(scratch, pf.meta) {
			return prevFile{}, false
		}
		return pf, true
	}

	for i := 0; i < len(nodes); {
		pf, ok := unchanged(i)
		if !ok {
			markRead(i)
			i++
			continue
		}
		// Extend the run while files stay unchanged and their previous records
		// keep ascending (the reused span must be one contiguous range)
		run := []prevFile{pf}
		k := i + 1
		for k < len(nodes) {
			next, ok := unchanged(k)
			if !ok || next.offset <= run[len(run)-1].offset {
				break
			}
			run = append(run, next)
			k++
		}
		start := run[0].offset
		last := run[len(run)-1]
		end := last.offset + pxar.HeaderSize + last.size
		chunks, cStart, cEnd, ok := prev.chunksFor(start, end)
		used := uint64(0)
		for _, f := range run {
			used += pxar.HeaderSize + f.size
		}
		total := cEnd - cStart
		if !ok || total < used || float64(total-used)/float64(total) > threshold {
			if ok {
				stats.RejectedRuns++
			}
			for j := i; j < k; j++ {
				markRead(j)
			}
			i = k
			continue
		}
		for j := i; j < k; j++ {
			f := run[j-i]
			plan[j] = payloadPlan{node: nodes[j], reuse: true, rel: f.offset - cStart, size: f.size}
			stats.ReusedFiles++
			stats.ReusedBytes += f.size
		}
		plan[i].inject = chunks
		plan[k-1].runEnd = true
		plan[k-1].runTotal = total
		stats.InjectedBytes += total
		i = k
	}
	return plan, read, stats
}
