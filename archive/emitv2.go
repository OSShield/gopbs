package archive

import (
	"github.com/osshield/gopbs/pxar"
	"github.com/osshield/gopbs/reuse"
)

// payloadEmitter streams the v2 payload stream (.ppxar): a start marker, one
// standard payload record per regular file in plan order, a tail marker. In
// synchronous mode it also publishes the bound sizes to the ledger (in async
// mode the dispatcher publishes them earlier, at dispatch time).
//
// With metadata change detection the stream is framed (package reuse): runs
// of unchanged files are not read; the frame at their position tells the
// uploader which previous chunks to reference instead.
type payloadEmitter struct {
	w       *countWriter
	src     payloadSource
	warn    func(Warning)
	ledger  *refLedger
	publish bool          // the source does not self-publish binds (sync mode)
	inject  *reuse.Writer // set when the stream is framed
}

func (pe *payloadEmitter) run(plan []payloadPlan) error {
	if err := pe.w.write(pxar.AppendPayloadStartMarker(nil)); err != nil {
		return err
	}
	for _, p := range plan {
		if p.reuse {
			if p.inject != nil {
				if err := pe.inject.Inject(p.inject); err != nil {
					return err
				}
			}
			continue
		}
		if err := pe.payload(p); err != nil {
			return err
		}
	}
	return pe.w.write(pxar.AppendPayloadTailMarker(nil))
}

func (pe *payloadEmitter) payload(p payloadPlan) error {
	pl, err := pe.src.open(p.node)
	if pe.publish {
		if err != nil {
			pe.ledger.publish(0, err)
		} else {
			pe.ledger.publish(pl.Size(), nil)
		}
	}
	if err != nil {
		return err
	}
	defer pl.Close()

	if err := pe.w.write(pxar.AppendPayloadHeader(nil, uint64(pl.Size()))); err != nil {
		return err
	}
	if err := pl.Copy(pe.w); err != nil {
		return err
	}
	for _, w := range pl.Warnings() {
		pe.warn(w)
	}
	return nil
}
