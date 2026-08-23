package archive

import (
	"github.com/scheiblingco/gopbs/pxar"
	"github.com/scheiblingco/gopbs/scan"
)

// payloadEmitter streams the v2 payload stream (.ppxar): a start marker, one
// standard payload record per regular file in plan order, a tail marker. In
// synchronous mode it also publishes the bound sizes to the ledger (in async
// mode the dispatcher publishes them earlier, at dispatch time).
type payloadEmitter struct {
	w       *countWriter
	src     payloadSource
	warn    func(Warning)
	ledger  *refLedger
	publish bool // the source does not self-publish binds (sync mode)
}

func (pe *payloadEmitter) run(payloads []*scan.Node) error {
	if err := pe.w.write(pxar.AppendPayloadStartMarker(nil)); err != nil {
		return err
	}
	for _, n := range payloads {
		if err := pe.payload(n); err != nil {
			return err
		}
	}
	return pe.w.write(pxar.AppendPayloadTailMarker(nil))
}

func (pe *payloadEmitter) payload(n *scan.Node) error {
	pl, err := pe.src.open(n)
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
