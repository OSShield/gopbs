package archive_test

import (
	"context"
	"io"
	"sync"
	"testing"

	"github.com/osshield/gopbs/archive"
)

// generateV2 consumes both split streams concurrently (metadata emission can
// await payload dispatch progress, so sequential draining may stall).
func generateV2(t *testing.T, a *archive.Archive) (meta, payload []byte) {
	t.Helper()
	metaRC, payloadRC, err := a.GenerateV2(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer metaRC.Close()
	defer payloadRC.Close()

	var (
		wg         sync.WaitGroup
		payloadErr error
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		payload, payloadErr = io.ReadAll(payloadRC)
	}()
	meta, err = io.ReadAll(metaRC)
	wg.Wait()
	if err != nil {
		t.Fatal(err)
	}
	if payloadErr != nil {
		t.Fatal(payloadErr)
	}
	return meta, payload
}
