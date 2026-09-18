package reuse

import (
	"bytes"
	"io"
	"testing"
)

func TestFramingRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)
	chunks := []Chunk{{Digest: [32]byte{1, 2, 3}, Size: 4096}, {Digest: [32]byte{9}, Size: 12}}
	if _, err := w.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if err := w.Inject(chunks); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(nil); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("tail")); err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(buf.Bytes(), []byte(Magic)) {
		t.Fatal("magic missing")
	}

	r, prefix, err := NewReader(bytes.NewReader(buf.Bytes()))
	if err != nil || prefix != nil {
		t.Fatalf("NewReader: %v %v", err, prefix)
	}
	kind, data, _, err := r.Next()
	if err != nil || kind != KindData || string(data) != "hello" {
		t.Fatalf("frame 1: %d %q %v", kind, data, err)
	}
	kind, _, got, err := r.Next()
	if err != nil || kind != KindInject || len(got) != 2 || got[0] != chunks[0] || got[1] != chunks[1] {
		t.Fatalf("frame 2: %d %+v %v", kind, got, err)
	}
	kind, data, _, err = r.Next()
	if err != nil || kind != KindData || string(data) != "tail" {
		t.Fatalf("frame 3: %d %q %v", kind, data, err)
	}
	if _, _, _, err := r.Next(); err != io.EOF {
		t.Fatalf("expected EOF, got %v", err)
	}
}

func TestNotFramed(t *testing.T) {
	for _, in := range []string{"", "abc", "plain payload stream bytes"} {
		r, prefix, err := NewReader(bytes.NewReader([]byte(in)))
		if err != ErrNotFramed || r != nil {
			t.Fatalf("%q: %v %v", in, r, err)
		}
		want := in
		if len(want) > len(Magic) {
			want = want[:len(Magic)]
		}
		if string(prefix) != want {
			t.Fatalf("%q: prefix %q, want %q", in, prefix, want)
		}
	}
}
