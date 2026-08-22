package pbs_test

// An in-process mock PBS server: a TLS listener that answers the regular
// API's ticket login, performs the backup-protocol 101 upgrade, then serves
// the session endpoints over HTTP/2 — verifying chunk framing (magic, CRC,
// compression, digest) as the real server would, and recording everything
// for assertions.

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
	"golang.org/x/net/http2"
)

type mockIndex struct {
	name       string
	digests    []string
	offsets    []uint64
	closed     bool
	csum       string
	size       uint64
	chunkCount uint64
}

type mockPBS struct {
	t           *testing.T
	ln          net.Listener
	fingerprint string
	baseURL     string

	zdec *zstd.Decoder

	mu          sync.Mutex
	loginCount  int
	upgradeReqs []*http.Request
	sessions    []net.Conn
	nextWID     uint64
	indexes     map[uint64]*mockIndex
	chunks      map[string][]byte // digest hex -> plaintext
	blobs       map[string][]byte // file name -> decoded payload
	previous    map[string][]byte // archive name -> raw didx
	finished    bool
	failUpgrade int            // respond with this status instead of 101
	failPath    map[string]int // h2 path -> status for the next call
}

func newMockPBS(t *testing.T) *mockPBS {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "mock-pbs"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
	})
	if err != nil {
		t.Fatal(err)
	}
	dec, err := zstd.NewReader(nil)
	if err != nil {
		t.Fatal(err)
	}

	m := &mockPBS{
		t:           t,
		ln:          ln,
		fingerprint: hex.EncodeToString(sum[:]),
		baseURL:     "https://" + ln.Addr().String(),
		zdec:        dec,
		nextWID:     1,
		indexes:     make(map[uint64]*mockIndex),
		chunks:      make(map[string][]byte),
		blobs:       make(map[string][]byte),
		previous:    make(map[string][]byte),
		failPath:    make(map[string]int),
	}
	go m.serve()
	t.Cleanup(func() { ln.Close(); dec.Close() })
	return m
}

func (m *mockPBS) serve() {
	for {
		conn, err := m.ln.Accept()
		if err != nil {
			return
		}
		go m.handleConn(conn)
	}
}

func (m *mockPBS) handleConn(conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		switch {
		case req.URL.Path == "/api2/json/access/ticket":
			m.handleTicket(conn, req)
			return // Connection: close
		case strings.HasSuffix(req.URL.Path, "/api2/json/backup"):
			m.handleUpgrade(conn, req)
			return
		default:
			fmt.Fprintf(conn, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
			return
		}
	}
}

func (m *mockPBS) handleTicket(conn net.Conn, req *http.Request) {
	if err := req.ParseForm(); err != nil {
		return
	}
	m.mu.Lock()
	m.loginCount++
	m.mu.Unlock()

	if req.PostFormValue("password") != "hunter2" {
		fmt.Fprintf(conn, "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		return
	}
	body, _ := json.Marshal(map[string]any{"data": map[string]string{
		"ticket":              "PBS:user@pam:TICKETDATA==",
		"CSRFPreventionToken": "CSRFTOKEN",
	}})
	fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		len(body), body)
}

func (m *mockPBS) handleUpgrade(conn net.Conn, req *http.Request) {
	m.mu.Lock()
	m.upgradeReqs = append(m.upgradeReqs, req)
	fail := m.failUpgrade
	m.mu.Unlock()

	if fail != 0 {
		fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\nContent-Length: 7\r\nConnection: close\r\n\r\nrefused",
			fail, http.StatusText(fail))
		return
	}
	if req.Header.Get("Upgrade") != "proxmox-backup-protocol-v1" {
		fmt.Fprintf(conn, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		return
	}
	fmt.Fprintf(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: proxmox-backup-protocol-v1\r\nConnection: Upgrade\r\n\r\n")

	m.mu.Lock()
	m.sessions = append(m.sessions, conn)
	m.mu.Unlock()

	(&http2.Server{}).ServeConn(conn, &http2.ServeConnOpts{
		Handler: http.HandlerFunc(m.handleH2),
	})
}

func (m *mockPBS) dropSessions() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, c := range m.sessions {
		c.Close()
	}
	m.sessions = nil
}

func httpError(w http.ResponseWriter, code int, format string, args ...any) {
	w.WriteHeader(code)
	fmt.Fprintf(w, format, args...)
}

func (m *mockPBS) handleH2(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	if code, ok := m.failPath[r.URL.Path]; ok {
		delete(m.failPath, r.URL.Path)
		m.mu.Unlock()
		httpError(w, code, "mock failure for %s", r.URL.Path)
		return
	}
	m.mu.Unlock()

	body, err := io.ReadAll(r.Body)
	if err != nil {
		httpError(w, 500, "body: %v", err)
		return
	}

	switch r.Method + " " + r.URL.Path {
	case "POST /dynamic_index":
		name := r.URL.Query().Get("archive-name")
		if name == "" {
			httpError(w, 400, "create without archive-name query parameter")
			return
		}
		in := struct{ Name string }{name}
		m.mu.Lock()
		wid := m.nextWID
		m.nextWID++
		m.indexes[wid] = &mockIndex{name: in.Name}
		m.mu.Unlock()
		fmt.Fprintf(w, `{"data":%d}`, wid)

	case "PUT /dynamic_index":
		var in struct {
			WID     uint64   `json:"wid"`
			Digests []string `json:"digest-list"`
			Offsets []uint64 `json:"offset-list"`
		}
		if err := json.Unmarshal(body, &in); err != nil {
			httpError(w, 400, "bad append body")
			return
		}
		if len(in.Digests) != len(in.Offsets) || len(in.Digests) == 0 || len(in.Digests) > 128 {
			httpError(w, 400, "bad append lengths: %d/%d", len(in.Digests), len(in.Offsets))
			return
		}
		m.mu.Lock()
		defer m.mu.Unlock()
		idx, ok := m.indexes[in.WID]
		if !ok || idx.closed {
			httpError(w, 400, "unknown or closed wid %d", in.WID)
			return
		}
		for _, d := range in.Digests {
			if _, ok := m.chunks[d]; !ok {
				httpError(w, 400, "append references unknown chunk %s", d)
				return
			}
		}
		idx.digests = append(idx.digests, in.Digests...)
		idx.offsets = append(idx.offsets, in.Offsets...)

	case "POST /dynamic_close":
		q := r.URL.Query()
		var in struct {
			WID        uint64
			Csum       string
			Size       uint64
			ChunkCount uint64
		}
		var perr error
		if in.WID, perr = strconv.ParseUint(q.Get("wid"), 10, 64); perr != nil {
			httpError(w, 400, "close without wid query parameter")
			return
		}
		in.Csum = q.Get("csum")
		if in.Size, perr = strconv.ParseUint(q.Get("size"), 10, 64); perr != nil {
			httpError(w, 400, "close without size query parameter")
			return
		}
		if in.ChunkCount, perr = strconv.ParseUint(q.Get("chunk-count"), 10, 64); perr != nil {
			httpError(w, 400, "close without chunk-count query parameter")
			return
		}
		m.mu.Lock()
		defer m.mu.Unlock()
		idx, ok := m.indexes[in.WID]
		if !ok || idx.closed {
			httpError(w, 400, "unknown or closed wid %d", in.WID)
			return
		}
		if uint64(len(idx.digests)) != in.ChunkCount {
			httpError(w, 400, "chunk-count %d, appended %d", in.ChunkCount, len(idx.digests))
			return
		}
		idx.closed, idx.csum, idx.size, idx.chunkCount = true, in.Csum, in.Size, in.ChunkCount

	case "POST /dynamic_chunk":
		q := r.URL.Query()
		plain, err := m.decodeBlob(body)
		if err != nil {
			httpError(w, 400, "chunk: %v", err)
			return
		}
		if enc, _ := strconv.Atoi(q.Get("encoded-size")); enc != len(body) {
			httpError(w, 400, "encoded-size %d, body %d", enc, len(body))
			return
		}
		if size, _ := strconv.Atoi(q.Get("size")); size != len(plain) {
			httpError(w, 400, "size %d, plaintext %d", size, len(plain))
			return
		}
		sum := sha256.Sum256(plain)
		if got := hex.EncodeToString(sum[:]); got != q.Get("digest") {
			httpError(w, 400, "digest %s, content hashes to %s", q.Get("digest"), got)
			return
		}
		m.mu.Lock()
		m.chunks[q.Get("digest")] = plain
		m.mu.Unlock()

	case "POST /blob":
		q := r.URL.Query()
		payload, err := m.decodeBlob(body)
		if err != nil {
			httpError(w, 400, "blob: %v", err)
			return
		}
		if enc, _ := strconv.Atoi(q.Get("encoded-size")); enc != len(body) {
			httpError(w, 400, "encoded-size %d, body %d", enc, len(body))
			return
		}
		m.mu.Lock()
		m.blobs[q.Get("file-name")] = payload
		m.mu.Unlock()

	case "GET /previous":
		m.mu.Lock()
		data, ok := m.previous[r.URL.Query().Get("archive-name")]
		m.mu.Unlock()
		if !ok {
			httpError(w, 404, "no previous backup")
			return
		}
		w.Write(data)

	case "POST /finish":
		m.mu.Lock()
		m.finished = true
		m.mu.Unlock()

	default:
		httpError(w, 404, "mock: no endpoint %s %s", r.Method, r.URL.Path)
	}
}

// decodeBlob validates blob framing exactly as the server would: magic,
// CRC32 over the payload, zstd for the compressed magic.
func (m *mockPBS) decodeBlob(framed []byte) ([]byte, error) {
	if len(framed) < 12 {
		return nil, fmt.Errorf("framed blob too short: %d", len(framed))
	}
	payload := framed[12:]
	if crc := binary.LittleEndian.Uint32(framed[8:12]); crc != crc32.ChecksumIEEE(payload) {
		return nil, fmt.Errorf("crc mismatch")
	}
	switch {
	case bytes.Equal(framed[:8], []byte{66, 171, 56, 7, 190, 131, 112, 161}):
		return payload, nil
	case bytes.Equal(framed[:8], []byte{49, 185, 88, 66, 111, 182, 163, 127}):
		return m.zdec.DecodeAll(payload, nil)
	}
	return nil, fmt.Errorf("unknown blob magic %x", framed[:8])
}

// makeDidx builds a synthetic dynamic index file for previous-backup tests.
func makeDidx(entries ...[32]byte) []byte {
	out := make([]byte, 4096, 4096+40*len(entries))
	copy(out, []byte{28, 145, 78, 165, 25, 186, 179, 205})
	offset := uint64(0)
	for _, d := range entries {
		offset += 1 << 20
		out = binary.LittleEndian.AppendUint64(out, offset)
		out = append(out, d[:]...)
	}
	return out
}
