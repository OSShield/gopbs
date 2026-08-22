package pbs

import (
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"
)

// Auth selects an authentication method. Implementations are sealed:
// TokenAuth and PasswordAuth.
type Auth interface{ isAuth() }

// TokenAuth authenticates with an API token: AuthID is
// "user@realm!tokenname", Secret the token secret. Sent as
// "Authorization: PBSAPIToken=<authid>:<secret>" on every request.
type TokenAuth struct {
	AuthID string
	Secret string
}

func (TokenAuth) isAuth() {}

// PasswordAuth authenticates with username and password via
// /api2/json/access/ticket. Tickets are cached and renewed automatically.
type PasswordAuth struct {
	Username string // without realm
	Realm    string // e.g. "pam" or "pbs"
	Password string
}

func (PasswordAuth) isAuth() {}

func (a PasswordAuth) userID() string { return a.Username + "@" + a.Realm }

// Config configures a Client.
type Config struct {
	// BaseURL is the server address, e.g. "https://pbs.example.com:8007".
	// The scheme must be https; the port defaults to 8007.
	BaseURL string

	Auth Auth

	// Fingerprint pins the server certificate: the SHA-256 of its DER
	// encoding as colon-separated hex (case-insensitive). When set, it is
	// always enforced and replaces chain verification. When empty, standard
	// chain verification applies.
	Fingerprint string

	// InsecureSkipAll disables certificate verification entirely. For lab
	// use only; Fingerprint is the supported way to trust a self-signed
	// server.
	InsecureSkipAll bool

	Datastore string

	Namespace string // optional

	// Workers is the number of in-flight chunk uploads (phase-8 pipeline);
	// 0 = 4.
	Workers int

	// ChunkSizeAvg is the content-defined chunking target; 0 = 4 MiB.
	// Must be a power of two.
	ChunkSizeAvg uint64

	// OnUploadProgress, when set, is called by the upload pipeline as chunks
	// are committed to an index, in stream order (Stats.Size grows
	// monotonically), and once more with done=true after the index closed.
	// Called from the uploading goroutine; keep it fast.
	OnUploadProgress func(archiveName string, stats UploadStats, done bool)
}

// SnapshotRef identifies the snapshot a backup session writes.
type SnapshotRef struct {
	Type string    // "host", "vm" or "ct"; default "host"
	ID   string    // default: os.Hostname()
	Time time.Time // default: now; fixed for the whole session
}

func (r SnapshotRef) withDefaults() (SnapshotRef, error) {
	if r.Type == "" {
		r.Type = "host"
	}
	switch r.Type {
	case "host", "vm", "ct":
	default:
		return r, fmt.Errorf("pbs: invalid backup type %q", r.Type)
	}
	if r.ID == "" {
		host, err := os.Hostname()
		if err != nil {
			return r, fmt.Errorf("pbs: no backup id and no hostname: %w", err)
		}
		r.ID = host
	}
	if r.Time.IsZero() {
		r.Time = time.Now()
	}
	return r, nil
}

// hostPort extracts the dial address from the base URL.
func hostPort(baseURL string) (string, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("pbs: invalid base URL: %w", err)
	}
	if u.Scheme != "https" {
		return "", fmt.Errorf("pbs: base URL must use https, got %q", u.Scheme)
	}
	if u.Host == "" {
		return "", fmt.Errorf("pbs: base URL %q has no host", baseURL)
	}
	host := u.Host
	if !strings.Contains(strings.TrimPrefix(host, "["), ":") || strings.HasSuffix(host, "]") {
		host += ":8007"
	}
	return host, nil
}
