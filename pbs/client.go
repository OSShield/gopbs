package pbs

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ticketLifetime is how long a PBS auth ticket is valid; we renew a margin
// earlier so long operations never start with an almost-expired ticket.
const (
	ticketLifetime    = 2 * time.Hour
	ticketRenewMargin = 15 * time.Minute
)

// Client holds connection settings and (for password auth) the cached
// ticket. Safe for concurrent use.
type Client struct {
	cfg      Config
	crypt    *cryptState // nil when Config.Crypt is nil
	addr     string      // host:port
	tlsConf  *tls.Config
	restHTTP *http.Client // HTTP/1.1 client for the regular API (ticket login)

	mu         sync.Mutex
	ticket     string
	csrf       string
	ticketTime time.Time
}

// NewClient validates the configuration. No connection is made until
// the first request. Auth and Datastore are checked by the calls that need
// them, so a client without them can still log in (Login, OpenIDLogin),
// list realms, or list datastores (with Auth).
func NewClient(cfg Config) (*Client, error) {
	if cfg.Workers < 0 {
		return nil, fmt.Errorf("pbs: negative worker count %d", cfg.Workers)
	}
	if cfg.ChunkSizeAvg != 0 && cfg.ChunkSizeAvg&(cfg.ChunkSizeAvg-1) != 0 {
		return nil, fmt.Errorf("pbs: ChunkSizeAvg %d is not a power of two", cfg.ChunkSizeAvg)
	}
	var crypt *cryptState
	if cfg.Crypt != nil {
		var err error
		if crypt, err = newCryptState(cfg.Crypt); err != nil {
			return nil, err
		}
	}

	// With DialSession the address only labels requests on the session
	// connection (the :authority pseudo-header); BaseURL may be omitted.
	addr := "localhost:8007"
	if cfg.BaseURL != "" || cfg.DialSession == nil {
		var err error
		if addr, err = hostPort(cfg.BaseURL); err != nil {
			return nil, err
		}
	}

	tlsConf, err := newTLSConfig(cfg)
	if err != nil {
		return nil, err
	}

	return &Client{
		cfg:     cfg,
		crypt:   crypt,
		addr:    addr,
		tlsConf: tlsConf,
		restHTTP: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig:   tlsConf,
				ForceAttemptHTTP2: false,
			},
		},
	}, nil
}

// authHeaders adds authentication to h. For password and ticket auth this
// logs in (or renews) as needed; mutating adds the CSRF token required for
// non-GET requests on the regular API.
func (c *Client) authHeaders(ctx context.Context, h http.Header, mutating bool) error {
	switch a := c.cfg.Auth.(type) {
	case TokenAuth:
		h.Set("Authorization", fmt.Sprintf("PBSAPIToken=%s:%s", a.AuthID, a.Secret))
		return nil
	case PasswordAuth, TicketAuth:
		ticket, csrf, err := c.ensureTicket(ctx)
		if err != nil {
			return err
		}
		h.Set("Cookie", "PBSAuthCookie="+url.QueryEscape(ticket))
		if mutating {
			h.Set("CSRFPreventionToken", csrf)
		}
		return nil
	case nil:
		return fmt.Errorf("pbs: Config.Auth is required")
	}
	return fmt.Errorf("pbs: unsupported auth type %T", c.cfg.Auth)
}

// ensureTicket returns a valid ticket: the cached one, a TicketAuth's
// ticket, or a fresh one from a password login or a renewal (PBS renews a
// ticket that is posted as the password).
func (c *Client) ensureTicket(ctx context.Context) (ticket, csrf string, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if t, ok := c.cfg.Auth.(TicketAuth); ok && c.ticket == "" {
		c.ticket, c.csrf, c.ticketTime = t.Ticket, t.CSRF, ticketIssued(t.Ticket)
	}
	if c.ticket != "" && time.Since(c.ticketTime) < ticketLifetime-ticketRenewMargin {
		return c.ticket, c.csrf, nil
	}

	var form url.Values
	switch a := c.cfg.Auth.(type) {
	case PasswordAuth:
		form = url.Values{"username": {a.userID()}, "password": {a.Password}}
	case TicketAuth:
		form = url.Values{"username": {a.Username}, "password": {c.ticket}}
	}
	t, err := c.postTicket(ctx, "/api2/json/access/ticket", "ticket login", form)
	if err != nil {
		return "", "", err
	}
	if isTFATicket(t.Ticket) {
		return "", "", fmt.Errorf("pbs: ticket login: second factor required; log in with Client.Login and use TicketAuth")
	}
	c.ticket, c.csrf, c.ticketTime = t.Ticket, t.CSRF, time.Now()
	return c.ticket, c.csrf, nil
}

// ticketResponse is the data of a successful login.
type ticketResponse struct {
	Ticket   string `json:"ticket"`
	CSRF     string `json:"CSRFPreventionToken"`
	Username string `json:"username"`
}

// postTicket POSTs an unauthenticated login form and decodes the ticket.
func (c *Client) postTicket(ctx context.Context, path, op string, form url.Values) (ticketResponse, error) {
	var t ticketResponse
	if err := c.do(ctx, http.MethodPost, path, op, form, false, &t); err != nil {
		return t, err
	}
	if t.Ticket == "" {
		return t, fmt.Errorf("pbs: %s: response carries no ticket", op)
	}
	return t, nil
}

// do performs one regular-API request: a GET with query parameters, or a
// POST with a form body. With auth, credentials are added. The response's
// "data" member is decoded into data.
func (c *Client) do(ctx context.Context, method, path, op string, params url.Values, auth bool, data any) error {
	if c.cfg.BaseURL == "" {
		return fmt.Errorf("pbs: %s requires Config.BaseURL", op)
	}
	u := &url.URL{Scheme: "https", Host: c.addr, Path: path}
	var body io.Reader
	if method == http.MethodGet {
		u.RawQuery = params.Encode()
	} else {
		body = strings.NewReader(params.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return fmt.Errorf("pbs: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if auth {
		if err := c.authHeaders(ctx, req.Header, method != http.MethodGet); err != nil {
			return err
		}
	}

	resp, err := c.restHTTP.Do(req)
	if err != nil {
		return fmt.Errorf("pbs: %s: %w", op, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return fmt.Errorf("pbs: %s: reading response: %w", op, err)
	}
	if resp.StatusCode != http.StatusOK {
		return statusError(op, resp.Status, resp.StatusCode, raw)
	}
	if err := json.Unmarshal(raw, &struct {
		Data any `json:"data"`
	}{data}); err != nil {
		return fmt.Errorf("pbs: %s: decoding response: %w", op, err)
	}
	return nil
}

// ticketIssued reads the issue time from a ticket
// ("PBS:<data>:<hex unix time>::<signature>"); unparsable tickets count as
// fresh, so the server decides.
func ticketIssued(ticket string) time.Time {
	head, _, _ := strings.Cut(ticket, "::")
	if i := strings.LastIndexByte(head, ':'); i >= 0 {
		if secs, err := strconv.ParseInt(head[i+1:], 16, 64); err == nil {
			return time.Unix(secs, 0)
		}
	}
	return time.Now()
}

func isTFATicket(ticket string) bool { return strings.HasPrefix(ticket, "PBS:!tfa!") }
