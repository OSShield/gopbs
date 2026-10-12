package pbs

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// Realm is one authentication realm of the server.
type Realm struct {
	Realm   string // e.g. "pam", "pbs", or an OpenID/LDAP realm's name
	Type    string // "pam", "pbs", "openid", "ldap", "ad"
	Comment string
}

// Realms lists the server's authentication realms. No credentials needed.
func (c *Client) Realms(ctx context.Context) ([]Realm, error) {
	var data []struct {
		Realm   string `json:"realm"`
		Type    string `json:"type"`
		Comment string `json:"comment"`
	}
	if err := c.do(ctx, http.MethodGet, "/api2/json/access/domains", "listing realms", nil, false, &data); err != nil {
		return nil, err
	}
	out := make([]Realm, 0, len(data))
	for _, d := range data {
		out = append(out, Realm{Realm: d.Realm, Type: d.Type, Comment: d.Comment})
	}
	return out, nil
}

// LoginResult is the outcome of Login: either Auth is set, or TFA asks for
// a second factor.
type LoginResult struct {
	Auth TicketAuth
	TFA  *TFAChallenge
}

// TFAChallenge is a pending second-factor login.
type TFAChallenge struct {
	c        *Client
	username string
	ticket   string // partial "PBS:!tfa!…" ticket
	// Types lists the second factors the user has configured and the server
	// offers, sorted: "totp", "recovery", "webauthn", "yubico", ….
	Types []string
}

// Login logs in with a user id ("user@realm") and password. Users with a
// second factor get a TFAChallenge to answer with Respond.
func (c *Client) Login(ctx context.Context, userID, password string) (*LoginResult, error) {
	t, err := c.postTicket(ctx, "/api2/json/access/ticket", "ticket login",
		url.Values{"username": {userID}, "password": {password}})
	if err != nil {
		return nil, err
	}
	if !isTFATicket(t.Ticket) {
		return &LoginResult{Auth: ticketAuth(t, userID)}, nil
	}
	ch := &TFAChallenge{c: c, username: userID, ticket: t.Ticket}
	// The partial ticket embeds the URL-encoded challenge JSON:
	// "PBS:!tfa!<challenge>:<time>::<signature>".
	enc, _, _ := strings.Cut(strings.TrimPrefix(t.Ticket, "PBS:!tfa!"), ":")
	if raw, err := url.QueryUnescape(enc); err == nil {
		var types map[string]json.RawMessage
		if json.Unmarshal([]byte(raw), &types) == nil {
			for k, v := range types {
				if s := string(v); s != "false" && s != "null" {
					ch.Types = append(ch.Types, k)
				}
			}
			sort.Strings(ch.Types)
		}
	}
	return &LoginResult{TFA: ch}, nil
}

// Respond answers the challenge with a second factor: kind is one of
// Types ("totp", "recovery", …) and code the user's answer.
func (ch *TFAChallenge) Respond(ctx context.Context, kind, code string) (TicketAuth, error) {
	t, err := ch.c.postTicket(ctx, "/api2/json/access/ticket", "second factor", url.Values{
		"username":      {ch.username},
		"password":      {kind + ":" + code},
		"tfa-challenge": {ch.ticket},
	})
	if err != nil {
		return TicketAuth{}, err
	}
	if isTFATicket(t.Ticket) {
		return TicketAuth{}, fmt.Errorf("%w: second factor rejected", ErrAuth)
	}
	return ticketAuth(t, ch.username), nil
}

// OpenIDAuthURL starts an OpenID Connect login on realm: the user opens the
// returned URL, and the identity provider redirects to redirectURL with
// "state" and "code" query parameters for OpenIDLogin. redirectURL must be
// allowed by the provider.
func (c *Client) OpenIDAuthURL(ctx context.Context, realm, redirectURL string) (string, error) {
	var u string
	err := c.do(ctx, http.MethodPost, "/api2/json/access/openid/auth-url", "openid auth url",
		url.Values{"realm": {realm}, "redirect-url": {redirectURL}}, false, &u)
	return u, err
}

// OpenIDLogin completes an OpenID Connect login with the redirect's state
// and code; redirectURL is the one given to OpenIDAuthURL.
func (c *Client) OpenIDLogin(ctx context.Context, state, code, redirectURL string) (TicketAuth, error) {
	t, err := c.postTicket(ctx, "/api2/json/access/openid/login", "openid login",
		url.Values{"state": {state}, "code": {code}, "redirect-url": {redirectURL}})
	if err != nil {
		return TicketAuth{}, err
	}
	return ticketAuth(t, t.Username), nil
}

func ticketAuth(t ticketResponse, fallbackUser string) TicketAuth {
	user := t.Username
	if user == "" {
		user = fallbackUser
	}
	return TicketAuth{Username: user, Ticket: t.Ticket, CSRF: t.CSRF}
}
