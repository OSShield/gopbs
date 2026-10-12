package pbs_test

import (
	"bytes"
	"context"
	"errors"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/osshield/gopbs/pbs"
	"github.com/osshield/gopbs/pbs/pbstest"
)

// anonClient has no Auth: enough for realms and logins.
func anonClient(t *testing.T, m *pbstest.Server) *pbs.Client {
	return clientFor(t, m, func(c *pbs.Config) { c.Auth, c.Datastore = nil, "" })
}

func TestRealms(t *testing.T) {
	m := pbstest.NewServer(t)
	realms, err := anonClient(t, m).Realms(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(realms) != 3 || realms[2] != (pbs.Realm{Realm: "sso", Type: "openid", Comment: "Company SSO"}) {
		t.Fatalf("realms = %+v", realms)
	}
}

func TestLogin(t *testing.T) {
	m := pbstest.NewServer(t)
	c := anonClient(t, m)
	ctx := context.Background()

	if _, err := c.Login(ctx, "user@pam", "wrong"); !errors.Is(err, pbs.ErrAuth) {
		t.Fatalf("bad password: %v", err)
	}
	res, err := c.Login(ctx, "user@pam", pbstest.Password)
	if err != nil {
		t.Fatal(err)
	}
	if res.TFA != nil || res.Auth != (pbs.TicketAuth{Username: "user@pam", Ticket: pbstest.Ticket, CSRF: "CSRFTOKEN"}) {
		t.Fatalf("login = %+v", res)
	}

	m.Lock()
	m.TFA = true
	m.Unlock()
	res, err = c.Login(ctx, "user@pam", pbstest.Password)
	if err != nil {
		t.Fatal(err)
	}
	if res.TFA == nil || !reflect.DeepEqual(res.TFA.Types, []string{"recovery", "totp"}) {
		t.Fatalf("expected a totp/recovery challenge, got %+v", res)
	}
	if _, err := res.TFA.Respond(ctx, "totp", "000000"); !errors.Is(err, pbs.ErrAuth) {
		t.Fatalf("bad code: %v", err)
	}
	auth, err := res.TFA.Respond(ctx, "totp", pbstest.TOTPCode)
	if err != nil {
		t.Fatal(err)
	}
	if auth.Ticket != pbstest.Ticket || auth.Username != "user@pam" {
		t.Fatalf("tfa auth = %+v", auth)
	}

	// Password auth cannot answer a challenge on its own.
	pw := clientFor(t, m, func(c *pbs.Config) {
		c.Auth = pbs.PasswordAuth{Username: "user", Realm: "pam", Password: pbstest.Password}
	})
	if _, err := pw.ListDatastores(ctx); err == nil || !strings.Contains(err.Error(), "second factor") {
		t.Fatalf("password auth with TFA: %v", err)
	}
}

func TestOpenID(t *testing.T) {
	m := pbstest.NewServer(t)
	c := anonClient(t, m)
	ctx := context.Background()
	const redirect = "http://127.0.0.1:8765/"

	raw, err := c.OpenIDAuthURL(ctx, "sso", redirect)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(raw)
	if err != nil || u.Query().Get("realm") != "sso" || u.Query().Get("redirect_uri") != redirect {
		t.Fatalf("auth url %q: %v", raw, err)
	}
	if _, err := c.OpenIDLogin(ctx, u.Query().Get("state"), "bad", redirect); !errors.Is(err, pbs.ErrAuth) {
		t.Fatalf("bad code: %v", err)
	}
	auth, err := c.OpenIDLogin(ctx, u.Query().Get("state"), pbstest.OIDCCode, redirect)
	if err != nil {
		t.Fatal(err)
	}
	if auth.Username != "alice@sso" || auth.Ticket != pbstest.Ticket {
		t.Fatalf("openid auth = %+v", auth)
	}
	m.Lock()
	defer m.Unlock()
	if f := m.LoginForms[len(m.LoginForms)-1]; f.Get("redirect-url") != redirect {
		t.Errorf("login form %v", f)
	}
}

func TestTicketAuth(t *testing.T) {
	m := pbstest.NewServer(t)
	ctx := context.Background()
	fresh := "PBS:user@pam:" + strings.ToUpper(strconv.FormatInt(time.Now().Unix(), 16)) + "::sig"
	c := clientFor(t, m, func(c *pbs.Config) { c.Auth = pbs.TicketAuth{Username: "user@pam", Ticket: fresh} })
	if _, err := c.ListDatastores(ctx); err != nil {
		t.Fatal(err)
	}
	m.Lock()
	cookie := m.APIReqs[0].Header.Get("Cookie")
	logins := m.LoginCount
	m.Unlock()
	if logins != 0 || cookie != "PBSAuthCookie="+url.QueryEscape(fresh) {
		t.Fatalf("fresh ticket: %d logins, cookie %q", logins, cookie)
	}

	// A ticket close to expiry is renewed by posting it as the password.
	old := "PBS:user@pam:5F000000::sig"
	c = clientFor(t, m, func(c *pbs.Config) { c.Auth = pbs.TicketAuth{Username: "user@pam", Ticket: old} })
	if _, err := c.ListDatastores(ctx); err != nil {
		t.Fatal(err)
	}
	m.Lock()
	defer m.Unlock()
	if m.LoginCount != 1 || m.LoginForms[0].Get("password") != old || m.LoginForms[0].Get("username") != "user@pam" {
		t.Fatalf("renewal: %d logins, forms %v", m.LoginCount, m.LoginForms)
	}
	if got := m.APIReqs[1].Header.Get("Cookie"); got != "PBSAuthCookie="+url.QueryEscape(pbstest.Ticket) {
		t.Fatalf("renewed cookie %q", got)
	}
}

func TestListings(t *testing.T) {
	m := pbstest.NewServer(t)
	ctx := context.Background()
	backup := func(ns, id string, at int64) {
		t.Helper()
		c := clientFor(t, m, func(c *pbs.Config) { c.Namespace = ns })
		s, err := c.StartBackup(ctx, pbs.SnapshotRef{ID: id, Time: time.Unix(at, 0)})
		if err != nil {
			t.Fatal(err)
		}
		defer s.Abort()
		if _, err := s.UploadStream(ctx, "data.db", bytes.NewReader([]byte("x"))); err != nil {
			t.Fatal(err)
		}
		if err := s.Finish(ctx); err != nil {
			t.Fatal(err)
		}
	}
	backup("", "org1", 1_700_000_000)
	backup("", "org1", 1_700_000_100)
	backup("", "org2", 1_700_000_050)
	backup("tenant/a", "x", 1_700_000_000)
	backup("tenant/b/deep", "y", 1_700_000_000)

	m.Lock()
	m.Datastores = []string{"zeta", "alpha"}
	m.Unlock()
	if _, err := anonClient(t, m).ListDatastores(ctx); err == nil {
		t.Fatal("listing datastores without auth should fail")
	}
	stores, err := clientFor(t, m, func(c *pbs.Config) { c.Datastore = "" }).ListDatastores(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(stores, []pbs.Datastore{{"alpha", "mock alpha"}, {"zeta", "mock zeta"}}) {
		t.Fatalf("datastores = %+v", stores)
	}

	nsPaths := func(parent string) []string {
		t.Helper()
		list, err := clientFor(t, m, func(c *pbs.Config) { c.Namespace = parent }).ListNamespaces(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, n := range list {
			out = append(out, n.Path)
		}
		return out
	}
	if got := nsPaths(""); !reflect.DeepEqual(got, []string{"tenant"}) {
		t.Fatalf("root namespaces = %v", got)
	}
	if got := nsPaths("tenant"); !reflect.DeepEqual(got, []string{"tenant/a", "tenant/b"}) {
		t.Fatalf("tenant namespaces = %v", got)
	}

	groups, err := clientFor(t, m, nil).ListGroups(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 2 || groups[0].ID != "org1" || groups[0].Count != 2 ||
		groups[0].LastBackup.Unix() != 1_700_000_100 || groups[1].ID != "org2" || len(groups[0].Files) == 0 {
		t.Fatalf("groups = %+v", groups)
	}
	if _, err := clientFor(t, m, func(c *pbs.Config) { c.Datastore = "" }).ListGroups(ctx); err == nil {
		t.Fatal("ListGroups without a datastore should fail")
	}
}
