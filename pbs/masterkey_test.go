package pbs_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"strings"
	"testing"

	"github.com/osshield/gopbs/pbs"
	"github.com/osshield/gopbs/pbs/pbstest"
)

// testdata/master-*.pem were written by "proxmox-backup-client key
// create-master-key" with the password "masterpass".
func loadTestMaster(t *testing.T) (*rsa.PrivateKey, []byte) {
	t.Helper()
	priv, err := os.ReadFile("testdata/master-private.pem")
	if err != nil {
		t.Fatal(err)
	}
	pub, err := os.ReadFile("testdata/master-public.pem")
	if err != nil {
		t.Fatal(err)
	}
	key, err := pbs.LoadMasterKey(priv, []byte("masterpass"))
	if err != nil {
		t.Fatal(err)
	}
	return key, pub
}

func TestLoadMasterKey(t *testing.T) {
	key, pub := loadTestMaster(t)
	block, _ := pem.Decode(pub)
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !key.PublicKey.Equal(pubKey) {
		t.Fatal("private key does not match master-public.pem")
	}

	priv, _ := os.ReadFile("testdata/master-private.pem")
	for _, tc := range []struct {
		pass []byte
		want string
	}{
		{[]byte("wrong"), "wrong passphrase"},
		{nil, "requires a passphrase"},
	} {
		if _, err := pbs.LoadMasterKey(priv, tc.pass); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("passphrase %q: err = %v, want %q", tc.pass, err, tc.want)
		}
	}

	gen, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(gen)
	for typ, der := range map[string][]byte{"RSA PRIVATE KEY": x509.MarshalPKCS1PrivateKey(gen), "PRIVATE KEY": pkcs8} {
		data := pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
		if k, err := pbs.LoadMasterKey(data, nil); err != nil || !k.Equal(gen) {
			t.Errorf("%s: %v", typ, err)
		}
		if _, err := pbs.LoadMasterKey(data, []byte("x")); err == nil {
			t.Errorf("%s: passphrase accepted for an unencrypted key", typ)
		}
	}
}

// A backup wrapped for the master key reads back after recovering the key.
func TestRecoverKey(t *testing.T) {
	master, pub := loadTestMaster(t)
	key := testKey(t)
	m := pbstest.NewServer(t)
	m.SetCryptKey(key)
	data := randomBytes(200_000)
	ref, _ := backupStream(t, clientFor(t, m, func(c *pbs.Config) {
		c.Crypt = &pbs.CryptConfig{Key: key, MasterPublicKey: pub}
	}), pbs.SnapshotRef{ID: "org1"}, data, []byte("{}"))

	ctx := context.Background()
	info, err := startReader(t, clientFor(t, m, nil), ref).RecoverKey(ctx, master)
	if err != nil {
		t.Fatal(err)
	}
	if info.Key != key {
		t.Fatal("recovered a different key")
	}

	recovered := clientFor(t, m, func(c *pbs.Config) { c.Crypt = info.CryptConfig(pbs.CryptModeEncrypt) })
	got, err := readIndex(ctx, startReader(t, recovered, ref), "data.db")
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("reading with the recovered key: %v", err)
	}

	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := startReader(t, clientFor(t, m, nil), ref).RecoverKey(ctx, other); err == nil ||
		!strings.Contains(err.Error(), "wrong master key") {
		t.Fatalf("wrong master key: %v", err)
	}
}
