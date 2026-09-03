package pbs_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/osshield/gopbs/pbs"
)

func TestKeyFileRoundTrip(t *testing.T) {
	key, err := pbs.GenerateEncryptionKey()
	if err != nil {
		t.Fatal(err)
	}
	pass := []byte("secret-passphrase")

	cases := []struct {
		name string
		kdf  pbs.KDF
		pass []byte
	}{
		{"scrypt", pbs.KDFScrypt, pass},
		{"pbkdf2", pbs.KDFPBKDF2, pass},
		{"plain", pbs.KDFNone, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data, err := pbs.CreateKeyFile(key, tc.pass, tc.kdf, "the hint")
			if err != nil {
				t.Fatal(err)
			}
			info, err := pbs.LoadKeyFile(data, tc.pass)
			if err != nil {
				t.Fatal(err)
			}
			if info.Key != key {
				t.Fatal("key does not round-trip")
			}
			if info.Hint != "the hint" {
				t.Fatalf("hint %q", info.Hint)
			}
			if info.Created.IsZero() || info.Modified.IsZero() {
				t.Fatal("timestamps not parsed")
			}
			want, err := pbs.CryptFingerprint(&pbs.CryptConfig{Key: key})
			if err != nil {
				t.Fatal(err)
			}
			if info.Fingerprint != want {
				t.Fatalf("fingerprint %q, want %q", info.Fingerprint, want)
			}

			// The file must carry the proxmox shape.
			var f map[string]any
			if err := json.Unmarshal(data, &f); err != nil {
				t.Fatal(err)
			}
			for _, field := range []string{"kdf", "created", "modified", "data", "fingerprint"} {
				if _, ok := f[field]; !ok {
					t.Fatalf("key file missing %q: %s", field, data)
				}
			}
			if tc.kdf == pbs.KDFNone {
				if f["kdf"] != nil {
					t.Fatalf("plain key file has kdf %v", f["kdf"])
				}
				raw, err := base64.StdEncoding.DecodeString(f["data"].(string))
				if err != nil || len(raw) != 32 {
					t.Fatalf("plain data: %d bytes, err %v", len(raw), err)
				}
			} else {
				raw, err := base64.StdEncoding.DecodeString(f["data"].(string))
				if err != nil || len(raw) != 64 {
					t.Fatalf("protected data: %d bytes, err %v (want iv16+tag16+key32)", len(raw), err)
				}
			}
		})
	}
}

func TestKeyFileErrors(t *testing.T) {
	key, err := pbs.GenerateEncryptionKey()
	if err != nil {
		t.Fatal(err)
	}

	if _, err := pbs.CreateKeyFile(key, []byte("abc"), pbs.KDFScrypt, ""); err == nil || !strings.Contains(err.Error(), "at least 5") {
		t.Fatalf("short passphrase: %v", err)
	}
	if _, err := pbs.CreateKeyFile(key, []byte("passphrase"), pbs.KDFNone, ""); err == nil {
		t.Fatal("KDFNone with passphrase accepted")
	}
	if _, err := pbs.CreateKeyFile(key, []byte("passphrase"), pbs.KDF("bcrypt"), ""); err == nil {
		t.Fatal("unknown KDF accepted")
	}

	protected, err := pbs.CreateKeyFile(key, []byte("right horse"), pbs.KDFScrypt, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pbs.LoadKeyFile(protected, []byte("wrong horse")); err == nil {
		t.Fatal("wrong passphrase accepted")
	}
	if _, err := pbs.LoadKeyFile(protected, nil); err == nil || !strings.Contains(err.Error(), "requires a passphrase") {
		t.Fatalf("missing passphrase: %v", err)
	}

	plain, err := pbs.CreateKeyFile(key, nil, pbs.KDFNone, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pbs.LoadKeyFile(plain, []byte("anything")); err == nil || !strings.Contains(err.Error(), "not passphrase-protected") {
		t.Fatalf("passphrase for plain file: %v", err)
	}

	// A tampered fingerprint must be caught.
	var f map[string]any
	if err := json.Unmarshal(plain, &f); err != nil {
		t.Fatal(err)
	}
	fp := f["fingerprint"].(string)
	f["fingerprint"] = "00:" + fp[3:]
	tampered, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pbs.LoadKeyFile(tampered, nil); err == nil || !strings.Contains(err.Error(), "fingerprint") {
		t.Fatalf("tampered fingerprint: %v", err)
	}
}

func TestWrapKeyConfig(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})

	key := testKey(t)
	created := time.Date(2024, 3, 1, 12, 0, 0, 0, time.UTC)
	now := time.Date(2026, 8, 25, 9, 30, 0, 0, time.UTC)
	cfg := &pbs.CryptConfig{Key: key, KeyCreated: created, MasterPublicKey: pubPEM}

	wrapped, err := pbs.WrapKeyConfig(cfg, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(wrapped) != rsaKey.Size() {
		t.Fatalf("wrapped length %d, want RSA modulus size %d", len(wrapped), rsaKey.Size())
	}

	//lint:ignore SA1019 the wrap format is PKCS#1 v1.5 for proxmox compatibility
	doc, err := rsa.DecryptPKCS1v15(nil, rsaKey, wrapped)
	if err != nil {
		t.Fatalf("master-key decrypt: %v", err)
	}
	var f struct {
		KDF         any    `json:"kdf"`
		Created     string `json:"created"`
		Modified    string `json:"modified"`
		Data        string `json:"data"`
		Fingerprint string `json:"fingerprint"`
	}
	if err := json.Unmarshal(doc, &f); err != nil {
		t.Fatalf("wrapped doc is not KeyConfig JSON: %v\n%s", err, doc)
	}
	if f.KDF != nil {
		t.Fatalf("wrapped kdf %v, want null", f.KDF)
	}
	raw, err := base64.StdEncoding.DecodeString(f.Data)
	if err != nil || len(raw) != 32 {
		t.Fatalf("wrapped data: %v, %d bytes", err, len(raw))
	}
	var got [32]byte
	copy(got[:], raw)
	if got != key {
		t.Fatal("wrapped key mismatch")
	}
	if !strings.HasPrefix(f.Created, "2024-03-01T12:00:00") {
		t.Fatalf("created %q does not preserve the key's timestamp", f.Created)
	}
	wantFP, err := pbs.CryptFingerprint(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if f.Fingerprint != wantFP {
		t.Fatalf("wrapped fingerprint %q, want %q", f.Fingerprint, wantFP)
	}

	// The RSA-encrypted doc must fit: a tiny master key is refused clearly.
	tiny, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	tinyDER, err := x509.MarshalPKIXPublicKey(&tiny.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	tinyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: tinyDER})
	_, err = pbs.WrapKeyConfig(&pbs.CryptConfig{Key: key, MasterPublicKey: tinyPEM}, now)
	if err == nil || !strings.Contains(err.Error(), "master key too small") {
		t.Fatalf("tiny master key: %v", err)
	}
}
