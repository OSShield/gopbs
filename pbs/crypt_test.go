package pbs_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/scrypt"

	"github.com/osshield/gopbs/pbs"
)

// testKey derives the key used by proxmox-backup's own manifest-signature
// test: scrypt(n=65536, r=8, p=1, empty salt) of "test".
func testKey(t *testing.T) [32]byte {
	t.Helper()
	raw, err := scrypt.Key([]byte("test"), nil, 65536, 8, 1, 32)
	if err != nil {
		t.Fatalf("scrypt: %v", err)
	}
	var key [32]byte
	copy(key[:], raw)
	return key
}

// TestManifestSignatureConformance reproduces proxmox-backup's
// test_manifest_signature vector, pinning the whole chain: key -> id_key
// (PBKDF2) -> canonical JSON -> HMAC.
func TestManifestSignatureConformance(t *testing.T) {
	ts, err := time.Parse(time.RFC3339, "2020-06-26T13:56:05Z")
	if err != nil {
		t.Fatal(err)
	}
	m := pbs.BackupManifest{
		BackupID:   "elsa",
		BackupTime: ts.Unix(),
		BackupType: "host",
		Files: []pbs.ManifestFile{
			{CryptMode: "encrypt", Csum: hex.EncodeToString(bytes.Repeat([]byte{1}, 32)), Filename: "test1.img.fidx", Size: 200},
			{CryptMode: "none", Csum: hex.EncodeToString(bytes.Repeat([]byte{2}, 32)), Filename: "abc.blob", Size: 200},
		},
		// Stripped before signing; present to prove that.
		Unprotected: map[string]any{"note": "This is not protected by the signature."},
	}

	canon, err := pbs.CanonicalManifestJSON(m)
	if err != nil {
		t.Fatalf("canonical JSON: %v", err)
	}
	if bytes.Contains(canon, []byte("signature")) || bytes.Contains(canon, []byte("unprotected")) {
		t.Fatalf("canonical form retains excluded members: %s", canon)
	}

	sig, err := pbs.CryptSignature(&pbs.CryptConfig{Key: testKey(t)}, canon)
	if err != nil {
		t.Fatalf("signature: %v", err)
	}
	const want = "d7b446fb7db081662081d4b40fedd858a1d6307a5aff4ecff7d5bf4fd35679e9"
	if got := hex.EncodeToString(sig[:]); got != want {
		t.Fatalf("signature mismatch:\ngot  %s\nwant %s\ncanonical: %s", got, want, canon)
	}
}

func TestKeyedDigest(t *testing.T) {
	key := testKey(t)
	data := []byte("some chunk payload")

	got, err := pbs.CryptDigest(&pbs.CryptConfig{Key: key}, data)
	if err != nil {
		t.Fatal(err)
	}
	if got == sha256.Sum256(data) {
		t.Fatal("keyed digest equals plain SHA-256")
	}

	// The digest namespace must differ between keys.
	other := key
	other[0] ^= 1
	got2, err := pbs.CryptDigest(&pbs.CryptConfig{Key: other}, data)
	if err != nil {
		t.Fatal(err)
	}
	if got == got2 {
		t.Fatal("digests collide across keys")
	}
}

func TestCryptFingerprintFormat(t *testing.T) {
	fp, err := pbs.CryptFingerprint(&pbs.CryptConfig{Key: testKey(t)})
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(fp, ":")
	if len(parts) != 32 {
		t.Fatalf("fingerprint %q: want 32 colon-separated bytes, got %d", fp, len(parts))
	}
	for _, p := range parts {
		if len(p) != 2 {
			t.Fatalf("fingerprint %q: element %q is not a hex byte", fp, p)
		}
		if _, err := hex.DecodeString(p); err != nil {
			t.Fatalf("fingerprint %q: element %q is not hex", fp, p)
		}
	}
}

func TestCryptConfigValidation(t *testing.T) {
	key := testKey(t)
	cases := []struct {
		name string
		cfg  pbs.CryptConfig
		want string
	}{
		{"zero key", pbs.CryptConfig{}, "Key is not set"},
		{"bad mode", pbs.CryptConfig{Mode: "sign", Key: key}, "invalid crypt mode"},
		{"master key without encrypt", pbs.CryptConfig{Mode: pbs.CryptModeSignOnly, Key: key, MasterPublicKey: []byte("x")}, "requires CryptModeEncrypt"},
		{"master key bad PEM", pbs.CryptConfig{Key: key, MasterPublicKey: []byte("not pem")}, "not PEM"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := pbs.CryptDigest(&tc.cfg, nil)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got error %v, want it to contain %q", err, tc.want)
			}
		})
	}

	// Empty mode defaults to encrypt: sign-only and empty must produce the
	// same primitives, and both must be accepted.
	d1, err := pbs.CryptDigest(&pbs.CryptConfig{Key: key}, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	d2, err := pbs.CryptDigest(&pbs.CryptConfig{Mode: pbs.CryptModeEncrypt, Key: key}, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	if d1 != d2 {
		t.Fatal("empty mode does not default to encrypt")
	}
}
