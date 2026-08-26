package pbs

import (
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"golang.org/x/crypto/scrypt"
)

// KDF selects how a key file's passphrase protects the key.
type KDF string

const (
	// KDFScrypt protects the key with scrypt (n=65536, r=8, p=1), the
	// proxmox-backup-client default.
	KDFScrypt KDF = "scrypt"
	// KDFPBKDF2 protects the key with PBKDF2-HMAC-SHA256 (65535 iterations).
	KDFPBKDF2 KDF = "pbkdf2"
	// KDFNone stores the key in plain; the file itself is the secret.
	KDFNone KDF = "none"
)

// KeyInfo is an encryption key loaded from a key file, with its metadata.
type KeyInfo struct {
	Key         [32]byte
	Created     time.Time
	Modified    time.Time
	Hint        string // passphrase hint, if the file has one
	Fingerprint string // colon-separated hex, recomputed from Key
}

// CryptConfig returns a config using this key in the given mode, preserving
// the key file's creation time for master-key wrapping.
func (k KeyInfo) CryptConfig(mode CryptMode) *CryptConfig {
	return &CryptConfig{Mode: mode, Key: k.Key, KeyCreated: k.Created}
}

// keyFileJSON mirrors proxmox-backup's KeyConfig serialization ("key.json").
type keyFileJSON struct {
	KDF         *kdfJSON `json:"kdf"`
	Created     string   `json:"created"`
	Modified    string   `json:"modified"`
	Data        string   `json:"data"`
	Fingerprint string   `json:"fingerprint,omitempty"`
	Hint        string   `json:"hint,omitempty"`
}

// kdfJSON is the externally tagged KeyDerivationConfig enum.
type kdfJSON struct {
	Scrypt *scryptParams `json:"Scrypt,omitempty"`
	PBKDF2 *pbkdf2Params `json:"PBKDF2,omitempty"`
}

type scryptParams struct {
	N    uint64 `json:"n"`
	R    uint64 `json:"r"`
	P    uint64 `json:"p"`
	Salt string `json:"salt"`
}

type pbkdf2Params struct {
	Iter int    `json:"iter"`
	Salt string `json:"salt"`
}

const (
	scryptN    = 65536
	scryptR    = 8
	scryptP    = 1
	pbkdf2Iter = 65535
	kdfSaltLen = 32
)

// GenerateEncryptionKey returns a fresh random 32-byte encryption key.
func GenerateEncryptionKey() ([32]byte, error) {
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		return key, fmt.Errorf("pbs: generating key: %w", err)
	}
	return key, nil
}

// LoadKeyFile parses a proxmox-backup key file ("key.json") and returns the
// key. passphrase unlocks scrypt/PBKDF2-protected files and must be nil for
// unprotected ones. The stored fingerprint, when present, is verified
// against the key.
func LoadKeyFile(data []byte, passphrase []byte) (KeyInfo, error) {
	var f keyFileJSON
	if err := json.Unmarshal(data, &f); err != nil {
		return KeyInfo{}, fmt.Errorf("pbs: parsing key file: %w", err)
	}
	raw, err := base64.StdEncoding.DecodeString(f.Data)
	if err != nil {
		return KeyInfo{}, fmt.Errorf("pbs: key file data is not base64: %w", err)
	}

	var info KeyInfo
	info.Hint = f.Hint
	// Timestamps are informational; tolerate formats proxmox's local-time
	// RFC3339 writer produces.
	info.Created, _ = time.Parse(time.RFC3339, f.Created)
	info.Modified, _ = time.Parse(time.RFC3339, f.Modified)

	switch {
	case f.KDF == nil:
		if passphrase != nil {
			return KeyInfo{}, fmt.Errorf("pbs: key file is not passphrase-protected")
		}
		if len(raw) != 32 {
			return KeyInfo{}, fmt.Errorf("pbs: plain key file holds %d bytes, want 32", len(raw))
		}
		copy(info.Key[:], raw)
	default:
		if passphrase == nil {
			return KeyInfo{}, fmt.Errorf("pbs: key file requires a passphrase")
		}
		derived, err := deriveKeyFileKey(f.KDF, passphrase)
		if err != nil {
			return KeyInfo{}, err
		}
		// Layout: iv(16) || tag(16) || encrypted key.
		if len(raw) < 32 {
			return KeyInfo{}, fmt.Errorf("pbs: protected key file data too short: %d bytes", len(raw))
		}
		key, err := openKeyFileData(derived, raw)
		if err != nil {
			return KeyInfo{}, fmt.Errorf("pbs: unlocking key (wrong passphrase?): %w", err)
		}
		if len(key) != 32 {
			return KeyInfo{}, fmt.Errorf("pbs: key file holds a %d-byte key, want 32", len(key))
		}
		copy(info.Key[:], key)
	}

	cs, err := newCryptState(&CryptConfig{Key: info.Key})
	if err != nil {
		return KeyInfo{}, err
	}
	info.Fingerprint = cs.fingerprintHex()
	if f.Fingerprint != "" {
		stored, err := parseFingerprint(f.Fingerprint)
		if err != nil {
			return KeyInfo{}, fmt.Errorf("pbs: key file fingerprint: %w", err)
		}
		if stored != cs.fingerprint {
			return KeyInfo{}, fmt.Errorf("pbs: key file fingerprint does not match the key")
		}
	}
	return info, nil
}

// CreateKeyFile serializes key as a proxmox-compatible key file. With
// KDFScrypt or KDFPBKDF2 the key is sealed under the passphrase (at least 5
// bytes, matching proxmox-backup); with KDFNone the passphrase must be nil
// and the key is stored in plain — write the file with mode 0600.
func CreateKeyFile(key [32]byte, passphrase []byte, kdf KDF, hint string) ([]byte, error) {
	cs, err := newCryptState(&CryptConfig{Key: key})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	f := keyFileJSON{
		Created:     now,
		Modified:    now,
		Fingerprint: cs.fingerprintHex(),
		Hint:        hint,
	}

	switch kdf {
	case KDFNone:
		if passphrase != nil {
			return nil, fmt.Errorf("pbs: KDFNone stores the key in plain; a passphrase would not protect it")
		}
		f.Data = base64.StdEncoding.EncodeToString(key[:])
	case KDFScrypt, KDFPBKDF2:
		if len(passphrase) < 5 {
			return nil, fmt.Errorf("pbs: passphrase must be at least 5 bytes")
		}
		salt := make([]byte, kdfSaltLen)
		if _, err := rand.Read(salt); err != nil {
			return nil, fmt.Errorf("pbs: generating salt: %w", err)
		}
		saltB64 := base64.StdEncoding.EncodeToString(salt)
		if kdf == KDFScrypt {
			f.KDF = &kdfJSON{Scrypt: &scryptParams{N: scryptN, R: scryptR, P: scryptP, Salt: saltB64}}
		} else {
			f.KDF = &kdfJSON{PBKDF2: &pbkdf2Params{Iter: pbkdf2Iter, Salt: saltB64}}
		}
		derived, err := deriveKeyFileKey(f.KDF, passphrase)
		if err != nil {
			return nil, err
		}
		sealed, err := sealKeyFileData(derived, key[:])
		if err != nil {
			return nil, err
		}
		f.Data = base64.StdEncoding.EncodeToString(sealed)
	default:
		return nil, fmt.Errorf("pbs: unknown KDF %q", kdf)
	}
	return json.MarshalIndent(f, "", "  ")
}

func deriveKeyFileKey(k *kdfJSON, passphrase []byte) ([32]byte, error) {
	var derived [32]byte
	switch {
	case k.Scrypt != nil:
		salt, err := base64.StdEncoding.DecodeString(k.Scrypt.Salt)
		if err != nil {
			return derived, fmt.Errorf("pbs: key file salt: %w", err)
		}
		raw, err := scrypt.Key(passphrase, salt, int(k.Scrypt.N), int(k.Scrypt.R), int(k.Scrypt.P), 32)
		if err != nil {
			return derived, fmt.Errorf("pbs: scrypt: %w", err)
		}
		copy(derived[:], raw)
	case k.PBKDF2 != nil:
		salt, err := base64.StdEncoding.DecodeString(k.PBKDF2.Salt)
		if err != nil {
			return derived, fmt.Errorf("pbs: key file salt: %w", err)
		}
		raw, err := pbkdf2.Key(sha256.New, string(passphrase), salt, k.PBKDF2.Iter, 32)
		if err != nil {
			return derived, fmt.Errorf("pbs: pbkdf2: %w", err)
		}
		copy(derived[:], raw)
	default:
		return derived, fmt.Errorf("pbs: key file has an unknown KDF")
	}
	return derived, nil
}

// openKeyFileData opens the iv(16)||tag(16)||ciphertext layout proxmox uses
// for the protected key material.
func openKeyFileData(derived [32]byte, raw []byte) ([]byte, error) {
	aead, err := newKeyFileAEAD(derived)
	if err != nil {
		return nil, err
	}
	iv, tag, ct := raw[:16], raw[16:32], raw[32:]
	sealed := make([]byte, 0, len(ct)+len(tag))
	sealed = append(append(sealed, ct...), tag...)
	return aead.Open(nil, iv, sealed, nil)
}

func sealKeyFileData(derived [32]byte, plain []byte) ([]byte, error) {
	aead, err := newKeyFileAEAD(derived)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 32, 32+len(plain)+16)
	if _, err := rand.Read(out[:16]); err != nil {
		return nil, fmt.Errorf("pbs: generating IV: %w", err)
	}
	sealed := aead.Seal(out[32:32], out[:16], plain, nil)
	copy(out[16:32], sealed[len(plain):]) // move the trailing tag into place
	return out[:32+len(plain)], nil
}

func newKeyFileAEAD(derived [32]byte) (cipher.AEAD, error) {
	cs, err := newCryptState(&CryptConfig{Key: derived})
	if err != nil {
		return nil, err
	}
	return cs.aead, nil
}

// wrapKeyConfig serializes the session key as an unprotected KeyConfig JSON
// (preserving the key's creation time) and encrypts the whole document with
// the RSA master key, PKCS#1 v1.5 — the "rsa-encrypted.key.blob" payload
// proxmox-backup-client produces.
func wrapKeyConfig(cs *cryptState, now time.Time) ([]byte, error) {
	created := cs.created
	if created.IsZero() {
		created = now
	}
	doc, err := json.Marshal(keyFileJSON{
		Created:     created.UTC().Format(time.RFC3339),
		Modified:    now.UTC().Format(time.RFC3339),
		Data:        base64.StdEncoding.EncodeToString(cs.key[:]),
		Fingerprint: cs.fingerprintHex(),
	})
	if err != nil {
		return nil, fmt.Errorf("pbs: encoding key config: %w", err)
	}
	if max := cs.masterKey.Size() - 11; len(doc) > max {
		return nil, fmt.Errorf("pbs: master key too small: %d-byte key config exceeds the %d-byte PKCS#1v1.5 limit", len(doc), max)
	}
	// PKCS#1 v1.5 is deprecated, but it is the padding proxmox-backup uses
	// (openssl Padding::PKCS1) — anything else would produce a key blob the
	// official tooling cannot decrypt.
	//lint:ignore SA1019 required for proxmox-backup compatibility
	wrapped, err := rsa.EncryptPKCS1v15(rand.Reader, cs.masterKey, doc)
	if err != nil {
		return nil, fmt.Errorf("pbs: wrapping key with master key: %w", err)
	}
	return wrapped, nil
}
