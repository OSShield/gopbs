package pbs

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"
)

// CryptMode selects how uploaded data relates to the encryption key.
type CryptMode string

const (
	// CryptModeEncrypt encrypts every chunk and blob with AES-256-GCM and
	// signs the manifest.
	CryptModeEncrypt CryptMode = "encrypt"
	// CryptModeSignOnly uploads plaintext but signs the manifest, proving it
	// was written by a holder of the key.
	CryptModeSignOnly CryptMode = "sign-only"
)

// CryptConfig configures client-side encryption, compatible with
// proxmox-backup-client: the same key file yields the same chunk digests, so
// deduplication works across clients. Set it on Config.Crypt; a nil
// Config.Crypt uploads plaintext with crypt-mode "none". The struct is
// treated as read-only after NewClient.
type CryptConfig struct {
	// Mode is CryptModeEncrypt or CryptModeSignOnly. Empty defaults to
	// CryptModeEncrypt, matching proxmox-backup-client's default when a key
	// is present.
	Mode CryptMode

	// Key is the raw 32-byte encryption key, e.g. from LoadKeyFile or
	// GenerateEncryptionKey. An all-zero key is rejected by NewClient.
	Key [32]byte

	// KeyCreated is the key's creation time, preserved in the master-key
	// wrapped copy uploaded with each backup. LoadKeyFile fills it from the
	// key file; zero means the wrap time is used.
	KeyCreated time.Time

	// MasterPublicKey, when set, is an RSA public key in PEM form ("PUBLIC
	// KEY" or "RSA PUBLIC KEY" block). Each backup then includes the
	// encryption key wrapped with it ("rsa-encrypted.key.blob"), so the
	// master key holder can recover the data if the encryption key is lost.
	// Requires Mode == CryptModeEncrypt.
	MasterPublicKey []byte
}

// cryptState is the validated, derived form of a CryptConfig, held by the
// Client. All fields are effectively immutable after newCryptState.
type cryptState struct {
	mode        CryptMode
	key         [32]byte
	idKey       [32]byte // keyed-digest namespace, derived from key
	fingerprint [32]byte
	aead        cipher.AEAD // AES-256-GCM with PBS's 16-byte IV
	created     time.Time
	masterKey   *rsa.PublicKey
}

// PBS derives the digest-namespace key and encrypts with a 16-byte GCM IV;
// these constants mirror proxmox-backup's CryptConfig.
const (
	idKeySalt        = "_id_key"
	idKeyIter        = 10
	cryptIVSize      = 16
	fingerprintInput = "Proxmox Backup Encryption Key Fingerprint"
)

func newCryptState(c *CryptConfig) (*cryptState, error) {
	mode := c.Mode
	if mode == "" {
		mode = CryptModeEncrypt
	}
	if mode != CryptModeEncrypt && mode != CryptModeSignOnly {
		return nil, fmt.Errorf("pbs: invalid crypt mode %q", c.Mode)
	}
	if c.Key == [32]byte{} {
		return nil, fmt.Errorf("pbs: Crypt.Key is not set")
	}

	cs := &cryptState{mode: mode, key: c.Key, created: c.KeyCreated}

	idKey, err := pbkdf2.Key(sha256.New, string(c.Key[:]), []byte(idKeySalt), idKeyIter, 32)
	if err != nil {
		return nil, fmt.Errorf("pbs: deriving id key: %w", err)
	}
	copy(cs.idKey[:], idKey)

	input := sha256.Sum256([]byte(fingerprintInput))
	cs.fingerprint = cs.computeDigest(input[:])

	block, err := aes.NewCipher(c.Key[:])
	if err != nil {
		return nil, fmt.Errorf("pbs: creating cipher: %w", err)
	}
	cs.aead, err = cipher.NewGCMWithNonceSize(block, cryptIVSize)
	if err != nil {
		return nil, fmt.Errorf("pbs: creating GCM: %w", err)
	}

	if c.MasterPublicKey != nil {
		if mode != CryptModeEncrypt {
			return nil, fmt.Errorf("pbs: Crypt.MasterPublicKey requires CryptModeEncrypt")
		}
		cs.masterKey, err = parseRSAPublicKey(c.MasterPublicKey)
		if err != nil {
			return nil, err
		}
	}
	return cs, nil
}

// computeDigest returns the keyed chunk digest, SHA256(data || id_key) — the
// id key appended after the data, matching proxmox-backup (which notes the
// order avoids length-extension attacks). Identical plaintext under the same
// key yields identical digests, so deduplication works per key.
func (cs *cryptState) computeDigest(data []byte) [32]byte {
	h := sha256.New()
	h.Write(data)
	h.Write(cs.idKey[:])
	var sum [32]byte
	h.Sum(sum[:0])
	return sum
}

// authTag returns HMAC-SHA256(id_key, data), the manifest signature primitive.
func (cs *cryptState) authTag(data []byte) [32]byte {
	h := hmac.New(sha256.New, cs.idKey[:])
	h.Write(data)
	var sum [32]byte
	h.Sum(sum[:0])
	return sum
}

// fingerprintHex is the key fingerprint as PBS displays it: colon-separated
// hex of all 32 bytes.
func (cs *cryptState) fingerprintHex() string { return formatFingerprint(cs.fingerprint) }

func parseRSAPublicKey(pemData []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("pbs: Crypt.MasterPublicKey is not PEM")
	}
	switch block.Type {
	case "PUBLIC KEY":
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("pbs: parsing master public key: %w", err)
		}
		rsaKey, ok := key.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("pbs: master public key is %T, not RSA", key)
		}
		return rsaKey, nil
	case "RSA PUBLIC KEY":
		key, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("pbs: parsing master public key: %w", err)
		}
		return key, nil
	}
	return nil, fmt.Errorf("pbs: unsupported master public key PEM block %q", block.Type)
}
