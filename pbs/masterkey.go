package pbs

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
)

// LoadMasterKey parses an RSA master private key in PEM form: the
// passphrase-protected PKCS#8 file "proxmox-backup-client key
// create-master-key" writes (PBES2 with PBKDF2 and AES-CBC), or an
// unencrypted "PRIVATE KEY" / "RSA PRIVATE KEY" block, for which passphrase
// must be nil.
func LoadMasterKey(pemData, passphrase []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("pbs: master key is not PEM")
	}
	encrypted := block.Type == "ENCRYPTED PRIVATE KEY"
	switch {
	case encrypted && passphrase == nil:
		return nil, errors.New("pbs: master key requires a passphrase")
	case !encrypted && passphrase != nil:
		return nil, errors.New("pbs: master key is not passphrase-protected")
	}

	var key any
	var err error
	switch block.Type {
	case "ENCRYPTED PRIVATE KEY":
		der, derr := decryptPKCS8(block.Bytes, passphrase)
		if derr != nil {
			return nil, derr
		}
		if key, err = x509.ParsePKCS8PrivateKey(der); err != nil {
			return nil, errors.New("pbs: unlocking master key (wrong passphrase?)")
		}
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("pbs: unsupported master key PEM block %q", block.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("pbs: parsing master key: %w", err)
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("pbs: master key is %T, not RSA", key)
	}
	return rsaKey, nil
}

// RecoverKey decrypts a master-key-wrapped encryption key: the content of a
// snapshot's "rsa-encrypted.key.blob", as DownloadBlob returns it.
func RecoverKey(wrapped []byte, master *rsa.PrivateKey) (KeyInfo, error) {
	//lint:ignore SA1019 PKCS#1 v1.5 is what proxmox-backup wraps keys with
	doc, err := rsa.DecryptPKCS1v15(nil, master, wrapped)
	if err != nil {
		return KeyInfo{}, errors.New("pbs: decrypting the wrapped key failed (wrong master key?)")
	}
	info, err := LoadKeyFile(doc, nil)
	if err != nil {
		return KeyInfo{}, fmt.Errorf("pbs: wrapped key: %w", err)
	}
	return info, nil
}

// RecoverKey recovers the snapshot's encryption key with the master private
// key, from the wrapped copy a backup with Crypt.MasterPublicKey stores.
// The session's client needs no key, so nothing read is verified yet: open
// a new client with the recovered key (info.CryptConfig) to read the
// snapshot. Its manifest signature, which covers the wrapped key, then
// proves the recovered key belongs to the snapshot.
func (r *ReaderSession) RecoverKey(ctx context.Context, master *rsa.PrivateKey) (KeyInfo, error) {
	wrapped, err := r.DownloadBlob(ctx, "rsa-encrypted.key.blob")
	if err != nil {
		return KeyInfo{}, err
	}
	return RecoverKey(wrapped, master)
}

var (
	oidPBES2      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidHMACSHA1   = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 7}
	oidHMACSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidAESCBC     = map[string]int{
		"2.16.840.1.101.3.4.1.2":  16,
		"2.16.840.1.101.3.4.1.22": 24,
		"2.16.840.1.101.3.4.1.42": 32,
	}
)

// decryptPKCS8 opens a PKCS#8 EncryptedPrivateKeyInfo protected with PBES2
// (RFC 8018): PBKDF2 with HMAC-SHA1 or HMAC-SHA256, AES-CBC.
func decryptPKCS8(der, passphrase []byte) ([]byte, error) {
	var info struct {
		Algo pkix.AlgorithmIdentifier
		Data []byte
	}
	var params struct {
		KDF    pkix.AlgorithmIdentifier
		Scheme pkix.AlgorithmIdentifier
	}
	var kdf struct {
		Salt   []byte
		Iter   int
		KeyLen int                      `asn1:"optional"`
		PRF    pkix.AlgorithmIdentifier `asn1:"optional"`
	}
	var iv []byte
	if _, err := asn1.Unmarshal(der, &info); err != nil || !info.Algo.Algorithm.Equal(oidPBES2) {
		return nil, errors.New("pbs: master key: only PBES2-encrypted PKCS#8 is supported")
	}
	if _, err := asn1.Unmarshal(info.Algo.Parameters.FullBytes, &params); err != nil || !params.KDF.Algorithm.Equal(oidPBKDF2) {
		return nil, errors.New("pbs: master key: only PBKDF2 key derivation is supported")
	}
	if _, err := asn1.Unmarshal(params.KDF.Parameters.FullBytes, &kdf); err != nil || kdf.Iter < 1 || kdf.Iter > 10_000_000 {
		return nil, errors.New("pbs: master key: malformed PBKDF2 parameters")
	}
	keyLen, ok := oidAESCBC[params.Scheme.Algorithm.String()]
	if !ok {
		return nil, fmt.Errorf("pbs: master key: unsupported cipher %s", params.Scheme.Algorithm)
	}
	if _, err := asn1.Unmarshal(params.Scheme.Parameters.FullBytes, &iv); err != nil || len(iv) != aes.BlockSize {
		return nil, errors.New("pbs: master key: malformed cipher parameters")
	}
	var prf func() hash.Hash
	switch {
	case len(kdf.PRF.Algorithm) == 0 || kdf.PRF.Algorithm.Equal(oidHMACSHA1):
		prf = sha1.New
	case kdf.PRF.Algorithm.Equal(oidHMACSHA256):
		prf = sha256.New
	default:
		return nil, fmt.Errorf("pbs: master key: unsupported PBKDF2 PRF %s", kdf.PRF.Algorithm)
	}

	key, err := pbkdf2.Key(prf, string(passphrase), kdf.Salt, kdf.Iter, keyLen)
	if err != nil {
		return nil, fmt.Errorf("pbs: master key: %w", err)
	}
	block, _ := aes.NewCipher(key)
	if len(info.Data) == 0 || len(info.Data)%aes.BlockSize != 0 {
		return nil, errors.New("pbs: master key: malformed encrypted data")
	}
	plain := make([]byte, len(info.Data))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, info.Data)
	// PKCS#7 padding; a wrong passphrase almost always breaks it.
	pad := int(plain[len(plain)-1])
	if pad == 0 || pad > aes.BlockSize {
		return nil, errors.New("pbs: unlocking master key (wrong passphrase?)")
	}
	for _, b := range plain[len(plain)-pad:] {
		if int(b) != pad {
			return nil, errors.New("pbs: unlocking master key (wrong passphrase?)")
		}
	}
	return plain[:len(plain)-pad], nil
}
