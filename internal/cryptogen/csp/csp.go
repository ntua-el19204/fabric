/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

/*
I will use the csp.go from version 3 (although I am using version 2.5)
since it seems more pluggable
*/
package csp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/pqc/dilithium/dilithium2"
	"crypto/pqc/dilithium/dilithium3"
	"crypto/pqc/dilithium/dilithium5"
	"crypto/pqc/falcon/falcon1024"
	"crypto/pqc/falcon/falcon1024padded"
	"crypto/pqc/falcon/falcon512"
	"crypto/pqc/falcon/falcon512padded"
	"crypto/pqc/mayo/mayo2"
	"crypto/pqc/mayo/mayo3"
	"crypto/pqc/mayo/mayo5"
	"crypto/pqc/ov/oviii"
	"crypto/pqc/ov/ovip"
	"crypto/pqc/ov/ovv"
	"crypto/pqc/snova/snova2454"
	"crypto/pqc/snova/snova2455"
	"crypto/pqc/snova/snova2583"
	"crypto/pqc/snova/snova2965"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
)

// LoadPrivateKey loads a private key from a file in keystorePath.  It looks
// for a file ending in "_sk" and expects a PEM-encoded PKCS8 EC private key.
func LoadPrivateKey(keystorePath string) (crypto.PrivateKey, error) {
	var priv crypto.PrivateKey

	walkFunc := func(path string, info os.FileInfo, pathErr error) error {
		if !strings.HasSuffix(path, "_sk") {
			return nil
		}

		rawKey, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		priv, err = parsePrivateKeyPEM(rawKey)
		if err != nil {
			return errors.WithMessage(err, path)
		}

		return nil
	}

	err := filepath.Walk(keystorePath, walkFunc)
	if err != nil {
		return nil, err
	}

	return priv, err
}

func parsePrivateKeyPEM(rawKey []byte) (crypto.PrivateKey, error) {
	block, _ := pem.Decode(rawKey)
	if block == nil {
		return nil, errors.New("bytes are not PEM encoded")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.WithMessage(err, "pem bytes are not PKCS8 encoded ")
	}

	_, isEcdsa := key.(*ecdsa.PrivateKey)
	_, isEd25519 := key.(ed25519.PrivateKey)
	// Post quantum digital signatures
	// Falcon
	_, isFalcon512 := key.(*falcon512.PrivateKey)
	_, isFalcon1024 := key.(*falcon1024.PrivateKey)
	_, isFalcon512padded := key.(*falcon512padded.PrivateKey)
	_, isFalcon1024padded := key.(*falcon1024padded.PrivateKey)
	// Dilithium
	_, isDilithium2 := key.(*dilithium2.PrivateKey)
	_, isDilithium3 := key.(*dilithium3.PrivateKey)
	_, isDilithium5 := key.(*dilithium5.PrivateKey)
	// Mayo
	_, isMayo2 := key.(*mayo2.PrivateKey)
	_, isMayo3 := key.(*mayo3.PrivateKey)
	_, isMayo5 := key.(*mayo5.PrivateKey)
	// Snova
	_, isSnova2454 := key.(*snova2454.PrivateKey)
	_, isSnova2583 := key.(*snova2583.PrivateKey)
	_, isSnova2455 := key.(*snova2455.PrivateKey)
	_, isSnova2965 := key.(*snova2965.PrivateKey)
	// UOV
	_, isOvip := key.(*ovip.PrivateKey)
	_, isOviii := key.(*oviii.PrivateKey)
	_, isOvv := key.(*ovv.PrivateKey)

	if !isEcdsa && !isEd25519 &&
		!isFalcon512 && !isFalcon1024 && !isFalcon512padded && !isFalcon1024padded &&
		!isDilithium2 && !isDilithium3 && !isDilithium5 &&
		!isMayo2 && !isMayo3 && !isMayo5 &&
		!isSnova2454 && !isSnova2583 && !isSnova2455 && !isSnova2965 &&
		!isOvip && !isOviii && !isOvv {
		return nil, errors.New("pem bytes do not contain an ECDSA nor ed25519  nor a supported post quantum private key")
	}

	return key, nil
}

// GeneratePrivateKey creates an ecdsa private key using a P-256 curve or an ed25519 key
// and stores it in keystorePath.
func GeneratePrivateKey(keystorePath string, keyAlg string) (crypto.PrivateKey, error) {
	var priv crypto.PrivateKey
	var err error

	switch keyAlg {
	case "ecdsa":
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "ed25519":
		_, priv, err = ed25519.GenerateKey(rand.Reader)
	// Post quantum digital signatures
	// Falcon
	case "falcon512":
		priv, err = falcon512.GenerateKey()
	case "falcon1024":
		priv, err = falcon1024.GenerateKey()
	case "falcon512padded":
		priv, err = falcon512padded.GenerateKey()
	case "falcon1024padded":
		priv, err = falcon1024padded.GenerateKey()
	// Dilithium
	case "dilithium2":
		priv, err = dilithium2.GenerateKey()
	case "dilithium3":
		priv, err = dilithium3.GenerateKey()
	case "dilithium5":
		priv, err = dilithium5.GenerateKey()
	// Mayo
	case "mayo2":
		priv, err = mayo2.GenerateKey()
	case "mayo3":
		priv, err = mayo3.GenerateKey()
	case "mayo5":
		priv, err = mayo5.GenerateKey()
	// Snova
	case "snova2454":
		priv, err = snova2454.GenerateKey()
	case "snova2583":
		priv, err = snova2583.GenerateKey()
	case "snova2455":
		priv, err = snova2455.GenerateKey()
	case "snova2965":
		priv, err = snova2965.GenerateKey()
	// UOV
	case "ovip":
		priv, err = ovip.GenerateKey()
	case "oviii":
		priv, err = oviii.GenerateKey()
	case "ovv":
		priv, err = ovv.GenerateKey()

	default:
		err = errors.WithMessagef(err, "Unsupported key algorithm: %s", keyAlg)
	}
	if err != nil {
		return nil, errors.WithMessage(err, "failed to generate private key")
	}

	pkcs8Encoded, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to marshal private key")
	}

	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8Encoded})

	keyFile := filepath.Join(keystorePath, "priv_sk")
	err = os.WriteFile(keyFile, pemEncoded, 0o600)
	if err != nil {
		return nil, errors.WithMessagef(err, "failed to save private key to file %s", keyFile)
	}

	return priv, err
}

/*
*
ECDSA signer implements the crypto.Signer interface for ECDSA keys.  The
Sign method ensures signatures are created with Low S values since Fabric
normalizes all signatures to Low S.
See https://github.com/bitcoin/bips/blob/master/bip-0146.mediawiki#low_s
for more detail.
*/
type ECDSASigner struct {
	PrivateKey *ecdsa.PrivateKey
}

// Public returns the ecdsa.PublicKey associated with PrivateKey.
func (e *ECDSASigner) Public() crypto.PublicKey {
	return &e.PrivateKey.PublicKey
}

// Sign signs the digest and ensures that signatures use the Low S value.
func (e *ECDSASigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	r, s, err := ecdsa.Sign(rand, e.PrivateKey, digest)
	if err != nil {
		return nil, err
	}

	// ensure Low S signatures
	sig := toLowS(
		e.PrivateKey.PublicKey,
		ECDSASignature{
			R: r,
			S: s,
		},
	)

	// return marshaled signature
	return asn1.Marshal(sig)
}

/*
*
When using ECDSA, both (r,s) and (r, -s mod n) are valid signatures.  In order
to protect against signature malleability attacks, Fabric normalizes all
signatures to a canonical form where s is at most half the order of the curve.
In order to make signatures compliant with what Fabric expects, toLowS creates
signatures in this canonical form.
*/
func toLowS(key ecdsa.PublicKey, sig ECDSASignature) ECDSASignature {
	// calculate half order of the curve
	halfOrder := new(big.Int).Div(key.Curve.Params().N, big.NewInt(2))
	// check if s is greater than half order of curve
	if sig.S.Cmp(halfOrder) == 1 {
		// Set s to N - s so that s will be less than or equal to half order
		sig.S.Sub(key.Params().N, sig.S)
	}
	return sig
}

type ECDSASignature struct {
	R, S *big.Int
}

type ED25519Signer struct {
	PrivateKey ed25519.PrivateKey
}

// Public returns the ed25519.PublicKey associated with PrivateKey.
func (e *ED25519Signer) Public() crypto.PublicKey {
	return e.PrivateKey.Public()
}

// Sign signs the digest
func (e *ED25519Signer) Sign(rand io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	sig := ed25519.Sign(e.PrivateKey, msg)

	return sig, nil
}

// Post quantum digital signatures
// Falcon
// Falcon512
type FALCON512Signer struct {
	PrivateKey *falcon512.PrivateKey
}

// Public returns the falcon512.PublicKey associated with PrivateKey.
func (e *FALCON512Signer) Public() crypto.PublicKey {
	return e.PrivateKey.PublicKey
}

// Sign signs the digest.
func (e *FALCON512Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	sig, err := e.PrivateKey.Sign(rand, digest, opts)

	if err != nil {
		return nil, err
	}

	// return marshaled signature
	return sig, err
}

// Falcon1024
type FALCON1024Signer struct {
	PrivateKey *falcon1024.PrivateKey
}

// Public returns the falcon1024.PublicKey associated with PrivateKey.
func (e *FALCON1024Signer) Public() crypto.PublicKey {
	return e.PrivateKey.PublicKey
}

// Sign signs the digest.
func (e *FALCON1024Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	sig, err := e.PrivateKey.Sign(rand, digest, opts)

	if err != nil {
		return nil, err
	}

	// return marshaled signature
	return sig, err
}

// 5Falcon12padded
type FALCON512PADDEDSigner struct {
	PrivateKey *falcon512padded.PrivateKey
}

// Public returns the falcon512padded.PublicKey associated with PrivateKey.
func (e *FALCON512PADDEDSigner) Public() crypto.PublicKey {
	return e.PrivateKey.PublicKey
}

// Sign signs the digest.
func (e *FALCON512PADDEDSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	sig, err := e.PrivateKey.Sign(rand, digest, opts)

	if err != nil {
		return nil, err
	}

	// return marshaled signature
	return sig, err
}

// Falcon1024padded
type FALCON1024PADDEDSigner struct {
	PrivateKey *falcon1024padded.PrivateKey
}

// Public returns the falcon1024padded.PublicKey associated with PrivateKey.
func (e *FALCON1024PADDEDSigner) Public() crypto.PublicKey {
	return e.PrivateKey.PublicKey
}

// Sign signs the digest.
func (e *FALCON1024PADDEDSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	sig, err := e.PrivateKey.Sign(rand, digest, opts)

	if err != nil {
		return nil, err
	}

	// return marshaled signature
	return sig, err
}

// Dilithium
// Dilithium2
type DILITHIUM2Signer struct {
	PrivateKey *dilithium2.PrivateKey
}

// Public returns the dilithium2.PublicKey associated with PrivateKey.
func (e *DILITHIUM2Signer) Public() crypto.PublicKey {
	return e.PrivateKey.PublicKey
}

// Sign signs the digest.
func (e *DILITHIUM2Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	sig, err := e.PrivateKey.Sign(rand, digest, opts)

	if err != nil {
		return nil, err
	}

	// return marshaled signature
	return sig, err
}

// Dilithium3
type DILITHIUM3Signer struct {
	PrivateKey *dilithium3.PrivateKey
}

// Public returns the dilithium3.PublicKey associated with PrivateKey.
func (e *DILITHIUM3Signer) Public() crypto.PublicKey {
	return e.PrivateKey.PublicKey
}

// Sign signs the digest.
func (e *DILITHIUM3Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	sig, err := e.PrivateKey.Sign(rand, digest, opts)

	if err != nil {
		return nil, err
	}

	// return marshaled signature
	return sig, err
}

// Dilithium5
type DILITHIUM5Signer struct {
	PrivateKey *dilithium5.PrivateKey
}

// Public returns the dilithium5.PublicKey associated with PrivateKey.
func (e *DILITHIUM5Signer) Public() crypto.PublicKey {
	return e.PrivateKey.PublicKey
}

// Sign signs the digest.
func (e *DILITHIUM5Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	sig, err := e.PrivateKey.Sign(rand, digest, opts)

	if err != nil {
		return nil, err
	}

	// return marshaled signature
	return sig, err
}

// Mayo
// Mayo2
type MAYO2Signer struct {
	PrivateKey *mayo2.PrivateKey
}

// Public returns the mayo2.PublicKey associated with PrivateKey.
func (e *MAYO2Signer) Public() crypto.PublicKey {
	return e.PrivateKey.PublicKey
}

// Sign signs the digest.
func (e *MAYO2Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	sig, err := e.PrivateKey.Sign(rand, digest, opts)

	if err != nil {
		return nil, err
	}

	// return marshaled signature
	return sig, err
}

// Mayo3
type MAYO3Signer struct {
	PrivateKey *mayo3.PrivateKey
}

// Public returns the mayo3.PublicKey associated with PrivateKey.
func (e *MAYO3Signer) Public() crypto.PublicKey {
	return e.PrivateKey.PublicKey
}

// Sign signs the digest.
func (e *MAYO3Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	sig, err := e.PrivateKey.Sign(rand, digest, opts)

	if err != nil {
		return nil, err
	}

	// return marshaled signature
	return sig, err
}

// Mayo5
type MAYO5Signer struct {
	PrivateKey *mayo5.PrivateKey
}

// Public returns the mayo5.PublicKey associated with PrivateKey.
func (e *MAYO5Signer) Public() crypto.PublicKey {
	return e.PrivateKey.PublicKey
}

// Sign signs the digest.
func (e *MAYO5Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	sig, err := e.PrivateKey.Sign(rand, digest, opts)

	if err != nil {
		return nil, err
	}

	// return marshaled signature
	return sig, err
}

// Snova
// Snova2454
type SNOVA2454Signer struct {
	PrivateKey *snova2454.PrivateKey
}

// Public returns the snova2454.PublicKey associated with PrivateKey.
func (e *SNOVA2454Signer) Public() crypto.PublicKey {
	return e.PrivateKey.PublicKey
}

// Sign signs the digest.
func (e *SNOVA2454Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	sig, err := e.PrivateKey.Sign(rand, digest, opts)

	if err != nil {
		return nil, err
	}

	// return marshaled signature
	return sig, err
}

// Snova2583
type SNOVA2583Signer struct {
	PrivateKey *snova2583.PrivateKey
}

// Public returns the snova2583.PublicKey associated with PrivateKey.
func (e *SNOVA2583Signer) Public() crypto.PublicKey {
	return e.PrivateKey.PublicKey
}

// Sign signs the digest.
func (e *SNOVA2583Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	sig, err := e.PrivateKey.Sign(rand, digest, opts)

	if err != nil {
		return nil, err
	}

	// return marshaled signature
	return sig, err
}

// Snova2455
type SNOVA2455Signer struct {
	PrivateKey *snova2455.PrivateKey
}

// Public returns the snova2455.PublicKey associated with PrivateKey.
func (e *SNOVA2455Signer) Public() crypto.PublicKey {
	return e.PrivateKey.PublicKey
}

// Sign signs the digest.
func (e *SNOVA2455Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	sig, err := e.PrivateKey.Sign(rand, digest, opts)

	if err != nil {
		return nil, err
	}

	// return marshaled signature
	return sig, err
}

// Snova2965
type SNOVA2965Signer struct {
	PrivateKey *snova2965.PrivateKey
}

// Public returns the snova2965.PublicKey associated with PrivateKey.
func (e *SNOVA2965Signer) Public() crypto.PublicKey {
	return e.PrivateKey.PublicKey
}

// Sign signs the digest.
func (e *SNOVA2965Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	sig, err := e.PrivateKey.Sign(rand, digest, opts)

	if err != nil {
		return nil, err
	}

	// return marshaled signature
	return sig, err
}

// UOV
// Ovip
type OVIPSigner struct {
	PrivateKey *ovip.PrivateKey
}

// Public returns the ovip.PublicKey associated with PrivateKey.
func (e *OVIPSigner) Public() crypto.PublicKey {
	return e.PrivateKey.PublicKey
}

// Sign signs the digest.
func (e *OVIPSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	sig, err := e.PrivateKey.Sign(rand, digest, opts)

	if err != nil {
		return nil, err
	}

	// return marshaled signature
	return sig, err
}

// Oviii
type OVIIISigner struct {
	PrivateKey *oviii.PrivateKey
}

// Public returns the oviii.PublicKey associated with PrivateKey.
func (e *OVIIISigner) Public() crypto.PublicKey {
	return e.PrivateKey.PublicKey
}

// Sign signs the digest.
func (e *OVIIISigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	sig, err := e.PrivateKey.Sign(rand, digest, opts)

	if err != nil {
		return nil, err
	}

	// return marshaled signature
	return sig, err
}

// Ovv
type OVVSigner struct {
	PrivateKey *ovv.PrivateKey
}

// Public returns the ovv.PublicKey associated with PrivateKey.
func (e *OVVSigner) Public() crypto.PublicKey {
	return e.PrivateKey.PublicKey
}

// Sign signs the digest.
func (e *OVVSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	sig, err := e.PrivateKey.Sign(rand, digest, opts)

	if err != nil {
		return nil, err
	}

	// return marshaled signature
	return sig, err
}
