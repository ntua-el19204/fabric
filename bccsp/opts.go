/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bccsp

const (
	// ECDSA Elliptic Curve Digital Signature Algorithm (key gen, import, sign, verify),
	// at default security level.
	// Each BCCSP may or may not support default security level. If not supported than
	// an error will be returned.
	ECDSA = "ECDSA"

	// ECDSAP256 Elliptic Curve Digital Signature Algorithm over P-256 curve
	ECDSAP256 = "ECDSAP256"

	// ECDSAP384 Elliptic Curve Digital Signature Algorithm over P-384 curve
	ECDSAP384 = "ECDSAP384"

	// ECDSAReRand ECDSA key re-randomization
	ECDSAReRand = "ECDSA_RERAND"

	// AES Advanced Encryption Standard at the default security level.
	// Each BCCSP may or may not support default security level. If not supported than
	// an error will be returned.
	AES = "AES"
	// AES128 Advanced Encryption Standard at 128 bit security level
	AES128 = "AES128"
	// AES192 Advanced Encryption Standard at 192 bit security level
	AES192 = "AES192"
	// AES256 Advanced Encryption Standard at 256 bit security level
	AES256 = "AES256"

	// HMAC keyed-hash message authentication code
	HMAC = "HMAC"
	// HMACTruncated256 HMAC truncated at 256 bits.
	HMACTruncated256 = "HMAC_TRUNCATED_256"

	// SHA Secure Hash Algorithm using default family.
	// Each BCCSP may or may not support default security level. If not supported than
	// an error will be returned.
	SHA = "SHA"

	// SHA2 is an identifier for SHA2 hash family
	SHA2 = "SHA2"
	// SHA3 is an identifier for SHA3 hash family
	SHA3 = "SHA3"

	// SHA256
	SHA256 = "SHA256"
	// SHA384
	SHA384 = "SHA384"
	// SHA3_256
	SHA3_256 = "SHA3_256"
	// SHA3_384
	SHA3_384 = "SHA3_384"

	// X509Certificate Label for X509 certificate related operation
	X509Certificate = "X509Certificate"

	// Post quantum digital signatures
	// Falcon
	FALCON512        = "falcon512"
	FALCON1024       = "falcon1024"
	FALCON512PADDED  = "falcon512padded"
	FALCON1024PADDED = "falcon1024padded"

	// Dilihtium
	DILITHIUM2 = "dilithium2"
	DILITHIUM3 = "dilithium3"
	DILITHIUM5 = "dilithium5"

	// Mayo
	MAYO2 = "mayo2"
	MAYO3 = "mayo3"
	MAYO5 = "mayo5"

	// Snova
	SNOVA2454 = "snova2454"
	SNOVA2583 = "snova2583"
	SNOVA2455 = "snova2455"
	SNOVA2965 = "snova2965"

	// UOV
	OVIP  = "ovip"
	OVIII = "oviii"
	OVV   = "ovv"
)

// ECDSAKeyGenOpts contains options for ECDSA key generation.
type ECDSAKeyGenOpts struct {
	Temporary bool
}

// Algorithm returns the key generation algorithm identifier (to be used).
func (opts *ECDSAKeyGenOpts) Algorithm() string {
	return ECDSA
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *ECDSAKeyGenOpts) Ephemeral() bool {
	return opts.Temporary
}

// ECDSAPKIXPublicKeyImportOpts contains options for ECDSA public key importation in PKIX format
type ECDSAPKIXPublicKeyImportOpts struct {
	Temporary bool
}

// Algorithm returns the key importation algorithm identifier (to be used).
func (opts *ECDSAPKIXPublicKeyImportOpts) Algorithm() string {
	return ECDSA
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *ECDSAPKIXPublicKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

// ECDSAPrivateKeyImportOpts contains options for ECDSA secret key importation in DER format
// or PKCS#8 format.
type ECDSAPrivateKeyImportOpts struct {
	Temporary bool
}

// Algorithm returns the key importation algorithm identifier (to be used).
func (opts *ECDSAPrivateKeyImportOpts) Algorithm() string {
	return ECDSA
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *ECDSAPrivateKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

// ECDSAGoPublicKeyImportOpts contains options for ECDSA key importation from ecdsa.PublicKey
type ECDSAGoPublicKeyImportOpts struct {
	Temporary bool
}

// Algorithm returns the key importation algorithm identifier (to be used).
func (opts *ECDSAGoPublicKeyImportOpts) Algorithm() string {
	return ECDSA
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *ECDSAGoPublicKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

// ECDSAReRandKeyOpts contains options for ECDSA key re-randomization.
type ECDSAReRandKeyOpts struct {
	Temporary bool
	Expansion []byte
}

// Algorithm returns the key derivation algorithm identifier (to be used).
func (opts *ECDSAReRandKeyOpts) Algorithm() string {
	return ECDSAReRand
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *ECDSAReRandKeyOpts) Ephemeral() bool {
	return opts.Temporary
}

// ExpansionValue returns the re-randomization factor
func (opts *ECDSAReRandKeyOpts) ExpansionValue() []byte {
	return opts.Expansion
}

// AESKeyGenOpts contains options for AES key generation at default security level
type AESKeyGenOpts struct {
	Temporary bool
}

// Algorithm returns the key generation algorithm identifier (to be used).
func (opts *AESKeyGenOpts) Algorithm() string {
	return AES
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *AESKeyGenOpts) Ephemeral() bool {
	return opts.Temporary
}

// HMACTruncated256AESDeriveKeyOpts contains options for HMAC truncated
// at 256 bits key derivation.
type HMACTruncated256AESDeriveKeyOpts struct {
	Temporary bool
	Arg       []byte
}

// Algorithm returns the key derivation algorithm identifier (to be used).
func (opts *HMACTruncated256AESDeriveKeyOpts) Algorithm() string {
	return HMACTruncated256
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *HMACTruncated256AESDeriveKeyOpts) Ephemeral() bool {
	return opts.Temporary
}

// Argument returns the argument to be passed to the HMAC
func (opts *HMACTruncated256AESDeriveKeyOpts) Argument() []byte {
	return opts.Arg
}

// HMACDeriveKeyOpts contains options for HMAC key derivation.
type HMACDeriveKeyOpts struct {
	Temporary bool
	Arg       []byte
}

// Algorithm returns the key derivation algorithm identifier (to be used).
func (opts *HMACDeriveKeyOpts) Algorithm() string {
	return HMAC
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *HMACDeriveKeyOpts) Ephemeral() bool {
	return opts.Temporary
}

// Argument returns the argument to be passed to the HMAC
func (opts *HMACDeriveKeyOpts) Argument() []byte {
	return opts.Arg
}

// AES256ImportKeyOpts contains options for importing AES 256 keys.
type AES256ImportKeyOpts struct {
	Temporary bool
}

// Algorithm returns the key importation algorithm identifier (to be used).
func (opts *AES256ImportKeyOpts) Algorithm() string {
	return AES
}

// Ephemeral returns true if the key generated has to be ephemeral,
// false otherwise.
func (opts *AES256ImportKeyOpts) Ephemeral() bool {
	return opts.Temporary
}

// HMACImportKeyOpts contains options for importing HMAC keys.
type HMACImportKeyOpts struct {
	Temporary bool
}

// Algorithm returns the key importation algorithm identifier (to be used).
func (opts *HMACImportKeyOpts) Algorithm() string {
	return HMAC
}

// Ephemeral returns true if the key generated has to be ephemeral,
// false otherwise.
func (opts *HMACImportKeyOpts) Ephemeral() bool {
	return opts.Temporary
}

// SHAOpts contains options for computing SHA.
type SHAOpts struct{}

// Algorithm returns the hash algorithm identifier (to be used).
func (opts *SHAOpts) Algorithm() string {
	return SHA
}

// X509PublicKeyImportOpts contains options for importing public keys from an x509 certificate
type X509PublicKeyImportOpts struct {
	Temporary bool
}

// Algorithm returns the key importation algorithm identifier (to be used).
func (opts *X509PublicKeyImportOpts) Algorithm() string {
	return X509Certificate
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *X509PublicKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

//----------------------------
/*
Post Quantum Signatures
*/
//----------------------------

/*
Falcon
*/

// ---------------------------
// Falcon512
// FALCON512KeyGenOpts contains options for FALCON512 key generation.
type FALCON512KeyGenOpts struct {
	Temporary bool
}

// Algorithm returns the key generation algorithm identifier (to be used).
func (opts *FALCON512KeyGenOpts) Algorithm() string {
	return FALCON512
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *FALCON512KeyGenOpts) Ephemeral() bool {
	return opts.Temporary
}

type FALCON512GoPublicKeyImportOpts struct {
	Temporary bool
}

// Algorithm returns the key generation algorithm identifier (to be used).
func (opts *FALCON512GoPublicKeyImportOpts) Algorithm() string {
	return FALCON512
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *FALCON512GoPublicKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

type FALCON512PrivateKeyImportOpts struct {
	Temporary bool
}

// Algorithm returns the key importation algorithm identifier (to be used).
func (opts *FALCON512PrivateKeyImportOpts) Algorithm() string {
	return FALCON512
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *FALCON512PrivateKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

// ---------------------------
// Falcon1024
// FALCON1024KeyGenOpts contains options for FALCON1024 key generation.
type FALCON1024KeyGenOpts struct {
	Temporary bool
}

// Algorithm returns the key generation algorithm identifier (to be used).
func (opts *FALCON1024KeyGenOpts) Algorithm() string {
	return FALCON1024
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *FALCON1024KeyGenOpts) Ephemeral() bool {
	return opts.Temporary
}

type FALCON1024GoPublicKeyImportOpts struct {
	Temporary bool
}

// Algorithm returns the key generation algorithm identifier (to be used).
func (opts *FALCON1024GoPublicKeyImportOpts) Algorithm() string {
	return FALCON1024
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *FALCON1024GoPublicKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

type FALCON1024PrivateKeyImportOpts struct {
	Temporary bool
}

// Algorithm returns the key importation algorithm identifier (to be used).
func (opts *FALCON1024PrivateKeyImportOpts) Algorithm() string {
	return FALCON1024
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *FALCON1024PrivateKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

// ---------------------------
// Falcon512padded
// FALCON512PADDEDKeyGenOpts contains options for FALCON512PADDED key generation.
type FALCON512PADDEDKeyGenOpts struct {
	Temporary bool
}

// Algorithm returns the key generation algorithm identifier (to be used).
func (opts *FALCON512PADDEDKeyGenOpts) Algorithm() string {
	return FALCON512PADDED
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *FALCON512PADDEDKeyGenOpts) Ephemeral() bool {
	return opts.Temporary
}

type FALCON512PADDEDGoPublicKeyImportOpts struct {
	Temporary bool
}

// Algorithm returns the key generation algorithm identifier (to be used).
func (opts *FALCON512PADDEDGoPublicKeyImportOpts) Algorithm() string {
	return FALCON512PADDED
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *FALCON512PADDEDGoPublicKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

type FALCON512PADDEDPrivateKeyImportOpts struct {
	Temporary bool
}

// Algorithm returns the key importation algorithm identifier (to be used).
func (opts *FALCON512PADDEDPrivateKeyImportOpts) Algorithm() string {
	return FALCON512PADDED
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *FALCON512PADDEDPrivateKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

// ---------------------------
// Falcon1024padded
// FALCON1024PADDEDKeyGenOpts contains options for FALCON1024PADDED key generation.
type FALCON1024PADDEDKeyGenOpts struct {
	Temporary bool
}

// Algorithm returns the key generation algorithm identifier (to be used).
func (opts *FALCON1024PADDEDKeyGenOpts) Algorithm() string {
	return FALCON1024PADDED
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *FALCON1024PADDEDKeyGenOpts) Ephemeral() bool {
	return opts.Temporary
}

type FALCON1024PADDEDGoPublicKeyImportOpts struct {
	Temporary bool
}

// Algorithm returns the key generation algorithm identifier (to be used).
func (opts *FALCON1024PADDEDGoPublicKeyImportOpts) Algorithm() string {
	return FALCON1024PADDED
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *FALCON1024PADDEDGoPublicKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

type FALCON1024PADDEDPrivateKeyImportOpts struct {
	Temporary bool
}

// Algorithm returns the key importation algorithm identifier (to be used).
func (opts *FALCON1024PADDEDPrivateKeyImportOpts) Algorithm() string {
	return FALCON1024PADDED
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *FALCON1024PADDEDPrivateKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

/*
Dilithium
*/

// ---------------------------
// Dilithium2
// DILITHIUM2KeyGenOpts contains options for DILITHIUM2 key generation.
type DILITHIUM2KeyGenOpts struct {
	Temporary bool
}

// Algorithm returns the key generation algorithm identifier (to be used).
func (opts *DILITHIUM2KeyGenOpts) Algorithm() string {
	return DILITHIUM2
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *DILITHIUM2KeyGenOpts) Ephemeral() bool {
	return opts.Temporary
}

type DILITHIUM2GoPublicKeyImportOpts struct {
	Temporary bool
}

// Algorithm returns the key generation algorithm identifier (to be used).
func (opts *DILITHIUM2GoPublicKeyImportOpts) Algorithm() string {
	return DILITHIUM2
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *DILITHIUM2GoPublicKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

type DILITHIUM2PrivateKeyImportOpts struct {
	Temporary bool
}

// Algorithm returns the key importation algorithm identifier (to be used).
func (opts *DILITHIUM2PrivateKeyImportOpts) Algorithm() string {
	return DILITHIUM2
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *DILITHIUM2PrivateKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

// ---------------------------
// Dilithium3
// DILITHIUM3KeyGenOpts contains options for DILITHIUM3 key generation.
type DILITHIUM3KeyGenOpts struct {
	Temporary bool
}

// Algorithm returns the key generation algorithm identifier (to be used).
func (opts *DILITHIUM3KeyGenOpts) Algorithm() string {
	return DILITHIUM3
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *DILITHIUM3KeyGenOpts) Ephemeral() bool {
	return opts.Temporary
}

type DILITHIUM3GoPublicKeyImportOpts struct {
	Temporary bool
}

// Algorithm returns the key generation algorithm identifier (to be used).
func (opts *DILITHIUM3GoPublicKeyImportOpts) Algorithm() string {
	return DILITHIUM3
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *DILITHIUM3GoPublicKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

type DILITHIUM3PrivateKeyImportOpts struct {
	Temporary bool
}

// Algorithm returns the key importation algorithm identifier (to be used).
func (opts *DILITHIUM3PrivateKeyImportOpts) Algorithm() string {
	return DILITHIUM3
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *DILITHIUM3PrivateKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

// ---------------------------
// Dilithium5
// DILITHIUM5KeyGenOpts contains options for DILITHIUM5 key generation.
type DILITHIUM5KeyGenOpts struct {
	Temporary bool
}

// Algorithm returns the key generation algorithm identifier (to be used).
func (opts *DILITHIUM5KeyGenOpts) Algorithm() string {
	return DILITHIUM5
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *DILITHIUM5KeyGenOpts) Ephemeral() bool {
	return opts.Temporary
}

type DILITHIUM5GoPublicKeyImportOpts struct {
	Temporary bool
}

// Algorithm returns the key generation algorithm identifier (to be used).
func (opts *DILITHIUM5GoPublicKeyImportOpts) Algorithm() string {
	return DILITHIUM5
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *DILITHIUM5GoPublicKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

type DILITHIUM5PrivateKeyImportOpts struct {
	Temporary bool
}

// Algorithm returns the key importation algorithm identifier (to be used).
func (opts *DILITHIUM5PrivateKeyImportOpts) Algorithm() string {
	return DILITHIUM5
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *DILITHIUM5PrivateKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

/*
Mayo
*/

// ---------------------------
// Mayo2
// MAYO2KeyGenOpts contains options for MAYO2 key generation.
type MAYO2KeyGenOpts struct {
	Temporary bool
}

// Algorithm returns the key generation algorithm identifier (to be used).
func (opts *MAYO2KeyGenOpts) Algorithm() string {
	return MAYO2
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *MAYO2KeyGenOpts) Ephemeral() bool {
	return opts.Temporary
}

type MAYO2GoPublicKeyImportOpts struct {
	Temporary bool
}

// Algorithm returns the key generation algorithm identifier (to be used).
func (opts *MAYO2GoPublicKeyImportOpts) Algorithm() string {
	return MAYO2
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *MAYO2GoPublicKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

type MAYO2PrivateKeyImportOpts struct {
	Temporary bool
}

// Algorithm returns the key importation algorithm identifier (to be used).
func (opts *MAYO2PrivateKeyImportOpts) Algorithm() string {
	return MAYO2
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *MAYO2PrivateKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

// ---------------------------
// Mayo3
// MAYO3KeyGenOpts contains options for MAYO3 key generation.
type MAYO3KeyGenOpts struct {
	Temporary bool
}

// Algorithm returns the key generation algorithm identifier (to be used).
func (opts *MAYO3KeyGenOpts) Algorithm() string {
	return MAYO3
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *MAYO3KeyGenOpts) Ephemeral() bool {
	return opts.Temporary
}

type MAYO3GoPublicKeyImportOpts struct {
	Temporary bool
}

// Algorithm returns the key generation algorithm identifier (to be used).
func (opts *MAYO3GoPublicKeyImportOpts) Algorithm() string {
	return MAYO3
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *MAYO3GoPublicKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

type MAYO3PrivateKeyImportOpts struct {
	Temporary bool
}

// Algorithm returns the key importation algorithm identifier (to be used).
func (opts *MAYO3PrivateKeyImportOpts) Algorithm() string {
	return MAYO3
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *MAYO3PrivateKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

// ---------------------------
// Mayo5
// MAYO5KeyGenOpts contains options for MAYO5 key generation.
type MAYO5KeyGenOpts struct {
	Temporary bool
}

// Algorithm returns the key generation algorithm identifier (to be used).
func (opts *MAYO5KeyGenOpts) Algorithm() string {
	return MAYO5
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *MAYO5KeyGenOpts) Ephemeral() bool {
	return opts.Temporary
}

type MAYO5GoPublicKeyImportOpts struct {
	Temporary bool
}

// Algorithm returns the key generation algorithm identifier (to be used).
func (opts *MAYO5GoPublicKeyImportOpts) Algorithm() string {
	return MAYO5
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *MAYO5GoPublicKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

type MAYO5PrivateKeyImportOpts struct {
	Temporary bool
}

// Algorithm returns the key importation algorithm identifier (to be used).
func (opts *MAYO5PrivateKeyImportOpts) Algorithm() string {
	return MAYO5
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *MAYO5PrivateKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

/*
Snova
*/

// ---------------------------
// Snova2454
// SNOVA2454KeyGenOpts contains options for SNOVA2454 key generation.
type SNOVA2454KeyGenOpts struct {
	Temporary bool
}

// Algorithm returns the key generation algorithm identifier (to be used).
func (opts *SNOVA2454KeyGenOpts) Algorithm() string {
	return SNOVA2454
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *SNOVA2454KeyGenOpts) Ephemeral() bool {
	return opts.Temporary
}

type SNOVA2454GoPublicKeyImportOpts struct {
	Temporary bool
}

// Algorithm returns the key generation algorithm identifier (to be used).
func (opts *SNOVA2454GoPublicKeyImportOpts) Algorithm() string {
	return SNOVA2454
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *SNOVA2454GoPublicKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

type SNOVA2454PrivateKeyImportOpts struct {
	Temporary bool
}

// Algorithm returns the key importation algorithm identifier (to be used).
func (opts *SNOVA2454PrivateKeyImportOpts) Algorithm() string {
	return SNOVA2454
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *SNOVA2454PrivateKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

// ---------------------------
// Snova2583
// SNOVA2583KeyGenOpts contains options for SNOVA2583 key generation.
type SNOVA2583KeyGenOpts struct {
	Temporary bool
}

// Algorithm returns the key generation algorithm identifier (to be used).
func (opts *SNOVA2583KeyGenOpts) Algorithm() string {
	return SNOVA2583
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *SNOVA2583KeyGenOpts) Ephemeral() bool {
	return opts.Temporary
}

type SNOVA2583GoPublicKeyImportOpts struct {
	Temporary bool
}

// Algorithm returns the key generation algorithm identifier (to be used).
func (opts *SNOVA2583GoPublicKeyImportOpts) Algorithm() string {
	return SNOVA2583
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *SNOVA2583GoPublicKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

type SNOVA2583PrivateKeyImportOpts struct {
	Temporary bool
}

// Algorithm returns the key importation algorithm identifier (to be used).
func (opts *SNOVA2583PrivateKeyImportOpts) Algorithm() string {
	return SNOVA2583
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *SNOVA2583PrivateKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

// ---------------------------
// Snova2455
// SNOVA2455KeyGenOpts contains options for SNOVA2455 key generation.
type SNOVA2455KeyGenOpts struct {
	Temporary bool
}

// Algorithm returns the key generation algorithm identifier (to be used).
func (opts *SNOVA2455KeyGenOpts) Algorithm() string {
	return SNOVA2455
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *SNOVA2455KeyGenOpts) Ephemeral() bool {
	return opts.Temporary
}

type SNOVA2455GoPublicKeyImportOpts struct {
	Temporary bool
}

// Algorithm returns the key generation algorithm identifier (to be used).
func (opts *SNOVA2455GoPublicKeyImportOpts) Algorithm() string {
	return SNOVA2455
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *SNOVA2455GoPublicKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

type SNOVA2455PrivateKeyImportOpts struct {
	Temporary bool
}

// Algorithm returns the key importation algorithm identifier (to be used).
func (opts *SNOVA2455PrivateKeyImportOpts) Algorithm() string {
	return SNOVA2455
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *SNOVA2455PrivateKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

// ---------------------------
// Snova2965
// SNOVA2965KeyGenOpts contains options for SNOVA2965 key generation.
type SNOVA2965KeyGenOpts struct {
	Temporary bool
}

// Algorithm returns the key generation algorithm identifier (to be used).
func (opts *SNOVA2965KeyGenOpts) Algorithm() string {
	return SNOVA2965
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *SNOVA2965KeyGenOpts) Ephemeral() bool {
	return opts.Temporary
}

type SNOVA2965GoPublicKeyImportOpts struct {
	Temporary bool
}

// Algorithm returns the key generation algorithm identifier (to be used).
func (opts *SNOVA2965GoPublicKeyImportOpts) Algorithm() string {
	return SNOVA2965
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *SNOVA2965GoPublicKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

type SNOVA2965PrivateKeyImportOpts struct {
	Temporary bool
}

// Algorithm returns the key importation algorithm identifier (to be used).
func (opts *SNOVA2965PrivateKeyImportOpts) Algorithm() string {
	return SNOVA2965
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *SNOVA2965PrivateKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

/*
UOV
*/

// ---------------------------
// OVIP
// OVIPKeyGenOpts contains options for OVIP key generation.
type OVIPKeyGenOpts struct {
	Temporary bool
}

// Algorithm returns the key generation algorithm identifier (to be used).
func (opts *OVIPKeyGenOpts) Algorithm() string {
	return OVIP
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *OVIPKeyGenOpts) Ephemeral() bool {
	return opts.Temporary
}

type OVIPGoPublicKeyImportOpts struct {
	Temporary bool
}

// Algorithm returns the key generation algorithm identifier (to be used).
func (opts *OVIPGoPublicKeyImportOpts) Algorithm() string {
	return OVIP
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *OVIPGoPublicKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

type OVIPPrivateKeyImportOpts struct {
	Temporary bool
}

// Algorithm returns the key importation algorithm identifier (to be used).
func (opts *OVIPPrivateKeyImportOpts) Algorithm() string {
	return OVIP
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *OVIPPrivateKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

// ---------------------------
// OVIII
// OVIIIKeyGenOpts contains options for OVIII key generation.
type OVIIIKeyGenOpts struct {
	Temporary bool
}

// Algorithm returns the key generation algorithm identifier (to be used).
func (opts *OVIIIKeyGenOpts) Algorithm() string {
	return OVIII
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *OVIIIKeyGenOpts) Ephemeral() bool {
	return opts.Temporary
}

type OVIIIGoPublicKeyImportOpts struct {
	Temporary bool
}

// Algorithm returns the key generation algorithm identifier (to be used).
func (opts *OVIIIGoPublicKeyImportOpts) Algorithm() string {
	return OVIII
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *OVIIIGoPublicKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

type OVIIIPrivateKeyImportOpts struct {
	Temporary bool
}

// Algorithm returns the key importation algorithm identifier (to be used).
func (opts *OVIIIPrivateKeyImportOpts) Algorithm() string {
	return OVIII
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *OVIIIPrivateKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

// ---------------------------
// OVV
// OVVKeyGenOpts contains options for OVV key generation.
type OVVKeyGenOpts struct {
	Temporary bool
}

// Algorithm returns the key generation algorithm identifier (to be used).
func (opts *OVVKeyGenOpts) Algorithm() string {
	return OVV
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *OVVKeyGenOpts) Ephemeral() bool {
	return opts.Temporary
}

type OVVGoPublicKeyImportOpts struct {
	Temporary bool
}

// Algorithm returns the key generation algorithm identifier (to be used).
func (opts *OVVGoPublicKeyImportOpts) Algorithm() string {
	return OVV
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *OVVGoPublicKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

type OVVPrivateKeyImportOpts struct {
	Temporary bool
}

// Algorithm returns the key importation algorithm identifier (to be used).
func (opts *OVVPrivateKeyImportOpts) Algorithm() string {
	return OVV
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *OVVPrivateKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}
