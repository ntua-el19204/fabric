/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sw

import (
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"reflect"

	"github.com/hyperledger/fabric/bccsp"
	"github.com/pkg/errors"
	"golang.org/x/crypto/sha3"
)

// NewDefaultSecurityLevel returns a new instance of the software-based BCCSP
// at security level 256, hash family SHA2 and using FolderBasedKeyStore as KeyStore.
func NewDefaultSecurityLevel(keyStorePath string) (bccsp.BCCSP, error) {
	ks := &fileBasedKeyStore{}
	if err := ks.Init(nil, keyStorePath, false); err != nil {
		return nil, errors.Wrapf(err, "Failed initializing key store at [%v]", keyStorePath)
	}

	return NewWithParams(256, "SHA2", ks)
}

// NewDefaultSecurityLevel returns a new instance of the software-based BCCSP
// at security level 256, hash family SHA2 and using the passed KeyStore.
func NewDefaultSecurityLevelWithKeystore(keyStore bccsp.KeyStore) (bccsp.BCCSP, error) {
	return NewWithParams(256, "SHA2", keyStore)
}

// NewWithParams returns a new instance of the software-based BCCSP
// set at the passed security level, hash family and KeyStore.
func NewWithParams(securityLevel int, hashFamily string, keyStore bccsp.KeyStore) (bccsp.BCCSP, error) {
	// Init config
	conf := &config{}
	err := conf.setSecurityLevel(securityLevel, hashFamily)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed initializing configuration at [%v,%v]", securityLevel, hashFamily)
	}

	swbccsp, err := New(keyStore)
	if err != nil {
		return nil, err
	}

	// Notice that errors are ignored here because some test will fail if one
	// of the following call fails.

	// Set the Encryptors
	swbccsp.AddWrapper(reflect.TypeOf(&aesPrivateKey{}), &aescbcpkcs7Encryptor{})

	// Set the Decryptors
	swbccsp.AddWrapper(reflect.TypeOf(&aesPrivateKey{}), &aescbcpkcs7Decryptor{})

	// Set the Signers
	swbccsp.AddWrapper(reflect.TypeOf(&ecdsaPrivateKey{}), &ecdsaSigner{})
	// Post quantum digital signatures
	// Falcon
	swbccsp.AddWrapper(reflect.TypeOf(&falcon512PrivateKey{}), &falcon512Signer{})
	swbccsp.AddWrapper(reflect.TypeOf(&falcon1024PrivateKey{}), &falcon1024Signer{})
	swbccsp.AddWrapper(reflect.TypeOf(&falcon512paddedPrivateKey{}), &falcon512paddedSigner{})
	swbccsp.AddWrapper(reflect.TypeOf(&falcon1024paddedPrivateKey{}), &falcon1024paddedSigner{})
	// Dilithium
	swbccsp.AddWrapper(reflect.TypeOf(&dilithium2PrivateKey{}), &dilithium2Signer{})
	swbccsp.AddWrapper(reflect.TypeOf(&dilithium3PrivateKey{}), &dilithium3Signer{})
	swbccsp.AddWrapper(reflect.TypeOf(&dilithium5PrivateKey{}), &dilithium5Signer{})
	// Mayo
	swbccsp.AddWrapper(reflect.TypeOf(&mayo2PrivateKey{}), &mayo2Signer{})
	swbccsp.AddWrapper(reflect.TypeOf(&mayo3PrivateKey{}), &mayo3Signer{})
	swbccsp.AddWrapper(reflect.TypeOf(&mayo5PrivateKey{}), &mayo5Signer{})
	// Snova
	swbccsp.AddWrapper(reflect.TypeOf(&snova2454PrivateKey{}), &snova2454Signer{})
	swbccsp.AddWrapper(reflect.TypeOf(&snova2583PrivateKey{}), &snova2583Signer{})
	swbccsp.AddWrapper(reflect.TypeOf(&snova2455PrivateKey{}), &snova2455Signer{})
	swbccsp.AddWrapper(reflect.TypeOf(&snova2965PrivateKey{}), &snova2965Signer{})
	// UOV
	swbccsp.AddWrapper(reflect.TypeOf(&ovipPrivateKey{}), &ovipSigner{})
	swbccsp.AddWrapper(reflect.TypeOf(&oviiiPrivateKey{}), &oviiiSigner{})
	swbccsp.AddWrapper(reflect.TypeOf(&ovvPrivateKey{}), &ovvSigner{})

	// Set the Verifiers
	swbccsp.AddWrapper(reflect.TypeOf(&ecdsaPrivateKey{}), &ecdsaPrivateKeyVerifier{})
	swbccsp.AddWrapper(reflect.TypeOf(&ecdsaPublicKey{}), &ecdsaPublicKeyKeyVerifier{})
	// Post quantum digital signatures
	// Falcon
	swbccsp.AddWrapper(reflect.TypeOf(&falcon512PublicKey{}), &falcon512PublicKeyKeyVerifier{})
	swbccsp.AddWrapper(reflect.TypeOf(&falcon1024PublicKey{}), &falcon1024PublicKeyKeyVerifier{})
	swbccsp.AddWrapper(reflect.TypeOf(&falcon512paddedPublicKey{}), &falcon512paddedPublicKeyKeyVerifier{})
	swbccsp.AddWrapper(reflect.TypeOf(&falcon1024paddedPublicKey{}), &falcon1024paddedPublicKeyKeyVerifier{})
	// Dilithium
	swbccsp.AddWrapper(reflect.TypeOf(&dilithium2PublicKey{}), &dilithium2PublicKeyKeyVerifier{})
	swbccsp.AddWrapper(reflect.TypeOf(&dilithium3PublicKey{}), &dilithium3PublicKeyKeyVerifier{})
	swbccsp.AddWrapper(reflect.TypeOf(&dilithium5PublicKey{}), &dilithium5PublicKeyKeyVerifier{})
	// Mayo
	swbccsp.AddWrapper(reflect.TypeOf(&mayo2PublicKey{}), &mayo2PublicKeyKeyVerifier{})
	swbccsp.AddWrapper(reflect.TypeOf(&mayo3PublicKey{}), &mayo3PublicKeyKeyVerifier{})
	swbccsp.AddWrapper(reflect.TypeOf(&mayo5PublicKey{}), &mayo5PublicKeyKeyVerifier{})
	// Snova
	swbccsp.AddWrapper(reflect.TypeOf(&snova2454PublicKey{}), &snova2454PublicKeyKeyVerifier{})
	swbccsp.AddWrapper(reflect.TypeOf(&snova2583PublicKey{}), &snova2583PublicKeyKeyVerifier{})
	swbccsp.AddWrapper(reflect.TypeOf(&snova2455PublicKey{}), &snova2455PublicKeyKeyVerifier{})
	swbccsp.AddWrapper(reflect.TypeOf(&snova2965PublicKey{}), &snova2965PublicKeyKeyVerifier{})
	// UOV
	swbccsp.AddWrapper(reflect.TypeOf(&ovipPublicKey{}), &ovipPublicKeyKeyVerifier{})
	swbccsp.AddWrapper(reflect.TypeOf(&oviiiPublicKey{}), &oviiiPublicKeyKeyVerifier{})
	swbccsp.AddWrapper(reflect.TypeOf(&ovvPublicKey{}), &ovvPublicKeyKeyVerifier{})

	// Set the Hashers
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.SHAOpts{}), &hasher{hash: conf.hashFunction})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.SHA256Opts{}), &hasher{hash: sha256.New})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.SHA384Opts{}), &hasher{hash: sha512.New384})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.SHA3_256Opts{}), &hasher{hash: sha3.New256})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.SHA3_384Opts{}), &hasher{hash: sha3.New384})

	// Set the key generators
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.ECDSAKeyGenOpts{}), &ecdsaKeyGenerator{curve: conf.ellipticCurve})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.ECDSAP256KeyGenOpts{}), &ecdsaKeyGenerator{curve: elliptic.P256()})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.ECDSAP384KeyGenOpts{}), &ecdsaKeyGenerator{curve: elliptic.P384()})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.AESKeyGenOpts{}), &aesKeyGenerator{length: conf.aesBitLength})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.AES256KeyGenOpts{}), &aesKeyGenerator{length: 32})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.AES192KeyGenOpts{}), &aesKeyGenerator{length: 24})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.AES128KeyGenOpts{}), &aesKeyGenerator{length: 16})
	// Post quantum digital signatures
	// Falcon
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.FALCON512KeyGenOpts{}), &falcon512KeyGenerator{})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.FALCON1024KeyGenOpts{}), &falcon1024KeyGenerator{})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.FALCON512PADDEDKeyGenOpts{}), &falcon512paddedKeyGenerator{})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.FALCON1024PADDEDKeyGenOpts{}), &falcon1024paddedKeyGenerator{})
	// Dilithium
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.DILITHIUM2KeyGenOpts{}), &dilithium2KeyGenerator{})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.DILITHIUM5KeyGenOpts{}), &dilithium5KeyGenerator{})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.DILITHIUM5KeyGenOpts{}), &dilithium5KeyGenerator{})
	// Mayo
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.MAYO2KeyGenOpts{}), &mayo2KeyGenerator{})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.MAYO3KeyGenOpts{}), &mayo3KeyGenerator{})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.MAYO5KeyGenOpts{}), &mayo5KeyGenerator{})
	// Snova
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.SNOVA2454KeyGenOpts{}), &snova2454KeyGenerator{})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.SNOVA2583KeyGenOpts{}), &snova2583KeyGenerator{})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.SNOVA2455KeyGenOpts{}), &snova2455KeyGenerator{})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.SNOVA2965KeyGenOpts{}), &snova2965KeyGenerator{})
	// UOV
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.OVIPKeyGenOpts{}), &ovipKeyGenerator{})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.OVIIIKeyGenOpts{}), &oviiiKeyGenerator{})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.OVVKeyGenOpts{}), &ovvKeyGenerator{})

	// Set the key deriver
	swbccsp.AddWrapper(reflect.TypeOf(&ecdsaPrivateKey{}), &ecdsaPrivateKeyKeyDeriver{})
	swbccsp.AddWrapper(reflect.TypeOf(&ecdsaPublicKey{}), &ecdsaPublicKeyKeyDeriver{})
	swbccsp.AddWrapper(reflect.TypeOf(&aesPrivateKey{}), &aesPrivateKeyKeyDeriver{conf: conf})

	// Set the key importers
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.AES256ImportKeyOpts{}), &aes256ImportKeyOptsKeyImporter{})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.HMACImportKeyOpts{}), &hmacImportKeyOptsKeyImporter{})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.ECDSAPKIXPublicKeyImportOpts{}), &ecdsaPKIXPublicKeyImportOptsKeyImporter{})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.ECDSAPrivateKeyImportOpts{}), &ecdsaPrivateKeyImportOptsKeyImporter{})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.ECDSAGoPublicKeyImportOpts{}), &ecdsaGoPublicKeyImportOptsKeyImporter{})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.X509PublicKeyImportOpts{}), &x509PublicKeyImportOptsKeyImporter{bccsp: swbccsp})
	// Post quantum digital signatures
	// Falcon
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.FALCON512PrivateKeyImportOpts{}), &falcon512PrivateKeyImportOptsKeyImporter{})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.FALCON512GoPublicKeyImportOpts{}), &falcon512GoPublicKeyImportOptsKeyImporter{})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.FALCON1024PrivateKeyImportOpts{}), &falcon1024PrivateKeyImportOptsKeyImporter{})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.FALCON1024GoPublicKeyImportOpts{}), &falcon1024GoPublicKeyImportOptsKeyImporter{})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.FALCON512PADDEDPrivateKeyImportOpts{}), &falcon512paddedPrivateKeyImportOptsKeyImporter{})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.FALCON512PADDEDGoPublicKeyImportOpts{}), &falcon512paddedGoPublicKeyImportOptsKeyImporter{})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.FALCON1024PADDEDPrivateKeyImportOpts{}), &falcon1024paddedPrivateKeyImportOptsKeyImporter{})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.FALCON1024PADDEDGoPublicKeyImportOpts{}), &falcon1024paddedGoPublicKeyImportOptsKeyImporter{})
	// Dilithium
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.DILITHIUM2PrivateKeyImportOpts{}), &dilithium2PrivateKeyImportOptsKeyImporter{})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.DILITHIUM2GoPublicKeyImportOpts{}), &dilithium2GoPublicKeyImportOptsKeyImporter{})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.DILITHIUM3PrivateKeyImportOpts{}), &dilithium3PrivateKeyImportOptsKeyImporter{})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.DILITHIUM3GoPublicKeyImportOpts{}), &dilithium3GoPublicKeyImportOptsKeyImporter{})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.DILITHIUM5PrivateKeyImportOpts{}), &dilithium5PrivateKeyImportOptsKeyImporter{})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.DILITHIUM5GoPublicKeyImportOpts{}), &dilithium5GoPublicKeyImportOptsKeyImporter{})
	// Mayo
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.MAYO2PrivateKeyImportOpts{}), &mayo2PrivateKeyImportOptsKeyImporter{})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.MAYO2GoPublicKeyImportOpts{}), &mayo2GoPublicKeyImportOptsKeyImporter{})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.MAYO3PrivateKeyImportOpts{}), &mayo3PrivateKeyImportOptsKeyImporter{})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.MAYO3GoPublicKeyImportOpts{}), &mayo3GoPublicKeyImportOptsKeyImporter{})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.MAYO5PrivateKeyImportOpts{}), &mayo5PrivateKeyImportOptsKeyImporter{})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.MAYO5GoPublicKeyImportOpts{}), &mayo5GoPublicKeyImportOptsKeyImporter{})
	// Snova
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.SNOVA2454PrivateKeyImportOpts{}), &snova2454PrivateKeyImportOptsKeyImporter{})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.SNOVA2454GoPublicKeyImportOpts{}), &snova2454GoPublicKeyImportOptsKeyImporter{})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.SNOVA2583PrivateKeyImportOpts{}), &snova2583PrivateKeyImportOptsKeyImporter{})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.SNOVA2583GoPublicKeyImportOpts{}), &snova2583GoPublicKeyImportOptsKeyImporter{})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.SNOVA2455PrivateKeyImportOpts{}), &snova2455PrivateKeyImportOptsKeyImporter{})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.SNOVA2455GoPublicKeyImportOpts{}), &snova2455GoPublicKeyImportOptsKeyImporter{})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.SNOVA2965PrivateKeyImportOpts{}), &snova2965PrivateKeyImportOptsKeyImporter{})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.SNOVA2965GoPublicKeyImportOpts{}), &snova2965GoPublicKeyImportOptsKeyImporter{})
	// UOV
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.OVIPPrivateKeyImportOpts{}), &ovipPrivateKeyImportOptsKeyImporter{})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.OVIPGoPublicKeyImportOpts{}), &ovipGoPublicKeyImportOptsKeyImporter{})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.OVIIIPrivateKeyImportOpts{}), &oviiiPrivateKeyImportOptsKeyImporter{})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.OVIIIGoPublicKeyImportOpts{}), &oviiiGoPublicKeyImportOptsKeyImporter{})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.OVVPrivateKeyImportOpts{}), &ovvPrivateKeyImportOptsKeyImporter{})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.OVVGoPublicKeyImportOpts{}), &ovvGoPublicKeyImportOptsKeyImporter{})

	return swbccsp, nil
}
