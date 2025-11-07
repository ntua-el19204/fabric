/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sw

import (
	"crypto/ecdsa"
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
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"reflect"

	"github.com/hyperledger/fabric/bccsp"
)

type aes256ImportKeyOptsKeyImporter struct{}

func (*aes256ImportKeyOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	aesRaw, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected byte array.")
	}

	if aesRaw == nil {
		return nil, errors.New("Invalid raw material. It must not be nil.")
	}

	if len(aesRaw) != 32 {
		return nil, fmt.Errorf("Invalid Key Length [%d]. Must be 32 bytes", len(aesRaw))
	}

	return &aesPrivateKey{aesRaw, false}, nil
}

type hmacImportKeyOptsKeyImporter struct{}

func (*hmacImportKeyOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	aesRaw, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected byte array.")
	}

	if len(aesRaw) == 0 {
		return nil, errors.New("Invalid raw material. It must not be nil.")
	}

	return &aesPrivateKey{aesRaw, false}, nil
}

type ecdsaPKIXPublicKeyImportOptsKeyImporter struct{}

func (*ecdsaPKIXPublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	der, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected byte array.")
	}

	if len(der) == 0 {
		return nil, errors.New("Invalid raw. It must not be nil.")
	}

	lowLevelKey, err := derToPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("Failed converting PKIX to ECDSA public key [%s]", err)
	}

	ecdsaPK, ok := lowLevelKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("Failed casting to ECDSA public key. Invalid raw material.")
	}

	return &ecdsaPublicKey{ecdsaPK}, nil
}

type ecdsaPrivateKeyImportOptsKeyImporter struct{}

func (*ecdsaPrivateKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	der, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("[ECDSADERPrivateKeyImportOpts] Invalid raw material. Expected byte array.")
	}

	if len(der) == 0 {
		return nil, errors.New("[ECDSADERPrivateKeyImportOpts] Invalid raw. It must not be nil.")
	}

	lowLevelKey, err := derToPrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("Failed converting PKIX to ECDSA public key [%s]", err)
	}

	ecdsaSK, ok := lowLevelKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("Failed casting to ECDSA private key. Invalid raw material.")
	}

	return &ecdsaPrivateKey{ecdsaSK}, nil
}

type ecdsaGoPublicKeyImportOptsKeyImporter struct{}

func (*ecdsaGoPublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	lowLevelKey, ok := raw.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected *ecdsa.PublicKey.")
	}

	return &ecdsaPublicKey{lowLevelKey}, nil
}

type x509PublicKeyImportOptsKeyImporter struct {
	bccsp *CSP
}

func (ki *x509PublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	x509Cert, ok := raw.(*x509.Certificate)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected *x509.Certificate.")
	}

	pk := x509Cert.PublicKey

	switch pk := pk.(type) {
	case *ecdsa.PublicKey:
		return ki.bccsp.KeyImporters[reflect.TypeOf(&bccsp.ECDSAGoPublicKeyImportOpts{})].KeyImport(
			pk,
			&bccsp.ECDSAGoPublicKeyImportOpts{Temporary: opts.Ephemeral()})
	case *rsa.PublicKey:
		// This path only exists to support environments that use RSA certificate
		// authorities to issue ECDSA certificates.
		return &rsaPublicKey{pubKey: pk}, nil
	// Post quantum signatures
	// Falcon
	case falcon512.PublicKey:
		return ki.bccsp.KeyImporters[reflect.TypeOf(&bccsp.FALCON512GoPublicKeyImportOpts{})].KeyImport(
			pk,
			&bccsp.FALCON512GoPublicKeyImportOpts{Temporary: opts.Ephemeral()})
	case falcon1024.PublicKey:
		return ki.bccsp.KeyImporters[reflect.TypeOf(&bccsp.FALCON1024GoPublicKeyImportOpts{})].KeyImport(
			pk,
			&bccsp.FALCON1024GoPublicKeyImportOpts{Temporary: opts.Ephemeral()})
	case falcon512padded.PublicKey:
		return ki.bccsp.KeyImporters[reflect.TypeOf(&bccsp.FALCON512PADDEDGoPublicKeyImportOpts{})].KeyImport(
			pk,
			&bccsp.FALCON512PADDEDGoPublicKeyImportOpts{Temporary: opts.Ephemeral()})
	case falcon1024padded.PublicKey:
		return ki.bccsp.KeyImporters[reflect.TypeOf(&bccsp.FALCON1024PADDEDGoPublicKeyImportOpts{})].KeyImport(
			pk,
			&bccsp.FALCON1024PADDEDGoPublicKeyImportOpts{Temporary: opts.Ephemeral()})

	// Dilithium
	case dilithium2.PublicKey:
		return ki.bccsp.KeyImporters[reflect.TypeOf(&bccsp.DILITHIUM2GoPublicKeyImportOpts{})].KeyImport(
			pk,
			&bccsp.DILITHIUM2GoPublicKeyImportOpts{Temporary: opts.Ephemeral()})
	case dilithium3.PublicKey:
		return ki.bccsp.KeyImporters[reflect.TypeOf(&bccsp.DILITHIUM3GoPublicKeyImportOpts{})].KeyImport(
			pk,
			&bccsp.DILITHIUM3GoPublicKeyImportOpts{Temporary: opts.Ephemeral()})
	case dilithium5.PublicKey:
		return ki.bccsp.KeyImporters[reflect.TypeOf(&bccsp.DILITHIUM5GoPublicKeyImportOpts{})].KeyImport(
			pk,
			&bccsp.DILITHIUM5GoPublicKeyImportOpts{Temporary: opts.Ephemeral()})

	// Mayo
	case mayo2.PublicKey:
		return ki.bccsp.KeyImporters[reflect.TypeOf(&bccsp.MAYO2GoPublicKeyImportOpts{})].KeyImport(
			pk,
			&bccsp.MAYO2GoPublicKeyImportOpts{Temporary: opts.Ephemeral()})

	case mayo3.PublicKey:
		return ki.bccsp.KeyImporters[reflect.TypeOf(&bccsp.MAYO3GoPublicKeyImportOpts{})].KeyImport(
			pk,
			&bccsp.MAYO3GoPublicKeyImportOpts{Temporary: opts.Ephemeral()})
	case mayo5.PublicKey:
		return ki.bccsp.KeyImporters[reflect.TypeOf(&bccsp.MAYO5GoPublicKeyImportOpts{})].KeyImport(
			pk,
			&bccsp.MAYO5GoPublicKeyImportOpts{Temporary: opts.Ephemeral()})

	// Snova
	case snova2454.PublicKey:
		return ki.bccsp.KeyImporters[reflect.TypeOf(&bccsp.SNOVA2454GoPublicKeyImportOpts{})].KeyImport(
			pk,
			&bccsp.SNOVA2454GoPublicKeyImportOpts{Temporary: opts.Ephemeral()})
	case snova2583.PublicKey:
		return ki.bccsp.KeyImporters[reflect.TypeOf(&bccsp.SNOVA2583GoPublicKeyImportOpts{})].KeyImport(
			pk,
			&bccsp.SNOVA2583GoPublicKeyImportOpts{Temporary: opts.Ephemeral()})
	case snova2455.PublicKey:
		return ki.bccsp.KeyImporters[reflect.TypeOf(&bccsp.SNOVA2455GoPublicKeyImportOpts{})].KeyImport(
			pk,
			&bccsp.SNOVA2455GoPublicKeyImportOpts{Temporary: opts.Ephemeral()})
	case snova2965.PublicKey:
		return ki.bccsp.KeyImporters[reflect.TypeOf(&bccsp.SNOVA2965GoPublicKeyImportOpts{})].KeyImport(
			pk,
			&bccsp.SNOVA2965GoPublicKeyImportOpts{Temporary: opts.Ephemeral()})

	// UOV
	case ovip.PublicKey:
		return ki.bccsp.KeyImporters[reflect.TypeOf(&bccsp.OVIPGoPublicKeyImportOpts{})].KeyImport(
			pk,
			&bccsp.OVIPGoPublicKeyImportOpts{Temporary: opts.Ephemeral()})
	case oviii.PublicKey:
		return ki.bccsp.KeyImporters[reflect.TypeOf(&bccsp.OVIPGoPublicKeyImportOpts{})].KeyImport(
			pk,
			&bccsp.OVIPGoPublicKeyImportOpts{Temporary: opts.Ephemeral()})
	case ovv.PublicKey:
		return ki.bccsp.KeyImporters[reflect.TypeOf(&bccsp.OVVGoPublicKeyImportOpts{})].KeyImport(
			pk,
			&bccsp.OVVGoPublicKeyImportOpts{Temporary: opts.Ephemeral()})
	default:
		return nil, errors.New("Certificate's public key type not recognized. Supported keys: [ECDSA, RSA, and some post quantum signatures]")
	}
}

/*
Post Quantum Digital Signatures
*/
// Falcon
type falcon512PKIXPublicKeyImportOptsKeyImporter struct{}

func (*falcon512PKIXPublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	der, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected byte array.")
	}

	if len(der) == 0 {
		return nil, errors.New("Invalid raw. It must not be nil.")
	}

	lowLevelKey, err := derToPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("Failed converting PKIX to FALCON512 public key [%s]", err)
	}

	falcon512PK, ok := lowLevelKey.(falcon512.PublicKey)
	if !ok {
		return nil, errors.New("Failed casting to FALCON512 public key. Invalid raw material.")
	}

	return &falcon512PublicKey{falcon512PK}, nil
}

type falcon512PrivateKeyImportOptsKeyImporter struct{}

func (*falcon512PrivateKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	der, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("[FALCON512DERPrivateKeyImportOpts] Invalid raw material. Expected byte array.")
	}

	if len(der) == 0 {
		return nil, errors.New("[FALCON512DERPrivateKeyImportOpts] Invalid raw. It must not be nil.")
	}

	lowLevelKey, err := derToPrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("Failed converting PKIX to FALCON512 public key [%s]", err)
	}

	falcon512SK, ok := lowLevelKey.(*falcon512.PrivateKey)
	if !ok {
		return nil, errors.New("Failed casting to FALCON512 private key. Invalid raw material.")
	}

	return &falcon512PrivateKey{falcon512SK}, nil
}

type falcon512GoPublicKeyImportOptsKeyImporter struct{}

func (*falcon512GoPublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	lowLevelKey, ok := raw.(falcon512.PublicKey)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected falcon512.PublicKey.")
	}

	return &falcon512PublicKey{lowLevelKey}, nil
}

type falcon1024PKIXPublicKeyImportOptsKeyImporter struct{}

func (*falcon1024PKIXPublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	der, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected byte array.")
	}

	if len(der) == 0 {
		return nil, errors.New("Invalid raw. It must not be nil.")
	}

	lowLevelKey, err := derToPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("Failed converting PKIX to FALCON1024 public key [%s]", err)
	}

	falcon1024PK, ok := lowLevelKey.(falcon1024.PublicKey)
	if !ok {
		return nil, errors.New("Failed casting to FALCON1024 public key. Invalid raw material.")
	}

	return &falcon1024PublicKey{falcon1024PK}, nil
}

type falcon1024PrivateKeyImportOptsKeyImporter struct{}

func (*falcon1024PrivateKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	der, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("[FALCON1024DERPrivateKeyImportOpts] Invalid raw material. Expected byte array.")
	}

	if len(der) == 0 {
		return nil, errors.New("[FALCON1024DERPrivateKeyImportOpts] Invalid raw. It must not be nil.")
	}

	lowLevelKey, err := derToPrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("Failed converting PKIX to FALCON1024 public key [%s]", err)
	}

	falcon1024SK, ok := lowLevelKey.(*falcon1024.PrivateKey)
	if !ok {
		return nil, errors.New("Failed casting to FALCON512 private key. Invalid raw material.")
	}

	return &falcon1024PrivateKey{falcon1024SK}, nil
}

type falcon1024GoPublicKeyImportOptsKeyImporter struct{}

func (*falcon1024GoPublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	lowLevelKey, ok := raw.(falcon1024.PublicKey)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected falcon1024.PublicKey.")
	}

	return &falcon1024PublicKey{lowLevelKey}, nil
}

type falcon512paddedPKIXPublicKeyImportOptsKeyImporter struct{}

func (*falcon512paddedPKIXPublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	der, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected byte array.")
	}

	if len(der) == 0 {
		return nil, errors.New("Invalid raw. It must not be nil.")
	}

	lowLevelKey, err := derToPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("Failed converting PKIX to FALCON512PADDED public key [%s]", err)
	}

	falcon512paddedPK, ok := lowLevelKey.(falcon512padded.PublicKey)
	if !ok {
		return nil, errors.New("Failed casting to FALCON512PADDED public key. Invalid raw material.")
	}

	return &falcon512paddedPublicKey{falcon512paddedPK}, nil
}

type falcon512paddedPrivateKeyImportOptsKeyImporter struct{}

func (*falcon512paddedPrivateKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	der, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("[FALCON512PADDEDDERPrivateKeyImportOpts] Invalid raw material. Expected byte array.")
	}

	if len(der) == 0 {
		return nil, errors.New("[FALCON512PADDEDDERPrivateKeyImportOpts] Invalid raw. It must not be nil.")
	}

	lowLevelKey, err := derToPrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("Failed converting PKIX to FALCON512PADDED public key [%s]", err)
	}

	falcon512paddedSK, ok := lowLevelKey.(*falcon512padded.PrivateKey)
	if !ok {
		return nil, errors.New("Failed casting to FALCON512PADDED private key. Invalid raw material.")
	}

	return &falcon512paddedPrivateKey{falcon512paddedSK}, nil
}

type falcon512paddedGoPublicKeyImportOptsKeyImporter struct{}

func (*falcon512paddedGoPublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	lowLevelKey, ok := raw.(falcon512padded.PublicKey)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected falcon512padded.PublicKey.")
	}

	return &falcon512paddedPublicKey{lowLevelKey}, nil
}

type falcon1024paddedPKIXPublicKeyImportOptsKeyImporter struct{}

func (*falcon1024paddedPKIXPublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	der, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected byte array.")
	}

	if len(der) == 0 {
		return nil, errors.New("Invalid raw. It must not be nil.")
	}

	lowLevelKey, err := derToPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("Failed converting PKIX to FALCON1024padded public key [%s]", err)
	}

	falcon1024paddedPK, ok := lowLevelKey.(falcon1024padded.PublicKey)
	if !ok {
		return nil, errors.New("Failed casting to FALCON1024PADDED public key. Invalid raw material.")
	}

	return &falcon1024paddedPublicKey{falcon1024paddedPK}, nil
}

type falcon1024paddedPrivateKeyImportOptsKeyImporter struct{}

func (*falcon1024paddedPrivateKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	der, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("[FALCON51024PADDEDDERPrivateKeyImportOpts] Invalid raw material. Expected byte array.")
	}

	if len(der) == 0 {
		return nil, errors.New("[FALCON1024PADDEDDERPrivateKeyImportOpts] Invalid raw. It must not be nil.")
	}

	lowLevelKey, err := derToPrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("Failed converting PKIX to FALCON1024PADDED public key [%s]", err)
	}

	falcon1024paddedSK, ok := lowLevelKey.(*falcon1024padded.PrivateKey)
	if !ok {
		return nil, errors.New("Failed casting to FALCON1024PADDED private key. Invalid raw material.")
	}

	return &falcon1024paddedPrivateKey{falcon1024paddedSK}, nil
}

type falcon1024paddedGoPublicKeyImportOptsKeyImporter struct{}

func (*falcon1024paddedGoPublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	lowLevelKey, ok := raw.(falcon1024padded.PublicKey)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected falcon1024padded.PublicKey.")
	}

	return &falcon1024paddedPublicKey{lowLevelKey}, nil
}

// Dilithium
type dilithium2PKIXPublicKeyImportOptsKeyImporter struct{}

func (*dilithium2PKIXPublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	der, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected byte array.")
	}

	if len(der) == 0 {
		return nil, errors.New("Invalid raw. It must not be nil.")
	}

	lowLevelKey, err := derToPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("Failed converting PKIX to DILITHIUM2 public key [%s]", err)
	}

	dilithium2PK, ok := lowLevelKey.(dilithium2.PublicKey)
	if !ok {
		return nil, errors.New("Failed casting to DILITHIUM2 public key. Invalid raw material.")
	}

	return &dilithium2PublicKey{dilithium2PK}, nil
}

type dilithium2PrivateKeyImportOptsKeyImporter struct{}

func (*dilithium2PrivateKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	der, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("[DILITHIUM2DERPrivateKeyImportOpts] Invalid raw material. Expected byte array.")
	}

	if len(der) == 0 {
		return nil, errors.New("[DILITHIUM2DERPrivateKeyImportOpts] Invalid raw. It must not be nil.")
	}

	lowLevelKey, err := derToPrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("Failed converting PKIX to DILITHIUM2 public key [%s]", err)
	}

	dilithium2SK, ok := lowLevelKey.(*dilithium2.PrivateKey)
	if !ok {
		return nil, errors.New("Failed casting to DILITHIUM2 private key. Invalid raw material.")
	}

	return &dilithium2PrivateKey{dilithium2SK}, nil
}

type dilithium2GoPublicKeyImportOptsKeyImporter struct{}

func (*dilithium2GoPublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	lowLevelKey, ok := raw.(dilithium2.PublicKey)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected dilithium2.PublicKey.")
	}

	return &dilithium2PublicKey{lowLevelKey}, nil
}

type dilithium3PKIXPublicKeyImportOptsKeyImporter struct{}

func (*dilithium3PKIXPublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	der, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected byte array.")
	}

	if len(der) == 0 {
		return nil, errors.New("Invalid raw. It must not be nil.")
	}

	lowLevelKey, err := derToPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("Failed converting PKIX to DILITHIUM3 public key [%s]", err)
	}

	dilithium3PK, ok := lowLevelKey.(dilithium3.PublicKey)
	if !ok {
		return nil, errors.New("Failed casting to DILITHIUM3 public key. Invalid raw material.")
	}

	return &dilithium3PublicKey{dilithium3PK}, nil
}

type dilithium3PrivateKeyImportOptsKeyImporter struct{}

func (*dilithium3PrivateKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	der, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("[DILITHIUM3DERPrivateKeyImportOpts] Invalid raw material. Expected byte array.")
	}

	if len(der) == 0 {
		return nil, errors.New("[DILITHIUM3DERPrivateKeyImportOpts] Invalid raw. It must not be nil.")
	}

	lowLevelKey, err := derToPrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("Failed converting PKIX to DILITHIUM3 public key [%s]", err)
	}

	dilithium3SK, ok := lowLevelKey.(*dilithium3.PrivateKey)
	if !ok {
		return nil, errors.New("Failed casting to DILITHIUM3 private key. Invalid raw material.")
	}

	return &dilithium3PrivateKey{dilithium3SK}, nil
}

type dilithium3GoPublicKeyImportOptsKeyImporter struct{}

func (*dilithium3GoPublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	lowLevelKey, ok := raw.(dilithium3.PublicKey)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected dilithium3.PublicKey.")
	}

	return &dilithium3PublicKey{lowLevelKey}, nil
}

type dilithium5PKIXPublicKeyImportOptsKeyImporter struct{}

func (*dilithium5PKIXPublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	der, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected byte array.")
	}

	if len(der) == 0 {
		return nil, errors.New("Invalid raw. It must not be nil.")
	}

	lowLevelKey, err := derToPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("Failed converting PKIX to DILITHIUM5 public key [%s]", err)
	}

	dilithium5PK, ok := lowLevelKey.(dilithium5.PublicKey)
	if !ok {
		return nil, errors.New("Failed casting to DILITHIUM5 public key. Invalid raw material.")
	}

	return &dilithium5PublicKey{dilithium5PK}, nil
}

type dilithium5PrivateKeyImportOptsKeyImporter struct{}

func (*dilithium5PrivateKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	der, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("[DILITHIUM5DERPrivateKeyImportOpts] Invalid raw material. Expected byte array.")
	}

	if len(der) == 0 {
		return nil, errors.New("[DILITHIUM5DERPrivateKeyImportOpts] Invalid raw. It must not be nil.")
	}

	lowLevelKey, err := derToPrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("Failed converting PKIX to DILITHIUM5 public key [%s]", err)
	}

	dilithium5SK, ok := lowLevelKey.(*dilithium5.PrivateKey)
	if !ok {
		return nil, errors.New("Failed casting to DILITHIUM5 private key. Invalid raw material.")
	}

	return &dilithium5PrivateKey{dilithium5SK}, nil
}

type dilithium5GoPublicKeyImportOptsKeyImporter struct{}

func (*dilithium5GoPublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	lowLevelKey, ok := raw.(dilithium5.PublicKey)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected dilithium5.PublicKey.")
	}

	return &dilithium5PublicKey{lowLevelKey}, nil
}

// Mayo
type mayo2PKIXPublicKeyImportOptsKeyImporter struct{}

func (*mayo2PKIXPublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	der, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected byte array.")
	}

	if len(der) == 0 {
		return nil, errors.New("Invalid raw. It must not be nil.")
	}

	lowLevelKey, err := derToPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("Failed converting PKIX to MAYO2 public key [%s]", err)
	}

	mayo2PK, ok := lowLevelKey.(mayo2.PublicKey)
	if !ok {
		return nil, errors.New("Failed casting to MAYO2 public key. Invalid raw material.")
	}

	return &mayo2PublicKey{mayo2PK}, nil
}

type mayo2PrivateKeyImportOptsKeyImporter struct{}

func (*mayo2PrivateKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	der, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("[MAYO2DERPrivateKeyImportOpts] Invalid raw material. Expected byte array.")
	}

	if len(der) == 0 {
		return nil, errors.New("[MAYO2DERPrivateKeyImportOpts] Invalid raw. It must not be nil.")
	}

	lowLevelKey, err := derToPrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("Failed converting PKIX to MAYO2 public key [%s]", err)
	}

	mayo2SK, ok := lowLevelKey.(*mayo2.PrivateKey)
	if !ok {
		return nil, errors.New("Failed casting to MAYO2 private key. Invalid raw material.")
	}

	return &mayo2PrivateKey{mayo2SK}, nil
}

type mayo2GoPublicKeyImportOptsKeyImporter struct{}

func (*mayo2GoPublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	lowLevelKey, ok := raw.(mayo2.PublicKey)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected mayo2.PublicKey.")
	}

	return &mayo2PublicKey{lowLevelKey}, nil
}

type mayo3PKIXPublicKeyImportOptsKeyImporter struct{}

func (*mayo3PKIXPublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	der, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected byte array.")
	}

	if len(der) == 0 {
		return nil, errors.New("Invalid raw. It must not be nil.")
	}

	lowLevelKey, err := derToPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("Failed converting PKIX to MAYO3 public key [%s]", err)
	}

	mayo3PK, ok := lowLevelKey.(mayo3.PublicKey)
	if !ok {
		return nil, errors.New("Failed casting to MAYO3 public key. Invalid raw material.")
	}

	return &mayo3PublicKey{mayo3PK}, nil
}

type mayo3PrivateKeyImportOptsKeyImporter struct{}

func (*mayo3PrivateKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	der, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("[MAYO3DERPrivateKeyImportOpts] Invalid raw material. Expected byte array.")
	}

	if len(der) == 0 {
		return nil, errors.New("[MAYO3DERPrivateKeyImportOpts] Invalid raw. It must not be nil.")
	}

	lowLevelKey, err := derToPrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("Failed converting PKIX to MAYO3 public key [%s]", err)
	}

	mayo3SK, ok := lowLevelKey.(*mayo3.PrivateKey)
	if !ok {
		return nil, errors.New("Failed casting to MAYO3 private key. Invalid raw material.")
	}

	return &mayo3PrivateKey{mayo3SK}, nil
}

type mayo3GoPublicKeyImportOptsKeyImporter struct{}

func (*mayo3GoPublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	lowLevelKey, ok := raw.(mayo3.PublicKey)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected mayo3.PublicKey.")
	}

	return &mayo3PublicKey{lowLevelKey}, nil
}

type mayo5PKIXPublicKeyImportOptsKeyImporter struct{}

func (*mayo5PKIXPublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	der, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected byte array.")
	}

	if len(der) == 0 {
		return nil, errors.New("Invalid raw. It must not be nil.")
	}

	lowLevelKey, err := derToPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("Failed converting PKIX to MAYO5 public key [%s]", err)
	}

	mayo5PK, ok := lowLevelKey.(mayo5.PublicKey)
	if !ok {
		return nil, errors.New("Failed casting to MAYO5 public key. Invalid raw material.")
	}

	return &mayo5PublicKey{mayo5PK}, nil
}

type mayo5PrivateKeyImportOptsKeyImporter struct{}

func (*mayo5PrivateKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	der, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("[MAYO5DERPrivateKeyImportOpts] Invalid raw material. Expected byte array.")
	}

	if len(der) == 0 {
		return nil, errors.New("[MAYO5DERPrivateKeyImportOpts] Invalid raw. It must not be nil.")
	}

	lowLevelKey, err := derToPrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("Failed converting PKIX to MAYO5 public key [%s]", err)
	}

	mayo5SK, ok := lowLevelKey.(*mayo5.PrivateKey)
	if !ok {
		return nil, errors.New("Failed casting to MAYO5 private key. Invalid raw material.")
	}

	return &mayo5PrivateKey{mayo5SK}, nil
}

type mayo5GoPublicKeyImportOptsKeyImporter struct{}

func (*mayo5GoPublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	lowLevelKey, ok := raw.(mayo5.PublicKey)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected mayo5.PublicKey.")
	}

	return &mayo5PublicKey{lowLevelKey}, nil
}

// Snova
type snova2454PKIXPublicKeyImportOptsKeyImporter struct{}

func (*snova2454PKIXPublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	der, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected byte array.")
	}

	if len(der) == 0 {
		return nil, errors.New("Invalid raw. It must not be nil.")
	}

	lowLevelKey, err := derToPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("Failed converting PKIX to SNOVA2454 public key [%s]", err)
	}

	snova2454PK, ok := lowLevelKey.(snova2454.PublicKey)
	if !ok {
		return nil, errors.New("Failed casting to SNOVA2454 public key. Invalid raw material.")
	}

	return &snova2454PublicKey{snova2454PK}, nil
}

type snova2454PrivateKeyImportOptsKeyImporter struct{}

func (*snova2454PrivateKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	der, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("[SNOVA2454DERPrivateKeyImportOpts] Invalid raw material. Expected byte array.")
	}

	if len(der) == 0 {
		return nil, errors.New("[SNOVA2454DERPrivateKeyImportOpts] Invalid raw. It must not be nil.")
	}

	lowLevelKey, err := derToPrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("Failed converting PKIX to SNOVA2454 public key [%s]", err)
	}

	snova2454SK, ok := lowLevelKey.(*snova2454.PrivateKey)
	if !ok {
		return nil, errors.New("Failed casting to SNOVA2454 private key. Invalid raw material.")
	}

	return &snova2454PrivateKey{snova2454SK}, nil
}

type snova2454GoPublicKeyImportOptsKeyImporter struct{}

func (*snova2454GoPublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	lowLevelKey, ok := raw.(snova2454.PublicKey)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected snova2454.PublicKey.")
	}

	return &snova2454PublicKey{lowLevelKey}, nil
}

type snova2583PKIXPublicKeyImportOptsKeyImporter struct{}

func (*snova2583PKIXPublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	der, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected byte array.")
	}

	if len(der) == 0 {
		return nil, errors.New("Invalid raw. It must not be nil.")
	}

	lowLevelKey, err := derToPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("Failed converting PKIX to SNOVA2583 public key [%s]", err)
	}

	snova2583PK, ok := lowLevelKey.(snova2583.PublicKey)
	if !ok {
		return nil, errors.New("Failed casting to SNOVA2583 public key. Invalid raw material.")
	}

	return &snova2583PublicKey{snova2583PK}, nil
}

type snova2583PrivateKeyImportOptsKeyImporter struct{}

func (*snova2583PrivateKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	der, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("[SNOVA2583DERPrivateKeyImportOpts] Invalid raw material. Expected byte array.")
	}

	if len(der) == 0 {
		return nil, errors.New("[SNOVA2583DERPrivateKeyImportOpts] Invalid raw. It must not be nil.")
	}

	lowLevelKey, err := derToPrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("Failed converting PKIX to SNOVA2583 public key [%s]", err)
	}

	snova2583SK, ok := lowLevelKey.(*snova2583.PrivateKey)
	if !ok {
		return nil, errors.New("Failed casting to SNOVA2583 private key. Invalid raw material.")
	}

	return &snova2583PrivateKey{snova2583SK}, nil
}

type snova2583GoPublicKeyImportOptsKeyImporter struct{}

func (*snova2583GoPublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	lowLevelKey, ok := raw.(snova2583.PublicKey)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected snova2583.PublicKey.")
	}

	return &snova2583PublicKey{lowLevelKey}, nil
}

type snova2455PKIXPublicKeyImportOptsKeyImporter struct{}

func (*snova2455PKIXPublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	der, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected byte array.")
	}

	if len(der) == 0 {
		return nil, errors.New("Invalid raw. It must not be nil.")
	}

	lowLevelKey, err := derToPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("Failed converting PKIX to SNOVA2455 public key [%s]", err)
	}

	snova2455PK, ok := lowLevelKey.(snova2455.PublicKey)
	if !ok {
		return nil, errors.New("Failed casting to SNOVA2455 public key. Invalid raw material.")
	}

	return &snova2455PublicKey{snova2455PK}, nil
}

type snova2455PrivateKeyImportOptsKeyImporter struct{}

func (*snova2455PrivateKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	der, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("[SNOVA2455DERPrivateKeyImportOpts] Invalid raw material. Expected byte array.")
	}

	if len(der) == 0 {
		return nil, errors.New("[SNOVA2455DERPrivateKeyImportOpts] Invalid raw. It must not be nil.")
	}

	lowLevelKey, err := derToPrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("Failed converting PKIX to SNOVA2455 public key [%s]", err)
	}

	snova2455SK, ok := lowLevelKey.(*snova2455.PrivateKey)
	if !ok {
		return nil, errors.New("Failed casting to SNOVA2455 private key. Invalid raw material.")
	}

	return &snova2455PrivateKey{snova2455SK}, nil
}

type snova2455GoPublicKeyImportOptsKeyImporter struct{}

func (*snova2455GoPublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	lowLevelKey, ok := raw.(snova2455.PublicKey)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected snova2455.PublicKey.")
	}

	return &snova2455PublicKey{lowLevelKey}, nil
}

type snova2965PKIXPublicKeyImportOptsKeyImporter struct{}

func (*snova2965PKIXPublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	der, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected byte array.")
	}

	if len(der) == 0 {
		return nil, errors.New("Invalid raw. It must not be nil.")
	}

	lowLevelKey, err := derToPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("Failed converting PKIX to SNOVA2965 public key [%s]", err)
	}

	snova2965PK, ok := lowLevelKey.(snova2965.PublicKey)
	if !ok {
		return nil, errors.New("Failed casting to SNOVA2965 public key. Invalid raw material.")
	}

	return &snova2965PublicKey{snova2965PK}, nil
}

type snova2965PrivateKeyImportOptsKeyImporter struct{}

func (*snova2965PrivateKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	der, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("[SNOVA2965DERPrivateKeyImportOpts] Invalid raw material. Expected byte array.")
	}

	if len(der) == 0 {
		return nil, errors.New("[SNOVA2965DERPrivateKeyImportOpts] Invalid raw. It must not be nil.")
	}

	lowLevelKey, err := derToPrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("Failed converting PKIX to SNOVA2965 public key [%s]", err)
	}

	snova2965SK, ok := lowLevelKey.(*snova2965.PrivateKey)
	if !ok {
		return nil, errors.New("Failed casting to SNOVA2965 private key. Invalid raw material.")
	}

	return &snova2965PrivateKey{snova2965SK}, nil
}

type snova2965GoPublicKeyImportOptsKeyImporter struct{}

func (*snova2965GoPublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	lowLevelKey, ok := raw.(snova2965.PublicKey)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected snova2965.PublicKey.")
	}

	return &snova2965PublicKey{lowLevelKey}, nil
}

// UOV
type ovipPKIXPublicKeyImportOptsKeyImporter struct{}

func (*ovipPKIXPublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	der, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected byte array.")
	}

	if len(der) == 0 {
		return nil, errors.New("Invalid raw. It must not be nil.")
	}

	lowLevelKey, err := derToPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("Failed converting PKIX to OVIP public key [%s]", err)
	}

	ovipPK, ok := lowLevelKey.(ovip.PublicKey)
	if !ok {
		return nil, errors.New("Failed casting to OVIP public key. Invalid raw material.")
	}

	return &ovipPublicKey{ovipPK}, nil
}

type ovipPrivateKeyImportOptsKeyImporter struct{}

func (*ovipPrivateKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	der, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("[OVIPDERPrivateKeyImportOpts] Invalid raw material. Expected byte array.")
	}

	if len(der) == 0 {
		return nil, errors.New("[OVIPDERPrivateKeyImportOpts] Invalid raw. It must not be nil.")
	}

	lowLevelKey, err := derToPrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("Failed converting PKIX to OVIP public key [%s]", err)
	}

	ovipSK, ok := lowLevelKey.(*ovip.PrivateKey)
	if !ok {
		return nil, errors.New("Failed casting to OVIP private key. Invalid raw material.")
	}

	return &ovipPrivateKey{ovipSK}, nil
}

type ovipGoPublicKeyImportOptsKeyImporter struct{}

func (*ovipGoPublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	lowLevelKey, ok := raw.(ovip.PublicKey)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected ovip.PublicKey.")
	}

	return &ovipPublicKey{lowLevelKey}, nil
}

type oviiiPKIXPublicKeyImportOptsKeyImporter struct{}

func (*oviiiPKIXPublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	der, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected byte array.")
	}

	if len(der) == 0 {
		return nil, errors.New("Invalid raw. It must not be nil.")
	}

	lowLevelKey, err := derToPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("Failed converting PKIX to OVIII public key [%s]", err)
	}

	oviiiPK, ok := lowLevelKey.(oviii.PublicKey)
	if !ok {
		return nil, errors.New("Failed casting to OVIII public key. Invalid raw material.")
	}

	return &oviiiPublicKey{oviiiPK}, nil
}

type oviiiPrivateKeyImportOptsKeyImporter struct{}

func (*oviiiPrivateKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	der, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("[OVIIIDERPrivateKeyImportOpts] Invalid raw material. Expected byte array.")
	}

	if len(der) == 0 {
		return nil, errors.New("[OVIIIDERPrivateKeyImportOpts] Invalid raw. It must not be nil.")
	}

	lowLevelKey, err := derToPrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("Failed converting PKIX to OVIII public key [%s]", err)
	}

	oviiiSK, ok := lowLevelKey.(*oviii.PrivateKey)
	if !ok {
		return nil, errors.New("Failed casting to OVIII private key. Invalid raw material.")
	}

	return &oviiiPrivateKey{oviiiSK}, nil
}

type oviiiGoPublicKeyImportOptsKeyImporter struct{}

func (*oviiiGoPublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	lowLevelKey, ok := raw.(oviii.PublicKey)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected oviii.PublicKey.")
	}

	return &oviiiPublicKey{lowLevelKey}, nil
}

type ovvPKIXPublicKeyImportOptsKeyImporter struct{}

func (*ovvPKIXPublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	der, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected byte array.")
	}

	if len(der) == 0 {
		return nil, errors.New("Invalid raw. It must not be nil.")
	}

	lowLevelKey, err := derToPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("Failed converting PKIX to OVV public key [%s]", err)
	}

	ovvPK, ok := lowLevelKey.(ovv.PublicKey)
	if !ok {
		return nil, errors.New("Failed casting to OVV public key. Invalid raw material.")
	}

	return &ovvPublicKey{ovvPK}, nil
}

type ovvPrivateKeyImportOptsKeyImporter struct{}

func (*ovvPrivateKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	der, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("[OVVDERPrivateKeyImportOpts] Invalid raw material. Expected byte array.")
	}

	if len(der) == 0 {
		return nil, errors.New("[OVVDERPrivateKeyImportOpts] Invalid raw. It must not be nil.")
	}

	lowLevelKey, err := derToPrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("Failed converting PKIX to OVV public key [%s]", err)
	}

	ovvSK, ok := lowLevelKey.(*ovv.PrivateKey)
	if !ok {
		return nil, errors.New("Failed casting to OVV private key. Invalid raw material.")
	}

	return &ovvPrivateKey{ovvSK}, nil
}

type ovvGoPublicKeyImportOptsKeyImporter struct{}

func (*ovvGoPublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	lowLevelKey, ok := raw.(ovv.PublicKey)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected ovv.PublicKey.")
	}

	return &ovvPublicKey{lowLevelKey}, nil
}
