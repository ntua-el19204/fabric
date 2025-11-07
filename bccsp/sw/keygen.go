/*
Copyright IBM Corp. 2017 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package sw

import (
	"crypto/ecdsa"
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
	"fmt"

	"github.com/hyperledger/fabric/bccsp"
)

type ecdsaKeyGenerator struct {
	curve elliptic.Curve
}

func (kg *ecdsaKeyGenerator) KeyGen(opts bccsp.KeyGenOpts) (bccsp.Key, error) {
	privKey, err := ecdsa.GenerateKey(kg.curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("Failed generating ECDSA key for [%v]: [%s]", kg.curve, err)
	}

	return &ecdsaPrivateKey{privKey}, nil
}

type aesKeyGenerator struct {
	length int
}

func (kg *aesKeyGenerator) KeyGen(opts bccsp.KeyGenOpts) (bccsp.Key, error) {
	lowLevelKey, err := GetRandomBytes(int(kg.length))
	if err != nil {
		return nil, fmt.Errorf("Failed generating AES %d key [%s]", kg.length, err)
	}

	return &aesPrivateKey{lowLevelKey, false}, nil
}

/*
Post Quantum Digital Signatures
*/

// Falcon
type falcon512KeyGenerator struct {
}

func (kg *falcon512KeyGenerator) KeyGen(opts bccsp.KeyGenOpts) (bccsp.Key, error) {
	privKey, err := falcon512.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("Failed generating FALCON512 key: [%s]", err)
	}

	return &falcon512PrivateKey{privKey}, nil
}

type falcon1024KeyGenerator struct {
}

func (kg *falcon1024KeyGenerator) KeyGen(opts bccsp.KeyGenOpts) (bccsp.Key, error) {
	privKey, err := falcon1024.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("Failed generating FALCON1024 key: [%s]", err)
	}

	return &falcon1024PrivateKey{privKey}, nil
}

type falcon512paddedKeyGenerator struct {
}

func (kg *falcon512paddedKeyGenerator) KeyGen(opts bccsp.KeyGenOpts) (bccsp.Key, error) {
	privKey, err := falcon512padded.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("Failed generating FALCON512PADDED key: [%s]", err)
	}

	return &falcon512paddedPrivateKey{privKey}, nil
}

type falcon1024paddedKeyGenerator struct {
}

func (kg *falcon1024paddedKeyGenerator) KeyGen(opts bccsp.KeyGenOpts) (bccsp.Key, error) {
	privKey, err := falcon1024padded.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("Failed generating FALCON1024PADDED key: [%s]", err)
	}

	return &falcon1024paddedPrivateKey{privKey}, nil
}

// Dilithium
type dilithium2KeyGenerator struct {
}

func (kg *dilithium2KeyGenerator) KeyGen(opts bccsp.KeyGenOpts) (bccsp.Key, error) {
	privKey, err := dilithium2.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("Failed generating DILITHIUM2 key: [%s]", err)
	}

	return &dilithium2PrivateKey{privKey}, nil
}

type dilithium3KeyGenerator struct {
}

func (kg *dilithium3KeyGenerator) KeyGen(opts bccsp.KeyGenOpts) (bccsp.Key, error) {
	privKey, err := dilithium3.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("Failed generating DILITHIUM3 key: [%s]", err)
	}

	return &dilithium3PrivateKey{privKey}, nil
}

type dilithium5KeyGenerator struct {
}

func (kg *dilithium5KeyGenerator) KeyGen(opts bccsp.KeyGenOpts) (bccsp.Key, error) {
	privKey, err := dilithium5.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("Failed generating DILITHIUM5 key: [%s]", err)
	}

	return &dilithium5PrivateKey{privKey}, nil
}

// Mayo
type mayo2KeyGenerator struct {
}

func (kg *mayo2KeyGenerator) KeyGen(opts bccsp.KeyGenOpts) (bccsp.Key, error) {
	privKey, err := mayo2.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("Failed generating MAYO2 key: [%s]", err)
	}

	return &mayo2PrivateKey{privKey}, nil
}

type mayo3KeyGenerator struct {
}

func (kg *mayo3KeyGenerator) KeyGen(opts bccsp.KeyGenOpts) (bccsp.Key, error) {
	privKey, err := mayo3.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("Failed generating MAYO3 key: [%s]", err)
	}

	return &mayo3PrivateKey{privKey}, nil
}

type mayo5KeyGenerator struct {
}

func (kg *mayo5KeyGenerator) KeyGen(opts bccsp.KeyGenOpts) (bccsp.Key, error) {
	privKey, err := mayo5.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("Failed generating MAYO5 key: [%s]", err)
	}

	return &mayo5PrivateKey{privKey}, nil
}

// Snova
type snova2454KeyGenerator struct {
}

func (kg *snova2454KeyGenerator) KeyGen(opts bccsp.KeyGenOpts) (bccsp.Key, error) {
	privKey, err := snova2454.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("Failed generating SNOVA2454 key: [%s]", err)
	}

	return &snova2454PrivateKey{privKey}, nil
}

type snova2583KeyGenerator struct {
}

func (kg *snova2583KeyGenerator) KeyGen(opts bccsp.KeyGenOpts) (bccsp.Key, error) {
	privKey, err := snova2583.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("Failed generating SNOVA2583 key: [%s]", err)
	}

	return &snova2583PrivateKey{privKey}, nil
}

type snova2455KeyGenerator struct {
}

func (kg *snova2455KeyGenerator) KeyGen(opts bccsp.KeyGenOpts) (bccsp.Key, error) {
	privKey, err := snova2455.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("Failed generating SNOVA2455 key: [%s]", err)
	}

	return &snova2455PrivateKey{privKey}, nil
}

type snova2965KeyGenerator struct {
}

func (kg *snova2965KeyGenerator) KeyGen(opts bccsp.KeyGenOpts) (bccsp.Key, error) {
	privKey, err := snova2965.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("Failed generating SNOVA2965 key: [%s]", err)
	}

	return &snova2965PrivateKey{privKey}, nil
}

// UOV
type ovipKeyGenerator struct {
}

func (kg *ovipKeyGenerator) KeyGen(opts bccsp.KeyGenOpts) (bccsp.Key, error) {
	privKey, err := ovip.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("Failed generating OVIP key: [%s]", err)
	}

	return &ovipPrivateKey{privKey}, nil
}

type oviiiKeyGenerator struct {
}

func (kg *oviiiKeyGenerator) KeyGen(opts bccsp.KeyGenOpts) (bccsp.Key, error) {
	privKey, err := oviii.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("Failed generating OVIII key: [%s]", err)
	}

	return &oviiiPrivateKey{privKey}, nil
}

type ovvKeyGenerator struct {
}

func (kg *ovvKeyGenerator) KeyGen(opts bccsp.KeyGenOpts) (bccsp.Key, error) {
	privKey, err := ovv.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("Failed generating OVV key: [%s]", err)
	}

	return &ovvPrivateKey{privKey}, nil
}
