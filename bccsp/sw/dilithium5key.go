/*
Copyright IBM Corp. 2016 All Rights Reserved.

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
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"

	dilithium5 "crypto/pqc/dilithium/dilithium5"

	"github.com/hyperledger/fabric/bccsp"
)

type dilithium5PrivateKey struct {
	privKey *dilithium5.PrivateKey
}

// Bytes converts this key to its byte representation,
// if this operation is allowed.
func (k *dilithium5PrivateKey) Bytes() ([]byte, error) {
	return nil, errors.New("Not supported.")
}

// SKI returns the subject key identifier of this key.
func (k *dilithium5PrivateKey) SKI() []byte {
	if k.privKey == nil {
		return nil
	}
	hash := sha256.New()
	hash.Write(k.privKey.Sk)
	return hash.Sum(nil)
}

// Symmetric returns true if this key is a symmetric key,
// false if this key is asymmetric
func (k *dilithium5PrivateKey) Symmetric() bool {
	return false
}

// Private returns true if this key is a private key,
// false otherwise.
func (k *dilithium5PrivateKey) Private() bool {
	return true
}

// PublicKey returns the corresponding public key part of an asymmetric public/private key pair.
// This method returns an error in symmetric key schemes.
func (k *dilithium5PrivateKey) PublicKey() (bccsp.Key, error) {
	return &dilithium5PublicKey{&k.privKey.PublicKey}, nil
}

type dilithium5PublicKey struct {
	pubKey *dilithium5.PublicKey
}

// Bytes converts this key to its byte representation,
// if this operation is allowed.
func (k *dilithium5PublicKey) Bytes() (raw []byte, err error) {
	raw, err = x509.MarshalPKIXPublicKey(k.pubKey)
	if err != nil {
		return nil, fmt.Errorf("Failed marshalling key [%s]", err)
	}
	return
}

// SKI returns the subject key identifier of this key.
func (k *dilithium5PublicKey) SKI() []byte {
	if k.pubKey == nil {
		return nil
	}
	hash := sha256.New()
	hash.Write(*k.pubKey)
	return hash.Sum(nil)
}

// Symmetric returns true if this key is a symmetric key,
// false if this key is asymmetric
func (k *dilithium5PublicKey) Symmetric() bool {
	return false
}

// Private returns true if this key is a private key,
// false otherwise.
func (k *dilithium5PublicKey) Private() bool {
	return false
}

// PublicKey returns the corresponding public key part of an asymmetric public/private key pair.
// This method returns an error in symmetric key schemes.
func (k *dilithium5PublicKey) PublicKey() (bccsp.Key, error) {
	return k, nil
}
