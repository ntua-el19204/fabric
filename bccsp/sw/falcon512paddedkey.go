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
	"crypto/pqc/falcon/falcon512padded"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/hyperledger/fabric/bccsp"
)

type falcon512paddedPrivateKey struct {
	privKey *falcon512padded.PrivateKey
}

// Bytes converts this key to its byte representation,
// if this operation is allowed.
func (k *falcon512paddedPrivateKey) Bytes() ([]byte, error) {
	return nil, errors.New("Not supported.")
}

// SKI returns the subject key identifier of this key.
func (k *falcon512paddedPrivateKey) SKI() []byte {
	if k.privKey == nil {
		return nil
	}
	hash := sha256.New()
	hash.Write(k.privKey.PublicKey)
	return hash.Sum(nil)
}

// Symmetric returns true if this key is a symmetric key,
// false if this key is asymmetric
func (k *falcon512paddedPrivateKey) Symmetric() bool {
	return false
}

// Private returns true if this key is a private key,
// false otherwise.
func (k *falcon512paddedPrivateKey) Private() bool {
	return true
}

// PublicKey returns the corresponding public key part of an asymmetric public/private key pair.
// This method returns an error in symmetric key schemes.
func (k *falcon512paddedPrivateKey) PublicKey() (bccsp.Key, error) {
	return &falcon512paddedPublicKey{k.privKey.PublicKey}, nil
}

type falcon512paddedPublicKey struct {
	pubKey falcon512padded.PublicKey
}

// Bytes converts this key to its byte representation,
// if this operation is allowed.
func (k *falcon512paddedPublicKey) Bytes() (raw []byte, err error) {
	raw, err = x509.MarshalPKIXPublicKey(k.pubKey)
	if err != nil {
		//fmt.Printf("Marshalling error: %v\n", err)
		return nil, fmt.Errorf("Failed marshalling key [%s]", err)

	}
	return
}

// SKI returns the subject key identifier of this key.
func (k *falcon512paddedPublicKey) SKI() []byte {
	if k.pubKey == nil {
		return nil
	}
	hash := sha256.New()
	hash.Write(k.pubKey)
	ski := hash.Sum(nil)
	//fmt.Printf("DEBUG: Generated SKI for Dilithium5 key: %x\n", ski) // Add this
	return ski
}

// Symmetric returns true if this key is a symmetric key,
// false if this key is asymmetric
func (k *falcon512paddedPublicKey) Symmetric() bool {
	return false
}

// Private returns true if this key is a private key,
// false otherwise.
func (k falcon512paddedPublicKey) Private() bool {
	return false
}

// PublicKey returns the corresponding public key part of an asymmetric public/private key pair.
// This method returns an error in symmetric key schemes.
func (k *falcon512paddedPublicKey) PublicKey() (bccsp.Key, error) {
	return k, nil
}
