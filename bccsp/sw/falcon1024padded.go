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
	"crypto/rand"

	"github.com/hyperledger/fabric/bccsp"
)

type falcon1024paddedSigner struct{}

func (s *falcon1024paddedSigner) Sign(k bccsp.Key, digest []byte, opts bccsp.SignerOpts) ([]byte, error) {
	return k.(*falcon1024paddedPrivateKey).privKey.Sign(rand.Reader, digest, opts)
}

type falcon1024paddedPrivateKeyVerifier struct{}

func (v *falcon1024paddedPrivateKeyVerifier) Verify(k bccsp.Key, signature, digest []byte, opts bccsp.SignerOpts) (bool, error) {
	return false, nil
}

type falcon1024paddedPublicKeyKeyVerifier struct{}

func (v *falcon1024paddedPublicKeyKeyVerifier) Verify(k bccsp.Key, signature, digest []byte, opts bccsp.SignerOpts) (bool, error) {
	return k.(*falcon1024paddedPublicKey).pubKey.Verify(digest, signature), nil
}
