/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sw

import (
	"bytes"
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
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/hyperledger/fabric/bccsp"
)

// NewFileBasedKeyStore instantiated a file-based key store at a given position.
// The key store can be encrypted if a non-empty password is specified.
// It can be also be set as read only. In this case, any store operation
// will be forbidden
func NewFileBasedKeyStore(pwd []byte, path string, readOnly bool) (bccsp.KeyStore, error) {
	ks := &fileBasedKeyStore{}
	return ks, ks.Init(pwd, path, readOnly)
}

// fileBasedKeyStore is a folder-based KeyStore.
// Each key is stored in a separated file whose name contains the key's SKI
// and flags to identity the key's type. All the keys are stored in
// a folder whose path is provided at initialization time.
// The KeyStore can be initialized with a password, this password
// is used to encrypt and decrypt the files storing the keys.
// A KeyStore can be read only to avoid the overwriting of keys.
type fileBasedKeyStore struct {
	path string

	readOnly bool
	isOpen   bool

	pwd []byte

	// Sync
	m sync.Mutex
}

// Init initializes this KeyStore with a password, a path to a folder
// where the keys are stored and a read only flag.
// Each key is stored in a separated file whose name contains the key's SKI
// and flags to identity the key's type.
// If the KeyStore is initialized with a password, this password
// is used to encrypt and decrypt the files storing the keys.
// The pwd can be nil for non-encrypted KeyStores. If an encrypted
// key-store is initialized without a password, then retrieving keys from the
// KeyStore will fail.
// A KeyStore can be read only to avoid the overwriting of keys.
func (ks *fileBasedKeyStore) Init(pwd []byte, path string, readOnly bool) error {
	// Validate inputs
	// pwd can be nil

	if len(path) == 0 {
		return errors.New("an invalid KeyStore path provided. Path cannot be an empty string")
	}

	ks.m.Lock()
	defer ks.m.Unlock()

	if ks.isOpen {
		return errors.New("keystore is already initialized")
	}

	ks.path = path

	clone := make([]byte, len(pwd))
	copy(clone, pwd)
	ks.pwd = clone
	ks.readOnly = readOnly

	exists, err := dirExists(path)
	if err != nil {
		return err
	}
	if !exists {
		err = ks.createKeyStore()
		if err != nil {
			return err
		}
		return ks.openKeyStore()
	}

	empty, err := dirEmpty(path)
	if err != nil {
		return err
	}
	if empty {
		err = ks.createKeyStore()
		if err != nil {
			return err
		}
	}

	return ks.openKeyStore()
}

// ReadOnly returns true if this KeyStore is read only, false otherwise.
// If ReadOnly is true then StoreKey will fail.
func (ks *fileBasedKeyStore) ReadOnly() bool {
	return ks.readOnly
}

// GetKey returns a key object whose SKI is the one passed.
func (ks *fileBasedKeyStore) GetKey(ski []byte) (bccsp.Key, error) {
	// Validate arguments
	if len(ski) == 0 {
		return nil, errors.New("invalid SKI. Cannot be of zero length")
	}

	suffix := ks.getSuffix(hex.EncodeToString(ski))

	switch suffix {
	case "key":
		// Load the key
		key, err := ks.loadKey(hex.EncodeToString(ski))
		if err != nil {
			return nil, fmt.Errorf("failed loading key [%x] [%s]", ski, err)
		}

		return &aesPrivateKey{key, false}, nil
	case "sk":
		// Load the private key
		key, err := ks.loadPrivateKey(hex.EncodeToString(ski))
		if err != nil {
			return nil, fmt.Errorf("failed loading secret key [%x] [%s]", ski, err)
		}

		switch k := key.(type) {
		case *ecdsa.PrivateKey:
			return &ecdsaPrivateKey{k}, nil
		// Post quantum digital signatures
		// Falcon
		case *falcon512.PrivateKey:
			return &falcon512PrivateKey{k}, nil
		case *falcon1024.PrivateKey:
			return &falcon1024PrivateKey{k}, nil
		case *falcon512padded.PrivateKey:
			return &falcon512paddedPrivateKey{k}, nil
		case *falcon1024padded.PrivateKey:
			return &falcon1024paddedPrivateKey{k}, nil
		// Dilithium
		case *dilithium2.PrivateKey:
			return &dilithium2PrivateKey{k}, nil
		case *dilithium3.PrivateKey:
			return &dilithium3PrivateKey{k}, nil
		case *dilithium5.PrivateKey:
			return &dilithium5PrivateKey{k}, nil
		// Mayo
		case *mayo2.PrivateKey:
			return &mayo2PrivateKey{k}, nil
		case *mayo3.PrivateKey:
			return &mayo3PrivateKey{k}, nil
		case *mayo5.PrivateKey:
			return &mayo5PrivateKey{k}, nil
		// Snova
		case *snova2454.PrivateKey:
			return &snova2454PrivateKey{k}, nil
		case *snova2583.PrivateKey:
			return &snova2583PrivateKey{k}, nil
		case *snova2455.PrivateKey:
			return &snova2455PrivateKey{k}, nil
		case *snova2965.PrivateKey:
			return &snova2965PrivateKey{k}, nil
		// Uov
		case *ovip.PrivateKey:
			return &ovipPrivateKey{k}, nil
		case *oviii.PrivateKey:
			return &oviiiPrivateKey{k}, nil
		case *ovv.PrivateKey:
			return &ovvPrivateKey{k}, nil

		default:
			return nil, errors.New("secret key type not recognized")
		}
	case "pk":
		// Load the public key
		key, err := ks.loadPublicKey(hex.EncodeToString(ski))
		if err != nil {
			return nil, fmt.Errorf("failed loading public key [%x] [%s]", ski, err)
		}

		switch k := key.(type) {
		case *ecdsa.PublicKey:
			return &ecdsaPublicKey{k}, nil
		// Post quantum digital signatures
		// Falcon
		case falcon512.PublicKey:
			return &falcon512PublicKey{k}, nil
		case falcon1024.PublicKey:
			return &falcon1024PublicKey{k}, nil
		case falcon512padded.PublicKey:
			return &falcon512paddedPublicKey{k}, nil
		case falcon1024padded.PublicKey:
			return &falcon1024paddedPublicKey{k}, nil
		// Dilithium
		case dilithium2.PublicKey:
			return &dilithium2PublicKey{k}, nil
		case dilithium3.PublicKey:
			return &dilithium3PublicKey{k}, nil
		case dilithium5.PublicKey:
			return &dilithium5PublicKey{k}, nil
		// Mayo
		case mayo2.PublicKey:
			return &mayo2PublicKey{k}, nil
		case mayo3.PublicKey:
			return &mayo3PublicKey{k}, nil
		case mayo5.PublicKey:
			return &mayo5PublicKey{k}, nil
		// Snova
		case snova2454.PublicKey:
			return &snova2454PublicKey{k}, nil
		case snova2583.PublicKey:
			return &snova2583PublicKey{k}, nil
		case snova2455.PublicKey:
			return &snova2455PublicKey{k}, nil
		case snova2965.PublicKey:
			return &snova2965PublicKey{k}, nil
		// Uov
		case ovip.PublicKey:
			return &ovipPublicKey{k}, nil
		case oviii.PublicKey:
			return &oviiiPublicKey{k}, nil
		case ovv.PublicKey:
			return &ovvPublicKey{k}, nil
		default:
			return nil, errors.New("public key type not recognized")
		}
	default:
		return ks.searchKeystoreForSKI(ski)
	}
}

// StoreKey stores the key k in this KeyStore.
// If this KeyStore is read only then the method will fail.
func (ks *fileBasedKeyStore) StoreKey(k bccsp.Key) (err error) {
	if ks.readOnly {
		return errors.New("read only KeyStore")
	}

	if k == nil {
		return errors.New("invalid key. It must be different from nil")
	}
	switch kk := k.(type) {
	case *ecdsaPrivateKey:
		err = ks.storePrivateKey(hex.EncodeToString(k.SKI()), kk.privKey)
		if err != nil {
			return fmt.Errorf("failed storing ECDSA private key [%s]", err)
		}

	case *ecdsaPublicKey:
		err = ks.storePublicKey(hex.EncodeToString(k.SKI()), kk.pubKey)
		if err != nil {
			return fmt.Errorf("failed storing ECDSA public key [%s]", err)
		}

	case *aesPrivateKey:
		err = ks.storeKey(hex.EncodeToString(k.SKI()), kk.privKey)
		if err != nil {
			return fmt.Errorf("failed storing AES key [%s]", err)
		}
	// Post quantum digital signatures
	// Falcon
	case *falcon512PrivateKey:
		if kk.privKey == nil {
			return fmt.Errorf("Failed storing empty Falcon512 private key")
		}
		err = ks.storePrivateKey(hex.EncodeToString(k.SKI()), kk.privKey)
		if err != nil {
			return fmt.Errorf("failed storing Falcon512 private key [%s]", err)
		}

	case *falcon512PublicKey:
		if kk.pubKey == nil {
			return fmt.Errorf("Failed storing empty Falcon512 public key")
		}
		err = ks.storePublicKey(hex.EncodeToString(k.SKI()), kk.pubKey)
		if err != nil {
			return fmt.Errorf("failed storing Falcon512 public key [%s]", err)
		}

	case *falcon1024PrivateKey:
		if kk.privKey == nil {
			return fmt.Errorf("Failed storing empty Falcon1024 private key")
		}
		err = ks.storePrivateKey(hex.EncodeToString(k.SKI()), kk.privKey)
		if err != nil {
			return fmt.Errorf("failed storing Falcon1024 private key [%s]", err)
		}

	case *falcon1024PublicKey:
		if kk.pubKey == nil {
			return fmt.Errorf("Failed storing empty Falcon1024 public key")
		}
		err = ks.storePublicKey(hex.EncodeToString(k.SKI()), kk.pubKey)
		if err != nil {
			return fmt.Errorf("failed storing Falcon1024 public key [%s]", err)
		}

	case *falcon512paddedPrivateKey:
		if kk.privKey == nil {
			return fmt.Errorf("Failed storing empty Falcon512padded private key")
		}
		err = ks.storePrivateKey(hex.EncodeToString(k.SKI()), kk.privKey)
		if err != nil {
			return fmt.Errorf("failed storing Falcon512padded private key [%s]", err)
		}

	case *falcon512paddedPublicKey:
		if kk.pubKey == nil {
			return fmt.Errorf("Failed storing empty Falcon512padded public key")
		}
		err = ks.storePublicKey(hex.EncodeToString(k.SKI()), kk.pubKey)
		if err != nil {
			return fmt.Errorf("failed storing Falcon512padded public key [%s]", err)
		}

	case *falcon1024paddedPrivateKey:
		if kk.privKey == nil {
			return fmt.Errorf("Failed storing empty Falcon1024padded private key")
		}
		err = ks.storePrivateKey(hex.EncodeToString(k.SKI()), kk.privKey)
		if err != nil {
			return fmt.Errorf("failed storing Falcon1024padded private key [%s]", err)
		}

	case *falcon1024paddedPublicKey:
		if kk.pubKey == nil {
			return fmt.Errorf("Failed storing empty Falcon1024padded public key")
		}
		err = ks.storePublicKey(hex.EncodeToString(k.SKI()), kk.pubKey)
		if err != nil {
			return fmt.Errorf("failed storing Falcon1024padded public key [%s]", err)
		}

	// Dilithium
	case *dilithium2PrivateKey:
		if kk.privKey == nil {
			return fmt.Errorf("Failed storing empty Dilithium2 private key")
		}
		err = ks.storePrivateKey(hex.EncodeToString(k.SKI()), kk.privKey)
		if err != nil {
			return fmt.Errorf("failed storing Dilithium2 private key [%s]", err)
		}

	case *dilithium2PublicKey:
		if kk.pubKey == nil {
			return fmt.Errorf("Failed storing empty Dilithium2 public key")
		}
		err = ks.storePublicKey(hex.EncodeToString(k.SKI()), kk.pubKey)
		if err != nil {
			return fmt.Errorf("failed storing Dilithium2 public key [%s]", err)
		}

	case *dilithium3PrivateKey:
		if kk.privKey == nil {
			return fmt.Errorf("Failed storing empty Dilithium3 private key")
		}
		err = ks.storePrivateKey(hex.EncodeToString(k.SKI()), kk.privKey)
		if err != nil {
			return fmt.Errorf("failed storing Dilithium3 private key [%s]", err)
		}

	case *dilithium3PublicKey:
		if kk.pubKey == nil {
			return fmt.Errorf("Failed storing empty Dilithium3 public key")
		}
		err = ks.storePublicKey(hex.EncodeToString(k.SKI()), kk.pubKey)
		if err != nil {
			return fmt.Errorf("failed storing Dilithium3 public key [%s]", err)
		}

	case *dilithium5PrivateKey:
		if kk.privKey == nil {
			return fmt.Errorf("Failed storing empty Dilithium5 private key")
		}
		err = ks.storePrivateKey(hex.EncodeToString(k.SKI()), kk.privKey)
		if err != nil {
			return fmt.Errorf("failed storing Dilithium5 private key [%s]", err)
		}

	case *dilithium5PublicKey:
		if kk.pubKey == nil {
			return fmt.Errorf("Failed storing empty Dilithium5 public key")
		}
		err = ks.storePublicKey(hex.EncodeToString(k.SKI()), kk.pubKey)
		if err != nil {
			return fmt.Errorf("failed storing Dilithium5 public key [%s]", err)
		}

	// Mayo
	case *mayo2PrivateKey:
		if kk.privKey == nil {
			return fmt.Errorf("Failed storing empty Mayo2 private key")
		}
		err = ks.storePrivateKey(hex.EncodeToString(k.SKI()), kk.privKey)
		if err != nil {
			return fmt.Errorf("failed storing Mayo2 private key [%s]", err)
		}

	case *mayo2PublicKey:
		if kk.pubKey == nil {
			return fmt.Errorf("Failed storing empty Mayo2 public key")
		}
		err = ks.storePublicKey(hex.EncodeToString(k.SKI()), kk.pubKey)
		if err != nil {
			return fmt.Errorf("failed storing Mayo2 public key [%s]", err)
		}

	case *mayo3PrivateKey:
		if kk.privKey == nil {
			return fmt.Errorf("Failed storing empty Mayo3 private key")
		}
		err = ks.storePrivateKey(hex.EncodeToString(k.SKI()), kk.privKey)
		if err != nil {
			return fmt.Errorf("failed storing Mayo3 private key [%s]", err)
		}

	case *mayo3PublicKey:
		if kk.pubKey == nil {
			return fmt.Errorf("Failed storing empty Mayo3 public key")
		}
		err = ks.storePublicKey(hex.EncodeToString(k.SKI()), kk.pubKey)
		if err != nil {
			return fmt.Errorf("failed storing Mayo3 public key [%s]", err)
		}

	case *mayo5PrivateKey:
		if kk.privKey == nil {
			return fmt.Errorf("Failed storing empty Mayo5 private key")
		}
		err = ks.storePrivateKey(hex.EncodeToString(k.SKI()), kk.privKey)
		if err != nil {
			return fmt.Errorf("failed storing Mayo5 private key [%s]", err)
		}

	case *mayo5PublicKey:
		if kk.pubKey == nil {
			return fmt.Errorf("Failed storing empty Mayo5 public key")
		}
		err = ks.storePublicKey(hex.EncodeToString(k.SKI()), kk.pubKey)
		if err != nil {
			return fmt.Errorf("failed storing Mayo5 public key [%s]", err)
		}

	// Snova
	case *snova2454PrivateKey:
		if kk.privKey == nil {
			return fmt.Errorf("Failed storing empty Snova2454 private key")
		}
		err = ks.storePrivateKey(hex.EncodeToString(k.SKI()), kk.privKey)
		if err != nil {
			return fmt.Errorf("failed storing Snova2454 private key [%s]", err)
		}

	case *snova2454PublicKey:
		if kk.pubKey == nil {
			return fmt.Errorf("Failed storing empty Snova2454 public key")
		}
		err = ks.storePublicKey(hex.EncodeToString(k.SKI()), kk.pubKey)
		if err != nil {
			return fmt.Errorf("failed storing Snova2454 public key [%s]", err)
		}

	case *snova2583PrivateKey:
		if kk.privKey == nil {
			return fmt.Errorf("Failed storing empty Snova2583 private key")
		}
		err = ks.storePrivateKey(hex.EncodeToString(k.SKI()), kk.privKey)
		if err != nil {
			return fmt.Errorf("failed storing Snova2583 private key [%s]", err)
		}

	case *snova2583PublicKey:
		if kk.pubKey == nil {
			return fmt.Errorf("Failed storing empty Snova2583 public key")
		}
		err = ks.storePublicKey(hex.EncodeToString(k.SKI()), kk.pubKey)
		if err != nil {
			return fmt.Errorf("failed storing Snova2583 public key [%s]", err)
		}

	case *snova2455PrivateKey:
		if kk.privKey == nil {
			return fmt.Errorf("Failed storing empty Snova2455 private key")
		}
		err = ks.storePrivateKey(hex.EncodeToString(k.SKI()), kk.privKey)
		if err != nil {
			return fmt.Errorf("failed storing Snova2455 private key [%s]", err)
		}

	case *snova2455PublicKey:
		if kk.pubKey == nil {
			return fmt.Errorf("Failed storing empty Snova2455 public key")
		}
		err = ks.storePublicKey(hex.EncodeToString(k.SKI()), kk.pubKey)
		if err != nil {
			return fmt.Errorf("failed storing Snova2455 public key [%s]", err)
		}

	case *snova2965PrivateKey:
		if kk.privKey == nil {
			return fmt.Errorf("Failed storing empty Snova2965 private key")
		}
		err = ks.storePrivateKey(hex.EncodeToString(k.SKI()), kk.privKey)
		if err != nil {
			return fmt.Errorf("failed storing Snova2965 private key [%s]", err)
		}

	case *snova2965PublicKey:
		if kk.pubKey == nil {
			return fmt.Errorf("Failed storing empty Snova2965 public key")
		}
		err = ks.storePublicKey(hex.EncodeToString(k.SKI()), kk.pubKey)
		if err != nil {
			return fmt.Errorf("failed storing Snova2965 public key [%s]", err)
		}

	// Uov
	case *ovipPrivateKey:
		if kk.privKey == nil {
			return fmt.Errorf("Failed storing empty Ovip private key")
		}
		err = ks.storePrivateKey(hex.EncodeToString(k.SKI()), kk.privKey)
		if err != nil {
			return fmt.Errorf("failed storing Ovip private key [%s]", err)
		}

	case *ovipPublicKey:
		if kk.pubKey == nil {
			return fmt.Errorf("Failed storing empty Ovip public key")
		}
		err = ks.storePublicKey(hex.EncodeToString(k.SKI()), kk.pubKey)
		if err != nil {
			return fmt.Errorf("failed storing Ovip public key [%s]", err)
		}
	case *oviiiPrivateKey:
		if kk.privKey == nil {
			return fmt.Errorf("Failed storing empty Oviii private key")
		}
		err = ks.storePrivateKey(hex.EncodeToString(k.SKI()), kk.privKey)
		if err != nil {
			return fmt.Errorf("failed storing Oviii private key [%s]", err)
		}

	case *oviiiPublicKey:
		if kk.pubKey == nil {
			return fmt.Errorf("Failed storing empty Oviii public key")
		}
		err = ks.storePublicKey(hex.EncodeToString(k.SKI()), kk.pubKey)
		if err != nil {
			return fmt.Errorf("failed storing Oviii public key [%s]", err)
		}
	case *ovvPrivateKey:
		if kk.privKey == nil {
			return fmt.Errorf("Failed storing empty Ovv private key")
		}
		err = ks.storePrivateKey(hex.EncodeToString(k.SKI()), kk.privKey)
		if err != nil {
			return fmt.Errorf("failed storing Ovv private key [%s]", err)
		}

	case *ovvPublicKey:
		if kk.pubKey == nil {
			return fmt.Errorf("Failed storing empty Ovv public key")
		}
		err = ks.storePublicKey(hex.EncodeToString(k.SKI()), kk.pubKey)
		if err != nil {
			return fmt.Errorf("failed storing Ovv public key [%s]", err)
		}

	default:
		return fmt.Errorf("key type not reconigned [%s]", k)
	}

	return
}

func (ks *fileBasedKeyStore) searchKeystoreForSKI(ski []byte) (k bccsp.Key, err error) {
	//fmt.Println("Inside searchKeyStoreForSKI in fielks.go  ", ski)
	files, _ := ioutil.ReadDir(ks.path)
	for _, f := range files {
		if f.IsDir() {
			continue
		}

		if f.Size() > (1 << 16) { // 64k, somewhat arbitrary limit, considering even large keys
			continue
		}

		raw, err := ioutil.ReadFile(filepath.Join(ks.path, f.Name()))
		if err != nil {
			continue
		}

		key, err := pemToPrivateKey(raw, ks.pwd)
		if err != nil {
			continue
		}

		switch kk := key.(type) {
		case *ecdsa.PrivateKey:
			k = &ecdsaPrivateKey{kk}
		// Post quantum digital signatures
		// Falcon
		case *falcon512.PrivateKey:
			k = &falcon512PrivateKey{kk}
		case *falcon1024.PrivateKey:
			k = &falcon1024PrivateKey{kk}
		case *falcon512padded.PrivateKey:
			k = &falcon512paddedPrivateKey{kk}
		case *falcon1024padded.PrivateKey:
			k = &falcon1024paddedPrivateKey{kk}
		// Dilithium
		case *dilithium2.PrivateKey:
			k = &dilithium2PrivateKey{kk}
		case *dilithium3.PrivateKey:
			k = &dilithium3PrivateKey{kk}
		case *dilithium5.PrivateKey:
			k = &dilithium5PrivateKey{kk}
		// Mayo
		case *mayo2.PrivateKey:
			k = &mayo2PrivateKey{kk}
		case *mayo3.PrivateKey:
			k = &mayo3PrivateKey{kk}
		case *mayo5.PrivateKey:
			k = &mayo5PrivateKey{kk}
		// Snova
		case *snova2454.PrivateKey:
			k = &snova2454PrivateKey{kk}
		case *snova2583.PrivateKey:
			k = &snova2583PrivateKey{kk}
		case *snova2455.PrivateKey:
			k = &snova2455PrivateKey{kk}
		case *snova2965.PrivateKey:
			k = &snova2965PrivateKey{kk}
		// Uov
		case *ovip.PrivateKey:
			k = &ovipPrivateKey{kk}
		case *oviii.PrivateKey:
			k = &oviiiPrivateKey{kk}
		case *ovv.PrivateKey:
			k = &ovvPrivateKey{kk}

		default:
			//fmt.Println("Inside searchKeyStoreForSKI in fielks.go   ", "inside default in cases and the SKI is")
			continue
		}

		if !bytes.Equal(k.SKI(), ski) {
			//fmt.Println("Inside searchKeyStoreForSKI in fielks.go, inside cheching equal bytes", "key ski: ", k.SKI(), "ski: ", ski)
			continue
		}

		return k, nil
	}
	return nil, fmt.Errorf("key with SKI %x not found in %s", ski, ks.path)
}

func (ks *fileBasedKeyStore) getSuffix(alias string) string {
	files, _ := ioutil.ReadDir(ks.path)
	for _, f := range files {
		if strings.HasPrefix(f.Name(), alias) {
			if strings.HasSuffix(f.Name(), "sk") {
				return "sk"
			}
			if strings.HasSuffix(f.Name(), "pk") {
				return "pk"
			}
			if strings.HasSuffix(f.Name(), "key") {
				return "key"
			}
			break
		}
	}
	return ""
}

func (ks *fileBasedKeyStore) storePrivateKey(alias string, privateKey interface{}) error {
	rawKey, err := privateKeyToPEM(privateKey, ks.pwd)
	if err != nil {
		logger.Errorf("Failed converting private key to PEM [%s]: [%s]", alias, err)
		return err
	}

	err = ioutil.WriteFile(ks.getPathForAlias(alias, "sk"), rawKey, 0o600)
	if err != nil {
		logger.Errorf("Failed storing private key [%s]: [%s]", alias, err)
		return err
	}

	return nil
}

func (ks *fileBasedKeyStore) storePublicKey(alias string, publicKey interface{}) error {
	rawKey, err := publicKeyToPEM(publicKey, ks.pwd)
	if err != nil {
		logger.Errorf("Failed converting public key to PEM [%s]: [%s]", alias, err)
		return err
	}

	err = ioutil.WriteFile(ks.getPathForAlias(alias, "pk"), rawKey, 0o600)
	if err != nil {
		logger.Errorf("Failed storing private key [%s]: [%s]", alias, err)
		return err
	}

	return nil
}

func (ks *fileBasedKeyStore) storeKey(alias string, key []byte) error {
	pem, err := aesToEncryptedPEM(key, ks.pwd)
	if err != nil {
		logger.Errorf("Failed converting key to PEM [%s]: [%s]", alias, err)
		return err
	}

	err = ioutil.WriteFile(ks.getPathForAlias(alias, "key"), pem, 0o600)
	if err != nil {
		logger.Errorf("Failed storing key [%s]: [%s]", alias, err)
		return err
	}

	return nil
}

func (ks *fileBasedKeyStore) loadPrivateKey(alias string) (interface{}, error) {
	path := ks.getPathForAlias(alias, "sk")
	logger.Debugf("Loading private key [%s] at [%s]...", alias, path)

	raw, err := ioutil.ReadFile(path)
	if err != nil {
		logger.Errorf("Failed loading private key [%s]: [%s].", alias, err.Error())

		return nil, err
	}

	privateKey, err := pemToPrivateKey(raw, ks.pwd)
	if err != nil {
		logger.Errorf("Failed parsing private key [%s]: [%s].", alias, err.Error())

		return nil, err
	}

	return privateKey, nil
}

func (ks *fileBasedKeyStore) loadPublicKey(alias string) (interface{}, error) {
	path := ks.getPathForAlias(alias, "pk")
	logger.Debugf("Loading public key [%s] at [%s]...", alias, path)

	raw, err := ioutil.ReadFile(path)
	if err != nil {
		logger.Errorf("Failed loading public key [%s]: [%s].", alias, err.Error())

		return nil, err
	}

	privateKey, err := pemToPublicKey(raw, ks.pwd)
	if err != nil {
		logger.Errorf("Failed parsing private key [%s]: [%s].", alias, err.Error())

		return nil, err
	}

	return privateKey, nil
}

func (ks *fileBasedKeyStore) loadKey(alias string) ([]byte, error) {
	path := ks.getPathForAlias(alias, "key")
	logger.Debugf("Loading key [%s] at [%s]...", alias, path)

	pem, err := ioutil.ReadFile(path)
	if err != nil {
		logger.Errorf("Failed loading key [%s]: [%s].", alias, err.Error())

		return nil, err
	}

	key, err := pemToAES(pem, ks.pwd)
	if err != nil {
		logger.Errorf("Failed parsing key [%s]: [%s]", alias, err)

		return nil, err
	}

	return key, nil
}

func (ks *fileBasedKeyStore) createKeyStore() error {
	// Create keystore directory root if it doesn't exist yet
	ksPath := ks.path
	logger.Debugf("Creating KeyStore at [%s]...", ksPath)

	err := os.MkdirAll(ksPath, 0o755)
	if err != nil {
		return err
	}

	logger.Debugf("KeyStore created at [%s].", ksPath)
	return nil
}

func (ks *fileBasedKeyStore) openKeyStore() error {
	if ks.isOpen {
		return nil
	}
	ks.isOpen = true
	logger.Debugf("KeyStore opened at [%s]...done", ks.path)

	return nil
}

func (ks *fileBasedKeyStore) getPathForAlias(alias, suffix string) string {
	return filepath.Join(ks.path, alias+"_"+suffix)
}

func dirExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func dirEmpty(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()

	_, err = f.Readdir(1)
	if err == io.EOF {
		return true, nil
	}
	return false, err
}
