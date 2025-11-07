/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package msp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
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
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"github.com/hyperledger/fabric/internal/cryptogen/ca"
	"github.com/hyperledger/fabric/internal/cryptogen/csp"
	fabricmsp "github.com/hyperledger/fabric/msp"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v3"
)

const (
	CLIENT = iota
	ORDERER
	PEER
	ADMIN
)

const (
	CLIENTOU  = "client"
	PEEROU    = "peer"
	ADMINOU   = "admin"
	ORDEREROU = "orderer"
)

var nodeOUMap = map[int]string{
	CLIENT:  CLIENTOU,
	PEER:    PEEROU,
	ADMIN:   ADMINOU,
	ORDERER: ORDEREROU,
}

func GenerateLocalMSP(
	baseDir,
	name string,
	sans []string,
	signCA *ca.CA,
	tlsCA *ca.CA,
	nodeType int,
	nodeOUs bool,
	keyAlg string,
) error {
	//fmt.Println("Inside Generate Local MSP")
	//fmt.Println("The keyalg alg is ", keyAlg)
	// create folder structure
	mspDir := filepath.Join(baseDir, "msp")
	tlsDir := filepath.Join(baseDir, "tls")

	err := createFolderStructure(mspDir, true)
	if err != nil {
		return err
	}

	err = os.MkdirAll(tlsDir, 0o755)
	if err != nil {
		return err
	}

	/*
		Create the MSP identity artifacts
	*/
	// get keystore path
	keystore := filepath.Join(mspDir, "keystore")

	// generate private key
	priv, err := csp.GeneratePrivateKey(keystore, keyAlg)
	if err != nil {
		return err
	}

	//fmt.Println("Private Key is ", priv)
	//fmt.Println()
	//fmt.Println("Public Key is ", getPublicKey(priv))
	//fmt.Println()

	// generate X509 certificate using signing CA
	var ous []string
	if nodeOUs {
		ous = []string{nodeOUMap[nodeType]}
	}
	cert, err := signCA.SignCertificate(
		filepath.Join(mspDir, "signcerts"),
		name,
		ous,
		nil,
		getPublicKey(priv),
		x509.KeyUsageDigitalSignature,
		[]x509.ExtKeyUsage{},
	)
	if err != nil {
		fmt.Println("Error in Sign Certificate")
		return err
	}

	// write artifacts to MSP folders

	// the signing CA certificate goes into cacerts
	err = x509Export(
		filepath.Join(mspDir, "cacerts", x509Filename(signCA.Name)),
		signCA.SignCert,
	)
	if err != nil {
		fmt.Println("Error in x509 export")
		return err
	}
	// the TLS CA certificate goes into tlscacerts
	err = x509Export(
		filepath.Join(mspDir, "tlscacerts", x509Filename(tlsCA.Name)),
		tlsCA.SignCert,
	)
	if err != nil {
		fmt.Println("Error in x509 export")
		return err
	}

	// generate config.yaml if required
	if nodeOUs {
		exportConfig(mspDir, filepath.Join("cacerts", x509Filename(signCA.Name)), true)
	}

	// the signing identity goes into admincerts.
	// This means that the signing identity
	// of this MSP is also an admin of this MSP
	// NOTE: the admincerts folder is going to be
	// cleared up anyway by copyAdminCert, but
	// we leave a valid admin for now for the sake
	// of unit tests
	if !nodeOUs {
		err = x509Export(filepath.Join(mspDir, "admincerts", x509Filename(name)), cert)
		if err != nil {
			return err
		}
	}

	/*
		Generate the TLS artifacts in the TLS folder
	*/

	// generate private key
	tlsPrivKey, err := csp.GeneratePrivateKey(tlsDir, "ecdsa")
	if err != nil {
		return err
	}

	// generate X509 certificate using TLS CA
	_, err = tlsCA.SignCertificate(
		filepath.Join(tlsDir),
		name,
		nil,
		sans,
		getPublicKey(tlsPrivKey),
		x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment,
		[]x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
	)
	if err != nil {
		return err
	}
	err = x509Export(filepath.Join(tlsDir, "ca.crt"), tlsCA.SignCert)
	if err != nil {
		return err
	}

	// rename the generated TLS X509 cert
	tlsFilePrefix := "server"
	if nodeType == CLIENT || nodeType == ADMIN {
		tlsFilePrefix = "client"
	}
	err = os.Rename(filepath.Join(tlsDir, x509Filename(name)),
		filepath.Join(tlsDir, tlsFilePrefix+".crt"))
	if err != nil {
		return err
	}

	err = keyExport(tlsDir, filepath.Join(tlsDir, tlsFilePrefix+".key"))
	if err != nil {
		return err
	}

	return nil
}

func GenerateVerifyingMSP(
	baseDir string,
	signCA,
	tlsCA *ca.CA,
	nodeOUs bool,
	keyAlg string,
) error {
	// create folder structure and write artifacts to proper locations
	err := createFolderStructure(baseDir, false)
	if err != nil {
		return err
	}
	// the signing CA certificate goes into cacerts
	err = x509Export(
		filepath.Join(baseDir, "cacerts", x509Filename(signCA.Name)),
		signCA.SignCert,
	)
	if err != nil {
		return err
	}
	// the TLS CA certificate goes into tlscacerts
	err = x509Export(
		filepath.Join(baseDir, "tlscacerts", x509Filename(tlsCA.Name)),
		tlsCA.SignCert,
	)
	if err != nil {
		return err
	}

	// generate config.yaml if required
	if nodeOUs {
		exportConfig(baseDir, "cacerts/"+x509Filename(signCA.Name), true)
	}

	// create a throwaway cert to act as an admin cert
	// NOTE: the admincerts folder is going to be
	// cleared up anyway by copyAdminCert, but
	// we leave a valid admin for now for the sake
	// of unit tests
	if nodeOUs {
		return nil
	}

	ksDir := filepath.Join(baseDir, "keystore")
	err = os.Mkdir(ksDir, 0o755)
	defer os.RemoveAll(ksDir)
	if err != nil {
		return errors.WithMessage(err, "failed to create keystore directory")
	}
	priv, err := csp.GeneratePrivateKey(ksDir, keyAlg)
	if err != nil {
		return err
	}
	_, err = signCA.SignCertificate(
		filepath.Join(baseDir, "admincerts"),
		signCA.Name,
		nil,
		nil,
		getPublicKey(priv),
		x509.KeyUsageDigitalSignature,
		[]x509.ExtKeyUsage{},
	)
	if err != nil {
		return err
	}

	return nil
}

func createFolderStructure(rootDir string, local bool) error {
	var folders []string
	// create admincerts, cacerts, keystore and signcerts folders
	folders = []string{
		filepath.Join(rootDir, "admincerts"),
		filepath.Join(rootDir, "cacerts"),
		filepath.Join(rootDir, "tlscacerts"),
	}
	if local {
		folders = append(folders, filepath.Join(rootDir, "keystore"),
			filepath.Join(rootDir, "signcerts"))
	}

	for _, folder := range folders {
		err := os.MkdirAll(folder, 0o755)
		if err != nil {
			return err
		}
	}

	return nil
}

func getPublicKey(priv crypto.PrivateKey) crypto.PublicKey {
	switch kk := priv.(type) {
	case *ecdsa.PrivateKey:
		return &(kk.PublicKey)
	case ed25519.PrivateKey:
		return kk.Public()
	// Post quantum digital signatures
	// Falcon
	case *falcon512.PrivateKey:
		return (kk.PublicKey)
	case *falcon1024.PrivateKey:
		return (kk.PublicKey)
	case *falcon512padded.PrivateKey:
		return (kk.PublicKey)
	case *falcon1024padded.PrivateKey:
		return (kk.PublicKey)
	// Dilithium
	case *dilithium2.PrivateKey:
		return (kk.PublicKey)
	case *dilithium3.PrivateKey:
		return (kk.PublicKey)
	case *dilithium5.PrivateKey:
		return (kk.PublicKey)
	// Mayo
	case *mayo2.PrivateKey:
		return (kk.PublicKey)
	case *mayo3.PrivateKey:
		return (kk.PublicKey)
	case *mayo5.PrivateKey:
		return (kk.PublicKey)
	// Snova
	case *snova2454.PrivateKey:
		return (kk.PublicKey)
	case *snova2583.PrivateKey:
		return (kk.PublicKey)
	case *snova2455.PrivateKey:
		return (kk.PublicKey)
	case *snova2965.PrivateKey:
		return (kk.PublicKey)
	// UOV
	case *ovip.PrivateKey:
		return (kk.PublicKey)
	case *oviii.PrivateKey:
		return (kk.PublicKey)
	case *ovv.PrivateKey:
		return (kk.PublicKey)

	default:
		panic("unsupported key algorithm")
	}
}

func x509Filename(name string) string {
	return name + "-cert.pem"
}

func x509Export(path string, cert *x509.Certificate) error {
	return pemExport(path, "CERTIFICATE", cert.Raw)
}

func keyExport(keystore, output string) error {
	return os.Rename(filepath.Join(keystore, "priv_sk"), output)
}

func pemExport(path, pemType string, bytes []byte) error {
	// write pem out to file
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	return pem.Encode(file, &pem.Block{Type: pemType, Bytes: bytes})
}

func exportConfig(mspDir, caFile string, enable bool) error {
	config := &fabricmsp.Configuration{
		NodeOUs: &fabricmsp.NodeOUs{
			Enable: enable,
			ClientOUIdentifier: &fabricmsp.OrganizationalUnitIdentifiersConfiguration{
				Certificate:                  caFile,
				OrganizationalUnitIdentifier: CLIENTOU,
			},
			PeerOUIdentifier: &fabricmsp.OrganizationalUnitIdentifiersConfiguration{
				Certificate:                  caFile,
				OrganizationalUnitIdentifier: PEEROU,
			},
			AdminOUIdentifier: &fabricmsp.OrganizationalUnitIdentifiersConfiguration{
				Certificate:                  caFile,
				OrganizationalUnitIdentifier: ADMINOU,
			},
			OrdererOUIdentifier: &fabricmsp.OrganizationalUnitIdentifiersConfiguration{
				Certificate:                  caFile,
				OrganizationalUnitIdentifier: ORDEREROU,
			},
		},
	}

	configBytes, err := yaml.Marshal(config)
	if err != nil {
		return err
	}

	file, err := os.Create(filepath.Join(mspDir, "config.yaml"))
	if err != nil {
		return err
	}

	defer file.Close()
	_, err = file.WriteString(string(configBytes))

	return err
}
