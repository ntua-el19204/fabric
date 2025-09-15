/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package msp

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"

	"github.com/hyperledger/fabric/internal/cryptogen/ca"
	"github.com/hyperledger/fabric/internal/cryptogen/csp"
	fabricmsp "github.com/hyperledger/fabric/msp"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
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
) error {
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

	// generate X509 certificate using signing CA
	var cert *x509.Certificate
	var ous []string
	if nodeOUs {
		ous = []string{nodeOUMap[nodeType]}
	}
	if nodeType == CLIENT || nodeType == ADMIN {
		// --- Client/Admin: ECDSA identity ---
		ecdsaPriv, err := csp.GeneratePrivateKey(keystore)
		if err != nil {
			return err
		}

		// Issue the MSP signcert with an ECDSA CA (reuse tlsCA or a dedicated ECDSA identity CA)
		// NOTE: adjust method name to match your ca.CA (see note below)
		cert, err = tlsCA.SignCertificate(
			filepath.Join(mspDir, "signcerts"),
			name,
			ous,
			nil,
			&ecdsaPriv.PublicKey,
			x509.KeyUsageDigitalSignature,
			nil,
		)
		if err != nil {
			return err
		}

	} else {
		// --- Peer/Orderer: Dilithium identity ---
		dilPriv, err := csp.GenerateDilithium5PrivateKey(keystore)
		if err != nil {
			return err
		}

		// NOTE: adjust method name to match your ca.CA
		cert, err = signCA.SignDilithium5Certificate(
			filepath.Join(mspDir, "signcerts"),
			name,
			ous,
			nil,
			dilPriv.PublicKey,
			x509.KeyUsageDigitalSignature,
			nil,
		)
		if err != nil {
			return err
		}
	}
	// write artifacts to MSP folders

	// the signing CA certificate goes into cacerts
	err = x509Export(
		filepath.Join(mspDir, "cacerts", x509Filename(signCA.Name)),
		signCA.SignCert,
	)
	if err != nil {
		return err
	}
	err = x509Export(
		filepath.Join(mspDir, "cacerts", x509Filename(tlsCA.Name)),
		tlsCA.SignCert,
	)
	if err != nil {
		return err
	}
	// the TLS CA certificate goes into tlscacerts
	err = x509Export(
		filepath.Join(mspDir, "tlscacerts", x509Filename(tlsCA.Name)),
		tlsCA.SignCert,
	)
	if err != nil {
		return err
	}

	// generate config.yaml if required
	// ---- Mixed NodeOUs config ----
	if nodeOUs {
		// ECDSA CA for Client/Admin, Dilithium CA for Peer/Orderer
		if err := exportMixedNodeOUs(
			mspDir,
			filepath.Join("cacerts", x509Filename(tlsCA.Name)),  // ECDSA CA file
			filepath.Join("cacerts", x509Filename(signCA.Name)), // Dilithium CA file
		); err != nil {
			return err
		}
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
	tlsPrivKey, err := csp.GeneratePrivateKey(tlsDir)
	if err != nil {
		return err
	}

	// generate X509 certificate using TLS CA
	_, err = tlsCA.SignCertificate(
		filepath.Join(tlsDir),
		name,
		nil,
		sans,
		&tlsPrivKey.PublicKey,
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

func GenerateVerifyingMSP(baseDir string, signCA, tlsCA *ca.CA, nodeOUs bool) error {
	// create folder structure
	if err := createFolderStructure(baseDir, false); err != nil {
		return err
	}

	// --- Put BOTH identity CAs in cacerts ---
	if err := x509Export(
		filepath.Join(baseDir, "cacerts", x509Filename(signCA.Name)),
		signCA.SignCert,
	); err != nil {
		return err
	}

	if err := x509Export(
		filepath.Join(baseDir, "cacerts", x509Filename(tlsCA.Name)),
		tlsCA.SignCert,
	); err != nil {
		return err
	}

	// --- TLS trust root into tlscacerts (as you already do) ---
	if err := x509Export(
		filepath.Join(baseDir, "tlscacerts", x509Filename(tlsCA.Name)),
		tlsCA.SignCert,
	); err != nil {
		return err
	}

	// --- NodeOUs config ---
	if nodeOUs {
		// ECDSA for Client/Admin, Dilithium for Peer/Orderer
		return exportMixedNodeOUs(
			baseDir,
			filepath.Join("cacerts", x509Filename(tlsCA.Name)),  // ECDSA CA
			filepath.Join("cacerts", x509Filename(signCA.Name)), // Dilithium CA
		)
	}

	// --- nodeOUs == false: create throwaway admin (make it ECDSA & issue with ECDSA CA) ---
	ksDir := filepath.Join(baseDir, "keystore")
	if err := os.Mkdir(ksDir, 0o755); err != nil {
		return errors.WithMessage(err, "failed to create keystore directory")
	}
	defer os.RemoveAll(ksDir)

	ecdsaPriv, err := csp.GeneratePrivateKey(ksDir)
	if err != nil {
		return err
	}

	// If your ECDSA method is SignCertificateECDSA, use that here
	if _, err := tlsCA.SignCertificate(
		filepath.Join(baseDir, "admincerts"),
		tlsCA.Name,
		nil,
		nil,
		&ecdsaPriv.PublicKey,
		x509.KeyUsageDigitalSignature,
		[]x509.ExtKeyUsage{},
	); err != nil {
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

func exportMixedNodeOUs(mspDir, ecdsaCAFile, dilCAFile string) error {
	cfg := &fabricmsp.Configuration{
		NodeOUs: &fabricmsp.NodeOUs{
			Enable: true,
			ClientOUIdentifier: &fabricmsp.OrganizationalUnitIdentifiersConfiguration{
				Certificate:                  ecdsaCAFile, // ECDSA CA
				OrganizationalUnitIdentifier: CLIENTOU,
			},
			AdminOUIdentifier: &fabricmsp.OrganizationalUnitIdentifiersConfiguration{
				Certificate:                  ecdsaCAFile, // ECDSA CA
				OrganizationalUnitIdentifier: ADMINOU,
			},
			PeerOUIdentifier: &fabricmsp.OrganizationalUnitIdentifiersConfiguration{
				Certificate:                  dilCAFile, // Dilithium CA
				OrganizationalUnitIdentifier: PEEROU,
			},
			OrdererOUIdentifier: &fabricmsp.OrganizationalUnitIdentifiersConfiguration{
				Certificate:                  dilCAFile, // Dilithium CA
				OrganizationalUnitIdentifier: ORDEREROU,
			},
		},
	}
	b, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(mspDir, "config.yaml"), b, 0o644)
}
