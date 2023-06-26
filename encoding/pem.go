package encoding

import (
	"crypto/x509"
	"encoding/pem"
	"strings"

	"github.com/pkg/errors"
)

// PEM TYPE
const (
	PEMTypePrivateKeyPKCS8 = "PRIVATE KEY"
	PEMTypePublicKeyPKIX   = "PUBLIC KEY"

	PEMTypePublicKeyECC  = "EC PUBLIC KEY"
	PEMTypePrivateKeyECC = "EC PRIVATE KEY"

	PEMTypePrivateKeyPKCS1 = "RSA PRIVATE KEY"
	PEMTypePublicKeyPKCS1  = "RSA PUBLIC KEY"

	PEMTypeCertSignRequest = "CERTIFICATE REQUEST"
	PEMTypeCert            = "CERTIFICATE"
)

// ASN12PEM 将ASN.1转PEM格式
func ASN12PEM(asn1Data []byte, pemType string) []byte {
	blockPub := &pem.Block{
		Type:  pemType,
		Bytes: asn1Data,
	}

	return pem.EncodeToMemory(blockPub)
}

// PEM2ASN1 将PEM转ASN.1格式
func PEM2ASN1(pemData []byte, pemType string) ([]byte, error) {
	var err error

	block, _ := pem.Decode(pemData)
	if block == nil {
		err = errors.Errorf("Decode pem private key failed.")
		return nil, err
	}

	if strings.Compare(block.Type, pemType) != 0 {
		err = errors.Errorf("PEM Data type failed, input %s, need %s", block.Type, pemType)
		return nil, err
	}

	return block.Bytes, nil
}

// PEM2x509CSR PEM to Internal object, x509 certificate signing request
func PEM2x509CSR(pem []byte) (*x509.CertificateRequest, error) {

	// 1. parse and check input CSR
	asn1, err := PEM2ASN1(pem, PEMTypeCertSignRequest)
	if err != nil {

		err = errors.New("trans PEM CSR to asn1 failed")

		return nil, err
	}

	csr, err := x509.ParseCertificateRequest(asn1)
	if err != nil {

		err = errors.New("x509.ParseCertificateRequest failed")
		return nil, err
	}

	return csr, nil
}

// PEM2x509Cert PEM to Internal object, x509 certificate
func PEM2x509Cert(pem []byte) (*x509.Certificate, error) {

	// 1. parse and check input CSR
	asn1, err := PEM2ASN1(pem, PEMTypeCert)
	if err != nil {

		err = errors.New("trans PEM CERT to asn1 failed")

		return nil, err
	}

	cert, err := x509.ParseCertificate(asn1)
	if err != nil {

		err = errors.New("x509.ParseCertificate failed")
		return nil, err
	}

	return cert, nil
}
