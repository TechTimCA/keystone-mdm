// Package pki runs Keystone's tiny private certificate authority.
// Each enrolled PC gets a client certificate signed by this CA, and the
// CA certificate is installed into the PC's trusted root store.
package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// CA signs device certificates.
type CA struct {
	Cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// LoadOrCreate reads ca.crt/ca.key from dir, creating them on first run.
func LoadOrCreate(dir, orgName string) (*CA, error) {
	certPath, keyPath := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")
	if cb, err := os.ReadFile(certPath); err == nil {
		kb, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, err
		}
		return parse(cb, kb)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: orgName + " Keystone MDM CA", Organization: []string{orgName}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(20, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	kder, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	cb := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	kb := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder})
	if err := os.WriteFile(certPath, cb, 0o644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath, kb, 0o600); err != nil {
		return nil, err
	}
	return parse(cb, kb)
}

func parse(cb, kb []byte) (*CA, error) {
	cp, _ := pem.Decode(cb)
	kp, _ := pem.Decode(kb)
	if cp == nil || kp == nil {
		return nil, errors.New("pki: bad PEM in CA files")
	}
	cert, err := x509.ParseCertificate(cp.Bytes)
	if err != nil {
		return nil, err
	}
	key, err := x509.ParseECPrivateKey(kp.Bytes)
	if err != nil {
		return nil, err
	}
	return &CA{Cert: cert, key: key}, nil
}

// SignDeviceCSR signs a PKCS#10 request from Windows enrollment.
// The certificate's CN is the device ID so the management endpoint can
// match the TLS client certificate back to the device.
func (ca *CA) SignDeviceCSR(csrDER []byte, deviceID string) (*x509.Certificate, error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, fmt.Errorf("pki: parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("pki: CSR signature: %w", err)
	}
	switch csr.PublicKey.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey:
	default:
		return nil, errors.New("pki: unsupported CSR key type")
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: deviceID},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, csr.PublicKey, ca.key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// Thumbprint is the uppercase SHA-1 hex Windows uses to name certificates.
func Thumbprint(c *x509.Certificate) string {
	sum := sha1.Sum(c.Raw)
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 126))
	return n
}
