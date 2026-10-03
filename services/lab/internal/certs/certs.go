// Package certs handles the two certificate authorities the lab needs: the
// "lab CA" that signs the fake internet's server certificates, and the
// interception CA the egress firewall uses to terminate and inspect TLS.
package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// CA is a loaded certificate authority able to mint leaf certificates.
type CA struct {
	Cert    *x509.Certificate
	Key     *ecdsa.PrivateKey
	PEM     []byte
	mu      sync.Mutex
	leaves  map[string]*tls.Certificate
	keyOnce sync.Once
	leafKey *ecdsa.PrivateKey
}

func serial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}

// LoadOrCreateCA reads a CA from certPath/keyPath, creating it when absent.
func LoadOrCreateCA(certPath, keyPath, commonName string) (*CA, error) {
	if b, err := os.ReadFile(certPath); err == nil {
		if kb, kerr := os.ReadFile(keyPath); kerr == nil {
			ca, perr := parseCA(b, kb)
			if perr == nil {
				return ca, nil
			}
		}
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	sn, err := serial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: sn,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"Aegis Egress Lab"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(5, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	kder, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder})

	if err := os.MkdirAll(filepath.Dir(certPath), 0o755); err != nil {
		return nil, err
	}
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return nil, err
	}
	return parseCA(certPEM, keyPEM)
}

func parseCA(certPEM, keyPEM []byte) (*CA, error) {
	cb, _ := pem.Decode(certPEM)
	kb, _ := pem.Decode(keyPEM)
	if cb == nil || kb == nil {
		return nil, fmt.Errorf("certs: bad PEM")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, err
	}
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		return nil, err
	}
	return &CA{Cert: cert, Key: key, PEM: certPEM, leaves: map[string]*tls.Certificate{}}, nil
}

// Leaf returns (and caches) a server certificate for host, signed by the CA.
// Hosts that parse as IP addresses get an IP SAN instead of a DNS SAN.
func (c *CA) Leaf(host string, extra ...string) (*tls.Certificate, error) {
	c.mu.Lock()
	if tc, ok := c.leaves[host]; ok {
		c.mu.Unlock()
		return tc, nil
	}
	c.mu.Unlock()

	var err error
	c.keyOnce.Do(func() {
		c.leafKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	})
	if err != nil {
		return nil, err
	}
	if c.leafKey == nil {
		return nil, fmt.Errorf("certs: leaf key unavailable")
	}

	sn, err := serial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          sn,
		Subject:               pkix.Name{CommonName: host, Organization: []string{"Aegis Egress Lab"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(2, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, h := range append([]string{host}, extra...) {
		if h == "" {
			continue
		}
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.Cert, &c.leafKey.PublicKey, c.Key)
	if err != nil {
		return nil, err
	}
	tc := &tls.Certificate{
		Certificate: [][]byte{der, c.Cert.Raw},
		PrivateKey:  c.leafKey,
	}
	c.mu.Lock()
	c.leaves[host] = tc
	c.mu.Unlock()
	return tc, nil
}

// WriteLeafFiles mints a leaf for host and writes cert+key PEM to disk. Used by
// the labca bootstrap so the fake internet's servers have real certificates.
func (c *CA) WriteLeafFiles(certPath, keyPath, host string, extra ...string) error {
	tc, err := c.Leaf(host, extra...)
	if err != nil {
		return err
	}
	key, ok := tc.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return fmt.Errorf("certs: unexpected key type")
	}
	kder, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	var chain []byte
	for _, der := range tc.Certificate {
		chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	if err := os.MkdirAll(filepath.Dir(certPath), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(certPath, chain, 0o644); err != nil {
		return err
	}
	return os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}), 0o644)
}

// PoolFrom builds an x509 pool from one or more PEM files, skipping missing ones.
func PoolFrom(paths ...string) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, p := range paths {
		if b, err := os.ReadFile(p); err == nil {
			pool.AppendCertsFromPEM(b)
		}
	}
	return pool
}

// ServerConfig returns a TLS config serving a certificate from disk.
func ServerConfig(certPath, keyPath string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, nil
}
