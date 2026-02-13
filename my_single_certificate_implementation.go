package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"sync"
	"time"
)

type SingleCertManager struct {
	caCert    *x509.Certificate
	caPrivKey interface{}
	domainMap map[string]bool
	cert      *tls.Certificate
	mu        sync.Mutex
}

func (cm *SingleCertManager) GetCertificate(domain string) (*tls.Certificate, error) {

	cm.mu.Lock()
	cert := cm.cert
	if _, ok := cm.domainMap[domain]; ok {

		cm.mu.Unlock()
		return cert, nil
	}
	cm.domainMap[domain] = true
	keys := make([]string, 0, len(cm.domainMap))

	for k := range cm.domainMap {
		keys = append(keys, k)
	}

	cert, err := cm.generateServerCert(keys)
	if err != nil {
		cm.mu.Unlock()

		logDebug("generateServerCert error %s", err.Error())
		os.Exit(0)

	}

	cm.cert = cert

	cm.mu.Unlock()

	return cert, nil

}

func (cm *SingleCertManager) generateServerCert(domain []string) (*tls.Certificate, error) {
	logDebug("Generating cert for %s", domain)

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "google.com",
		},
		NotBefore: time.Now().Add(-time.Hour),  // Allow for clock skew
		NotAfter:  time.Now().AddDate(0, 0, 7), // Short validity (7 days)

		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              domain,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, cm.caCert, &priv.PublicKey, cm.caPrivKey)
	if err != nil {
		return nil, err
	}

	return &tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}, nil
}
