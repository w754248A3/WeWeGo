package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"
)

// generateTestCA generates a temporary CA cert and key for testing.
func generateTestCA() (string, string, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "Test CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(1 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return "", "", err
	}

	certOut, err := os.CreateTemp("", "ca-cert-*.pem")
	if err != nil {
		return "", "", err
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certOut.Close()

	keyOut, err := os.CreateTemp("", "ca-key-*.pem")
	if err != nil {
		return "", "", err
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", "", err
	}
	pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	keyOut.Close()

	return certOut.Name(), keyOut.Name(), nil
}

func setupEnv(t testing.TB, enableH2 bool) (*httptest.Server, *http.Client, func()) {
	certPath, keyPath, err := generateTestCA()
	if err != nil {
		t.Fatal(err)
	}

	// Setup Upstream
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s", r.Proto)
	}))
	if enableH2 {
		upstream.EnableHTTP2 = true
	} else {
		upstream.EnableHTTP2 = false
	}
	upstream.StartTLS()

	// Setup Proxy
	ca, err := loadCA(certPath, keyPath)
	if err != nil {
		t.Fatalf("Failed to load CA: %v", err)
	}
	cm := NewCertManager(ca, 100)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	proxyAddr := l.Addr().String()

	protos := []string{"http/1.1"}
	if enableH2 {
		protos = []string{"h2", "http/1.1"}
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			NextProtos:         protos,
			InsecureSkipVerify: true,
		},
		ForceAttemptHTTP2: enableH2,
	}

	proxyClient := &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	proxy := &ProxyServer{
		CertManager: cm,
		Client:      proxyClient,
	}

	proxyServer := &http.Server{
		Handler: proxy,
	}

	go proxyServer.Serve(l)

	// Setup Client
	proxyURL, _ := url.Parse("http://" + proxyAddr)
	caCertPEM, _ := os.ReadFile(certPath)
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(caCertPEM)

	clientTransport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{
			RootCAs:            certPool,
			NextProtos:         protos,
			InsecureSkipVerify: true,
		},
		ForceAttemptHTTP2: enableH2,
	}

	client := &http.Client{
		Transport: clientTransport,
	}

	cleanup := func() {
		upstream.Close()
		proxyServer.Close()
		os.Remove(certPath)
		os.Remove(keyPath)
	}

	return upstream, client, cleanup
}

func TestHTTP2Support(t *testing.T) {
	upstream, client, cleanup := setupEnv(t, true)
	defer cleanup()

	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.Proto != "HTTP/2.0" {
		t.Errorf("Downstream connection protocol is %s, want HTTP/2.0", resp.Proto)
	} else {
		t.Log("Downstream connection is HTTP/2.0")
	}

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "HTTP/2.0" {
		t.Errorf("Upstream connection protocol is %s, want HTTP/2.0", string(body))
	} else {
		t.Log("Upstream connection is HTTP/2.0")
	}
}

func BenchmarkHTTP2(b *testing.B) {
	upstream, client, cleanup := setupEnv(b, true)
	defer cleanup()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp, err := client.Get(upstream.URL)
		if err != nil {
			b.Fatalf("Request failed: %v", err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}

func BenchmarkHTTP1(b *testing.B) {
	upstream, client, cleanup := setupEnv(b, false)
	defer cleanup()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp, err := client.Get(upstream.URL)
		if err != nil {
			b.Fatalf("Request failed: %v", err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}
