package main

import (
	"container/list"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

var debugMode = os.Getenv("PROXY_DEBUG") == "1"

func logDebug(format string, v ...interface{}) {
	if debugMode {
		log.Printf("[DEBUG] "+format, v...)
	}
}

// main acts as the entry point of the application.
//
// Description:
//
//	It parses the command-line arguments to determine which subcommand ('genca' or 'proxy') to execute.
//	It serves as the dispatcher for the CLI tool.
//
// Parameters:
//
//	None (uses os.Args directly).
//
// Return Value:
//
//	None.
//
// Implementation Logic:
//  1. Validates the number of command-line arguments.
//  2. Switches on the first argument (subcommand) to invoke the corresponding handler function.
//  3. Exits with status code 1 if the command is unknown or arguments are missing.
func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: wewego <command> [arguments]")
		fmt.Println("Commands: genca, proxy")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "genca":
		handleGenCA()
	case "proxy":
		handleProxy()
	default:
		fmt.Printf("Unknown command: %s\n", os.Args[1])
		os.Exit(1)
	}
}

// handleGenCA handles the generation of the Root Certificate Authority (CA).
//
// Description:
//
//	This function generates a 4096-bit RSA private key and a self-signed CA certificate.
//	It exports the generated key and certificate in multiple formats (PEM, DER, PKCS#12)
//	to facilitate import into different operating systems and browsers.
//
// Parameters:
//
//	None (uses os.Args for flag parsing).
//
// Return Value:
//
//	None.
//
// Implementation Logic:
//  1. Parses command-line flags for the 'genca' subcommand.
//  2. Generates a secure RSA private key (4096 bits).
//  3. Creates a self-signed X.509 certificate template with CA properties (IsCA=true, KeyUsage).
//  4. Exports the certificate and key to files:
//     - ca-cert.pem: PEM encoded certificate.
//     - ca-key.pem: PEM encoded private key.
//     - ca.cer: DER encoded certificate (for Windows).
//     - ca.p12: PKCS#12 archive (for browsers).
func handleGenCA() {
	// --- Step 1: Parse Flags ---
	fs := flag.NewFlagSet("genca", flag.ExitOnError)
	if err := fs.Parse(os.Args[2:]); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing flags: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Generating CA certificate and private key...")

	// --- Step 2: Generate Private Key ---
	// Generate a 4096-bit RSA private key for robust security.
	priv, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate private key: %v\n", err)
		os.Exit(1)
	}

	// --- Step 3: Create CA Certificate Template ---
	// Generate a random serial number (128-bit) as per RFC 5280.
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate serial number: %v\n", err)
		os.Exit(1)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "Local HTTPS Proxy CA",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(10, 0, 0), // Valid for 10 years

		// Key Usage settings critical for a CA certificate
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true, // Mark as CA
		MaxPathLen:            0,    // Limit CA path length for security
		MaxPathLenZero:        true,
	}

	// Compute Subject Key Identifier (SKI) for authority chaining
	ski := computeSKI(priv)
	template.SubjectKeyId = ski
	template.AuthorityKeyId = ski

	// --- Step 4: Self-Sign Certificate ---
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create certificate: %v\n", err)
		os.Exit(1)
	}

	// --- Step 5: Export Files ---

	// Export PEM Certificate
	certPemFile, err := os.Create("ca-cert.pem")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create ca-cert.pem: %v\n", err)
		os.Exit(1)
	}
	pem.Encode(certPemFile, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certPemFile.Close()

	// Export PEM Private Key
	keyOut, err := os.OpenFile("ca-key.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create ca-key.pem: %v\n", err)
		os.Exit(1)
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to marshal private key: %v\n", err)
		os.Exit(1)
	}
	pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	keyOut.Close()

	// Export DER Certificate (Windows friendly)
	if err := os.WriteFile("ca.cer", derBytes, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write ca.cer: %v\n", err)
		os.Exit(1)
	}

	// Export PKCS#12 (Browser friendly)
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse certificate: %v\n", err)
		os.Exit(1)
	}
	p12Bytes, err := pkcs12.Modern.Encode(priv, cert, nil, "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to encode ca.p12: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile("ca.p12", p12Bytes, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write ca.p12: %v\n", err)
		os.Exit(1)
	}

	// Print Summary
	hash := sha256.Sum256(derBytes)
	fmt.Printf("\nCA generated successfully!\n")
	fmt.Printf("SHA-256 Fingerprint: %s\n", hex.EncodeToString(hash[:]))
	fmt.Println("\nImport Tips:")
	fmt.Println("- Windows: Double-click 'ca.cer' -> Install Certificate -> Local Machine -> Trusted Root Certification Authorities")
	fmt.Println("- macOS: Open 'ca-cert.pem' in Keychain Access -> System -> Trust -> Always Trust")
	fmt.Println("- Browser: Import 'ca.p12' (empty password) or 'ca-cert.pem' into your browser's certificate manager")
}

// computeSKI calculates the Subject Key Identifier (SKI) for an RSA private key.
//
// Description:
//
//	The SKI is used to identify the public key corresponding to a private key.
//	It is essential for building certificate chains.
//
// Parameters:
//
//	priv (*rsa.PrivateKey): The private key to compute the SKI for.
//
// Return Value:
//
//	([]byte): The SHA-256 hash of the marshaled public key.
//
// Implementation Logic:
//  1. Marshal the public key part of the private key to PKCS#1 format.
//  2. Compute the SHA-256 hash of the marshaled bytes.
//  3. Return the hash slice.
func computeSKI(priv *rsa.PrivateKey) []byte {
	pubBytes := x509.MarshalPKCS1PublicKey(&priv.PublicKey)
	hash := sha256.Sum256(pubBytes)
	return hash[:]
}

// handleProxy starts and manages the HTTPS proxy server.
//
// Description:
//
//	This is the main entry point for the 'proxy' subcommand. It initializes the
//	proxy server components, including the Certificate Authority, Certificate Manager,
//	Request/Response Interceptors, and the HTTP/TCP listeners. It also handles
//	graceful shutdown on system signals.
//
// Parameters:
//
//	None (uses os.Args for flag parsing).
//
// Return Value:
//
//	None.
//
// Implementation Logic:
//  1. Parse command-line arguments (listen address, CA paths, upstream proxy/host).
//  2. Validate upstream host configuration.
//  3. Load the CA certificate and key for MITM operations.
//  4. Initialize the CertManager with an LRU cache.
//  5. Configure the HTTP Transport with HTTP/2 support and upstream proxy settings.
//  6. Initialize the DemoInterceptor for request/response modification.
//  7. Set up the ProxyServer handler and the http.Server.
//  8. Start a goroutine for signal handling to support graceful shutdown.
//  9. Start the server and listen for incoming connections.
func handleProxy() {
	// --- Step 1: Parse and Validate Flags ---
	caCertPath := flag.String("cacert", "ca-cert.pem", "Path to CA certificate")
	caKeyPath := flag.String("cakey", "ca-key.pem", "Path to CA private key")
	listenAddr := flag.String("listen", "127.0.0.1:8443", "Listen address")
	cacheSize := flag.Int("certCacheSize", 200, "Size of the certificate cache")
	upstreamProxyStr := flag.String("upstreamProxyUrl", "", "Upstream proxy URL (e.g. http://127.0.0.1:8080)")
	upstreamHostUrlStr := flag.String("upstreamHostUrl", "", "Upstream proxy URL (e.g. http://127.0.0.1:8080)")

	flag.CommandLine.Parse(os.Args[2:])
	var err error

	addr, err := net.ResolveTCPAddr("tcp", *listenAddr)
	if err != nil {
		log.Fatalf("listenAddr error %s", err.Error())
	}

	if *upstreamHostUrlStr == "" {
		log.Fatalf("Upstream host is required")
	}

	if _, err = url.Parse(*upstreamHostUrlStr); err != nil {
		log.Fatalf("Invalid upstream host URL: %v", err)
	}

	var upstreamProxyURL *url.URL
	if *upstreamProxyStr != "" {
		var err error
		upstreamProxyURL, err = url.Parse(*upstreamProxyStr)
		if err != nil {
			log.Fatalf("Invalid upstream proxy URL: %v", err)
		}
		// Ensure default port if missing
		if upstreamProxyURL.Port() == "" {
			if upstreamProxyURL.Scheme == "https" {
				upstreamProxyURL.Host = net.JoinHostPort(upstreamProxyURL.Hostname(), "443")
			} else {
				upstreamProxyURL.Host = net.JoinHostPort(upstreamProxyURL.Hostname(), "80")
			}
		}
	}

	// --- Step 2: Load CA and Initialize CertManager ---
	ca, err := loadCA(*caCertPath, *caKeyPath)
	if err != nil {
		log.Fatalf("Failed to load CA: %v", err)
	}

	cm := NewCertManager(ca, *cacheSize)

	// --- Step 3: Configure Transport and Interceptors ---
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			NextProtos: []string{"h2", "http/1.1"},
		},
		ForceAttemptHTTP2: true,
	}

	if upstreamProxyURL != nil {
		transport.Proxy = http.ProxyURL(upstreamProxyURL)
	} else {
		transport.Proxy = nil // Direct connection
	}

	demo := NewDemoInterceptor(*upstreamHostUrlStr)

	conCh := make(chan net.Conn, 3)

	// --- Step 4: Initialize ProxyServer ---
	proxy := &ProxyServer{
		Addr:                addr,
		connCh:              conCh,
		CertManager:         cm,
		RequestInterceptor:  demo,
		ResponseInterceptor: demo,
		Client: &http.Client{
			Transport: transport,
			// Do not follow redirects automatically; let the client handle them.
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}

	go startHTTP(conCh, addr, proxy)

	server := &http.Server{
		Addr:    *listenAddr,
		Handler: proxy,
	}

	// --- Step 5: Setup Graceful Shutdown ---
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		sig := <-sigChan
		logDebug("Received signal %v, shutting down...", sig)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			log.Printf("Server shutdown error: %v", err)
		}
	}()

	// --- Step 6: Start Server ---
	logDebug("Starting proxy on %s", *listenAddr)
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalf("ListenAndServe error: %v", err)
	}
}

// --- CertManager & LRU Cache ---

// CertManager manages the dynamic generation and caching of TLS certificates.
//
// Description:
//
//	It acts as an intermediate Certificate Authority (MITM CA), generating
//	certificates on-the-fly for intercepted domains. It employs an LRU cache
//	to minimize the overhead of key generation and signing.
//
// Fields:
//
//	caCert: The root CA certificate used for signing.
//	caPrivKey: The private key of the root CA.
//	cache: An LRU cache storing generated certificates.
//	mu: Mutex for thread-safe access to the cache.
type CertManager struct {
	caCert    *x509.Certificate
	caPrivKey interface{}
	cache     *LRUCache
	mu        sync.Mutex
}

// NewCertManager creates and initializes a new CertManager instance.
//
// Description:
//
//	Initializes the CertManager with the provided CA certificate and a configured
//	LRU cache size.
//
// Parameters:
//
//	ca (tls.Certificate): The loaded CA certificate pair.
//	cacheSize (int): The maximum number of certificates to hold in memory.
//
// Return Value:
//
//	(*CertManager): A pointer to the initialized CertManager.
//
// Implementation Logic:
//  1. Parse the x509 leaf certificate from the tls.Certificate.
//  2. Initialize the LRUCache.
//  3. Return the struct.
func NewCertManager(ca tls.Certificate, cacheSize int) *CertManager {
	cert, _ := x509.ParseCertificate(ca.Certificate[0])
	return &CertManager{
		caCert:    cert,
		caPrivKey: ca.PrivateKey,
		cache:     NewLRUCache(cacheSize),
	}
}

// loadCA loads the CA certificate and private key from the filesystem.
//
// Description:
//
//	Reads the PEM encoded certificate and key files and parses them into a
//	tls.Certificate object.
//
// Parameters:
//
//	certPath (string): Path to the CA certificate file.
//	keyPath (string): Path to the CA private key file.
//
// Return Value:
//
//	(tls.Certificate): The parsed certificate pair.
//	(error): Error object if loading fails.
func loadCA(certPath, keyPath string) (tls.Certificate, error) {
	return tls.LoadX509KeyPair(certPath, keyPath)
}

// GetCertificate retrieves or generates a certificate for the given domain.
//
// Description:
//
//	This is the core method for obtaining a server certificate during the TLS handshake.
//	It first checks the in-memory cache. If missing, it generates a new one.
//
// Parameters:
//
//	domain (string): The target domain name (SNI).
//
// Return Value:
//
//	(*tls.Certificate): The certificate to use for the handshake.
//	(error): Error if generation fails.
//
// Implementation Logic:
//  1. Check LRU cache (thread-safe). If found, return immediately.
//  2. If not found, call generateServerCert to create a new one.
//     (Note: There is a potential optimization point here using singleflight to prevent
//     duplicate work on concurrent requests for the same domain).
//  3. Store the new certificate in the cache.
//  4. Return the certificate.
func (cm *CertManager) GetCertificate(domain string) (*tls.Certificate, error) {
	cm.mu.Lock()
	if cert, ok := cm.cache.Get(domain); ok {
		cm.mu.Unlock()
		return cert, nil
	}
	cm.mu.Unlock()

	// Cache miss: Generate new certificate
	// TODO: Implement singleflight to avoid Thundering Herd problem on concurrent misses.
	cert, err := cm.generateServerCert(domain)
	if err != nil {
		return nil, err
	}

	cm.mu.Lock()
	cm.cache.Add(domain, cert)
	cm.mu.Unlock()

	return cert, nil
}

// generateServerCert creates a new leaf certificate for a specific domain.
//
// Description:
//
//	Generates a 2048-bit RSA key pair and creates a certificate signed by the
//	internal CA. It supports wildcard domains to reduce the number of generated certs.
//
// Parameters:
//
//	domain (string): The domain name to generate the certificate for.
//
// Return Value:
//
//	(*tls.Certificate): The generated certificate pair.
//	(error): Error if any step fails.
//
// Implementation Logic:
//  1. Generate a temporary 2048-bit RSA key.
//  2. Determine if a wildcard domain (e.g., *.example.com) should be used based on the domain depth.
//  3. Create a certificate template with:
//     - Unique serial number.
//     - Validity period (7 days).
//     - KeyUsage (DigitalSignature, KeyEncipherment).
//     - ExtKeyUsage (ServerAuth).
//     - DNSNames (SANs) including the domain and optional wildcard.
//  4. Sign the template using the CA's private key.
//  5. Return the tls.Certificate.
func (cm *CertManager) generateServerCert(domain string) (*tls.Certificate, error) {
	logDebug("Generating cert for %s", domain)

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)

	// Wildcard Logic:
	// If domain is "a.b.com", we try to generate for "*.b.com" to cover all subdomains.
	parts := strings.Split(domain, ".")
	wildcard := ""
	baseDomain := ""
	if len(parts) >= 2 {
		wildcard = "*." + strings.Join(parts[len(parts)-2:], ".")
		baseDomain = strings.Join(parts[len(parts)-2:], ".")
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: domain,
		},
		NotBefore: time.Now().Add(-time.Hour),  // Allow for clock skew
		NotAfter:  time.Now().AddDate(0, 0, 7), // Short validity (7 days)

		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{domain},
	}

	if wildcard != "" {
		template.DNSNames = append(template.DNSNames, wildcard, baseDomain)
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

// LRUCache implements a Least Recently Used (LRU) cache with fixed size.
//
// Description:
//
//	Uses a combination of a doubly linked list and a hash map to provide O(1) access
//	and eviction.
type LRUCache struct {
	size int                      // Maximum capacity
	ll   *list.List               // Doubly linked list for order
	data map[string]*list.Element // Map for fast lookup
}

// cacheItem represents a single entry in the LRU cache.
type cacheItem struct {
	key  string           // Domain name
	cert *tls.Certificate // Certificate
}

// NewLRUCache initializes a new LRUCache.
//
// Parameters:
//
//	size (int): The maximum number of items.
//
// Return Value:
//
//	(*LRUCache): The initialized cache.
func NewLRUCache(size int) *LRUCache {
	return &LRUCache{
		size: size,
		ll:   list.New(),
		data: make(map[string]*list.Element),
	}
}

// Get retrieves an item from the cache.
//
// Parameters:
//
//	key (string): The lookup key (domain).
//
// Return Value:
//
//	(*tls.Certificate): The value if found.
//	(bool): True if found, false otherwise.
//
// Implementation Logic:
//
//	If found, moves the element to the front of the list (mark as recently used) and returns it.
func (c *LRUCache) Get(key string) (*tls.Certificate, bool) {
	if ele, ok := c.data[key]; ok {
		c.ll.MoveToFront(ele)
		return ele.Value.(*cacheItem).cert, true
	}
	return nil, false
}

// Add inserts or updates an item in the cache.
//
// Parameters:
//
//	key (string): The domain key.
//	cert (*tls.Certificate): The certificate to store.
//
// Implementation Logic:
//  1. If key exists, update value and move to front.
//  2. If key is new, push to front.
//  3. If size exceeds capacity, remove the oldest item (back of list).
func (c *LRUCache) Add(key string, cert *tls.Certificate) {
	if ele, ok := c.data[key]; ok {
		c.ll.MoveToFront(ele)
		ele.Value.(*cacheItem).cert = cert
		return
	}
	ele := c.ll.PushFront(&cacheItem{key, cert})
	c.data[key] = ele
	if c.ll.Len() > c.size {
		c.removeOldest()
	}
}

// removeOldest removes the least recently used item.
//
// Implementation Logic:
//
//	Removes the element from the back of the list and deletes it from the map.
func (c *LRUCache) removeOldest() {
	ele := c.ll.Back()
	if ele != nil {
		c.ll.Remove(ele)
		delete(c.data, ele.Value.(*cacheItem).key)
	}
}

// --- Proxy Server ---

// ProxyServer is the core HTTP handler for the proxy.
//
// Description:
//
//	It implements http.Handler and routes requests based on the method (CONNECT vs others).
//	It holds references to the CertManager, Client, and Interceptors.
type ProxyServer struct {
	CertManager         *CertManager
	Client              *http.Client
	connCh              chan net.Conn
	Addr                net.Addr
	RequestInterceptor  RequestInterceptor
	ResponseInterceptor ResponseInterceptor
}

// ServeHTTP implements the http.Handler interface.
//
// Description:
//
//	Dispatches requests. HTTPS requests (CONNECT) are handled by handleConnect.
//	Plain HTTP requests are redirected to HTTPS to enforce security.
//
// Parameters:
//
//	w (http.ResponseWriter): The response writer.
//	r (*http.Request): The incoming request.
func (p *ProxyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
	} else {
		// Enforce HTTPS: Redirect plain HTTP to HTTPS
		if r.URL.Scheme == "http" || r.TLS == nil {
			target := "https://" + r.Host + r.URL.Path
			if r.URL.RawQuery != "" {
				target += "?" + r.URL.RawQuery
			}
			http.Redirect(w, r, target, http.StatusMovedPermanently)
			return
		}
		p.handleHTTP(w, r)
	}
}

var connDataStore sync.Map

// handleConnect establishes the HTTPS tunnel and performs MITM interception.
//
// Description:
//
//	Hijacks the client TCP connection, pretends to be the upstream server (TLS Handshake),
//	and then proxies the decrypted HTTP traffic.
//
// Parameters:
//
//	w (http.ResponseWriter): Response writer.
//	r (*http.Request): The CONNECT request.
//
// Implementation Logic:
//  1. Hijack the connection from the HTTP server.
//  2. Send "200 Connection Established" to the client.
//  3. Peek the SNI from the client's ClientHello.
//  4. Generate/Get a certificate for the SNI (or target host).
//  5. Perform TLS handshake with the client (as the server).
//  6. Launch an internal HTTP server (TunnelHandler) over this TLS connection to handle the actual requests.
func (p *ProxyServer) handleConnect(w http.ResponseWriter, r *http.Request) {
	destHost := r.URL.Host

	targetHost, targetPort, err := net.SplitHostPort(destHost)

	if err != nil {
		http.Error(w, "Host error", http.StatusBadRequest)
		return
	}

	if targetHost == "" {
		targetHost = destHost
	}
	if targetPort == "" {
		targetPort = "443"
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	// --- Step 1: Hijack Connection ---
	rawClientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	// --- Step 2: Respond 200 OK ---
	_, err = rawClientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if err != nil {
		rawClientConn.Close()
		return
	}

	clientConn := rawClientConn
	// --- Step 4: Prepare Certificate and TLS ---
	certHost := targetHost

	cert, err := p.CertManager.GetCertificate(certHost)
	if err != nil {
		log.Printf("Failed to get certificate for %s: %v", certHost, err)
		clientConn.Close()
		return
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2", "http/1.1"}, // Support H2
	}

	// --- Step 5: TLS Handshake ---
	tlsClientConn := tls.Server(clientConn, tlsConfig)
	if err := tlsClientConn.Handshake(); err != nil {
		logDebug("TLS handshake failed with client for %s: %v", certHost, err)
		tlsClientConn.Close()
		return
	}

	// --- Step 6: Start Inner HTTP Server ---

	mdwc := &MyDataWithConn{
		targetHost: targetHost,
		targetPort: targetPort,
	}

	key := getKey(tlsClientConn)

	_, isload := connDataStore.LoadOrStore(key, mdwc)

	if isload {
		logMy("键已经存在")
		os.Exit(0)
	}

	p.connCh <- tlsClientConn

}

func startHTTP(connCh chan net.Conn, addr net.Addr, p *ProxyServer) {

	tunnelHandler := &TunnelHandler{
		proxy: p,
	}

	listener := &SingleConnListener{
		connCh: connCh,
		addr:   addr,
	}

	innerServer := &http.Server{
		Handler:     tunnelHandler,
		ConnContext: myConnContextHook,
	}

	if err := innerServer.Serve(listener); err != nil && err != http.ErrServerClosed {
		// Ignore "use of closed network connection" errors as they are expected on shutdown
		logMy("serve close %s", err.Error())
	} else {
		logMy("serve close")
	}

	logDebug("MitM Session closed for")

}

// handleHTTP handles plain HTTP requests (not currently supported/used).
//
// Description:
//
//	Since we force HTTPS, this handler simply returns an error or redirect.
//	However, if ServeHTTP logic allows, this would handle plain HTTP proxying.
func (p *ProxyServer) handleHTTP(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "Plain HTTP not supported, use HTTPS", http.StatusForbidden)
}

// --- New Types for HTTP/2 Support ---

// TunnelHandler handles the decrypted HTTP requests within the TLS tunnel.
//
// Description:
//
//	Receives requests from the internal HTTP server (after TLS termination),
//	intercepts them, forwards them to the upstream, and returns the response.
type TunnelHandler struct {
	proxy *ProxyServer
}

// ServeHTTP processes individual requests inside the tunnel.
//
// Parameters:
//
//	w (http.ResponseWriter): Response writer.
//	r (*http.Request): Incoming request.
//
// Implementation Logic:
//  1. Reconstruct the absolute URL for the request.
//  2. Invoke RequestInterceptor.
//  3. Handle GET/HEAD requests with body issues (explicitly clear body).
//  4. Forward the request using the ProxyServer's Client.
//  5. Invoke ResponseInterceptor.
//  6. Copy response headers and body back to the client.
func (h *TunnelHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	data, ok := r.Context().Value(connDataKey).(*MyDataWithConn)
	if !ok {

		logMy("ServeHTTP key not MyDataWithConn")

	}

	r.URL.Scheme = "https"

	if r.Host == "" {
		r.URL.Host = net.JoinHostPort(data.targetHost, data.targetPort)
	} else {
		r.URL.Host = net.JoinHostPort(r.Host, data.targetPort)
	}

	r.RequestURI = "" // Must be empty for Client.Do

	logDebug("[%s] Request received: %s %s", data.targetHost, r.Method, r.URL.String())

	// --- Step 2: Request Interception ---
	if h.proxy.RequestInterceptor != nil {
		if err := h.proxy.RequestInterceptor.OnRequest(r); err != nil {
			logDebug("[%s] Request intercepted error: %v", data.targetHost, err)
			http.Error(w, "Request Intercepted", http.StatusBadGateway)
			return
		}
	}
	logDebug("[%s] Request received: %s %s", data.targetHost, r.Method, r.URL.String())

	// --- Step 3: Forward Request ---
	// Important: GET and HEAD requests must not have a body.
	if r.Method == "GET" || r.Method == "HEAD" {
		r.Body = nil
		r.ContentLength = 0
	}

	resp, err := h.proxy.Client.Do(r)
	if err != nil {
		logDebug("[%s] Forward error: %v", data.targetHost, err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	logDebug("[%s] Response received: %s", data.targetHost, resp.Status)

	// --- Step 4: Response Interception ---
	if h.proxy.ResponseInterceptor != nil {
		if err := h.proxy.ResponseInterceptor.OnResponse(resp); err != nil {
			logDebug("[%s] Response intercepted error: %v", data.targetHost, err)
			http.Error(w, "Response Intercepted", http.StatusBadGateway)
			return
		}
	}

	// --- Step 5: Write Response ---
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// copyHeader copies HTTP headers from source to destination.
//
// Parameters:
//
//	dst (http.Header): Destination headers.
//	src (http.Header): Source headers.
func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

// SingleConnListener adapts a single net.Conn to the net.Listener interface.
//
// Description:
//
//	This allows an http.Server to serve a single pre-established connection
//	and then stop. It is used for the inner HTTP server in the MITM tunnel.
type SingleConnListener struct {
	connCh <-chan net.Conn
	addr   net.Addr
}

type MyDataWithConn struct {
	targetHost string
	targetPort string
}

func logMy(format string, v ...interface{}) {
	log.Printf("[LOG] "+format, v...)
}

type contextKey string

const connDataKey contextKey = "custom-conn-data"

func getKey(c net.Conn) string {
	return c.RemoteAddr().String()

}

func myConnContextHook(ctx context.Context, c net.Conn) context.Context {

	key := getKey(c)
	v, isload := connDataStore.LoadAndDelete(key)

	if !isload {
		logMy("key not load %s", key)

		os.Exit(0)

	}

	// 类型断言：检查是否是我们自定义的 Conn
	if v, ok := v.(*MyDataWithConn); ok {

		// 将数据注入到 Context 中
		// 注意：这里创建了一个派生的 Context
		ctx = context.WithValue(ctx, connDataKey, v)
	} else {
		logMy("type is not MyDataWithConn")

		os.Exit(0)
	}
	return ctx
}

// Accept returns the connection once, then closes.
//
// Return Value:
//
//	(net.Conn): The connection (first call).
//	(error): net.ErrClosed (subsequent calls).
func (l *SingleConnListener) Accept() (net.Conn, error) {

	if v, ok := <-l.connCh; ok {
		return v, nil
	} else {

		return nil, net.ErrClosed
	}

}

// Close is a no-op for this listener as it doesn't own a listening socket.
func (l *SingleConnListener) Close() error {

	return nil
}

// Addr returns the local address of the connection.
func (l *SingleConnListener) Addr() net.Addr {
	return l.addr
}

// --- Filters & Interceptors ---

// RequestInterceptor defines the interface for modifying requests.
type RequestInterceptor interface {
	// OnRequest is called before the request is forwarded to the upstream.
	OnRequest(req *http.Request) error
}

// ResponseInterceptor defines the interface for modifying responses.
type ResponseInterceptor interface {
	// OnResponse is called after receiving the response from the upstream.
	OnResponse(resp *http.Response) error
}
