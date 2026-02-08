package main

import (
	"bufio"
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

// main 是程序的入口点，负责解析子命令并分发执行逻辑。
//
// 业务用途：
// 提供命令行交互界面，支持 'genca' (生成证书) 和 'proxy' (启动代理) 两个核心功能。
//
// 参数说明：
// os.Args[1] - 子命令名称
//
// 示例：
// wewego genca
// wewego proxy -listen :8080
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

// handleGenCA 处理根证书 (CA) 的生成逻辑。
//
// 核心功能：
// 1. 生成 4096 位的 RSA 私钥。
// 2. 创建有效期为 10 年的自签名 CA 证书。
// 3. 将证书和私钥导出为多种标准格式 (PEM, DER, PKCS12)。
//
// 实现思路：
// 使用 Go 的 crypto/x509 标准库构建证书模板，设置 IsCA: true 以及相应的 KeyUsage，
// 以确保生成的证书能被操作系统和浏览器识别为有效的受信任根。
//
// 返回值：
// 无。执行失败时会直接调用 os.Exit(1) 并打印错误信息。
func handleGenCA() {
	fs := flag.NewFlagSet("genca", flag.ExitOnError)
	if err := fs.Parse(os.Args[2:]); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing flags: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Generating CA certificate and private key...")

	// 1. 生成 4096 位 RSA 私钥，用于 CA 的身份标识和后续证书签发
	priv, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate private key: %v\n", err)
		os.Exit(1)
	}

	// 2. 创建自签名的 CA 证书
	// 生成 128 位的随机序列号，符合 RFC 5280 标准。
	// 技术细节：使用 big.Int 的 Lsh (左移) 操作计算 2^128，作为随机数的上限。
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
		NotAfter:  time.Now().AddDate(10, 0, 0), // 证书有效期设为 10 年

		// 设置关键的使用限制
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true, // 声明此证书为 CA
		MaxPathLen:            0,    // 限制 CA 路径长度，增强安全性
		MaxPathLenZero:        true,
	}

	// 为证书添加 SubjectKeyIdentifier 和 AuthorityKeyIdentifier，用于建立信任链
	ski := computeSKI(priv)
	template.SubjectKeyId = ski
	template.AuthorityKeyId = ski

	// 自签名操作：使用私钥对包含自身公钥的模板进行签名
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create certificate: %v\n", err)
		os.Exit(1)
	}

	// 3. 导出多种格式的文件，以适配不同的操作系统和浏览器
	// 导出为 PEM 格式的证书，通常用于 macOS/Linux
	certPemFile, err := os.Create("ca-cert.pem")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create ca-cert.pem: %v\n", err)
		os.Exit(1)
	}
	pem.Encode(certPemFile, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certPemFile.Close()

	// 导出为 PEM 格式的私钥，设置权限为 0600 (仅所有者可读写)
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

	// 导出为 DER 编码的 .cer 文件，通常用于 Windows 导入
	if err := os.WriteFile("ca.cer", derBytes, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write ca.cer: %v\n", err)
		os.Exit(1)
	}

	// 导出为 PKCS#12 (.p12) 格式，方便浏览器一键导入，默认密码为空
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

	// 4. 打印指纹及后续操作指南
	hash := sha256.Sum256(derBytes)
	fmt.Printf("\nCA generated successfully!\n")
	fmt.Printf("SHA-256 Fingerprint: %s\n", hex.EncodeToString(hash[:]))
	fmt.Println("\nImport Tips:")
	fmt.Println("- Windows: Double-click 'ca.cer' -> Install Certificate -> Local Machine -> Trusted Root Certification Authorities")
	fmt.Println("- macOS: Open 'ca-cert.pem' in Keychain Access -> System -> Trust -> Always Trust")
	fmt.Println("- Browser: Import 'ca.p12' (empty password) or 'ca-cert.pem' into your browser's certificate manager")
}

// computeSKI 计算并返回 RSA 公钥的 Subject Key Identifier (SKI)。
//
// 算法逻辑：
// 采用 RFC 5280 推荐的方法 1：计算公钥内容的 SHA-1 哈希值（此处为了安全性使用了 SHA-256）。
//
// 参数：
// priv - 指向 RSA 私钥的指针
//
// 返回值：
// 包含哈希值的字节切片
func computeSKI(priv *rsa.PrivateKey) []byte {
	pubBytes := x509.MarshalPKCS1PublicKey(&priv.PublicKey)
	hash := sha256.Sum256(pubBytes)
	return hash[:]
}

// handleProxy 处理代理服务器的启动逻辑。
//
// 核心功能：
// 1. 解析命令行参数（监听地址、证书路径等）。
// 2. 加载根证书并初始化证书管理器。
// 3. 配置 HTTP 代理服务器并实现优雅退出。
//
// 异常处理：
// 如果 CA 文件不存在或加载失败，程序将记录 Fatal 错误并退出。
func handleProxy() {
	caCertPath := flag.String("cacert", "ca-cert.pem", "Path to CA certificate")
	caKeyPath := flag.String("cakey", "ca-key.pem", "Path to CA private key")
	listenAddr := flag.String("listen", "127.0.0.1:8443", "Listen address")
	cacheSize := flag.Int("certCacheSize", 200, "Size of the certificate cache")
	upstreamStr := flag.String("upstream", "", "Upstream proxy URL (e.g. http://127.0.0.1:8080)")
	upstreamHost := flag.String("upstreamHost", "", "Upstream proxy host (e.g. 127.0.0.1)")
	pathReplace := flag.String("pathReplace", "/", "Replace path in request (e.g. /new-path)")
	
	flag.CommandLine.Parse(os.Args[2:])

	// 验证上游主机是否指定
	if *upstreamHost == "" {
		log.Fatalf("Upstream proxy host is required")
	}

	var upstreamURL *url.URL
	if *upstreamStr != "" {
		var err error
		upstreamURL, err = url.Parse(*upstreamStr)
		if err != nil {
			log.Fatalf("Invalid upstream proxy URL: %v", err)
		}
		// 补全默认端口
		if upstreamURL.Port() == "" {
			if upstreamURL.Scheme == "https" {
				upstreamURL.Host = net.JoinHostPort(upstreamURL.Hostname(), "443")
			} else {
				upstreamURL.Host = net.JoinHostPort(upstreamURL.Hostname(), "80")
			}
		}
	}

	// 加载 CA 证书对，用于动态签发子证书
	ca, err := loadCA(*caCertPath, *caKeyPath)
	if err != nil {
		log.Fatalf("Failed to load CA: %v", err)
	}

	cm := NewCertManager(ca, *cacheSize)

	
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			NextProtos: []string{"h2", "http/1.1"},
		},
		ForceAttemptHTTP2: true,
	}

	// 如果指定了上游代理，则配置 Transport 使用该代理
	if upstreamURL != nil {
		transport.Proxy = http.ProxyURL(upstreamURL)
	} else {
		// 显式禁用系统代理，确保上游连接为直接连接
		transport.Proxy = nil
	}

    // 实例化拦截器
	demo := NewDemoInterceptor(*upstreamHost, *pathReplace)

	proxy := &ProxyServer{
		CertManager:         cm,
		UpstreamProxy:       upstreamURL,
		RequestInterceptor:  demo,
		ResponseInterceptor: demo,
		Client: &http.Client{
			Transport: transport,
			// 默认不跟随重定向，将重定向响应透传给客户端
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}

	server := &http.Server{
		Addr:    *listenAddr,
		Handler: proxy,
	}

	// 优雅退出处理逻辑
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		sig := <-sigChan
		logDebug("Received signal %v, shutting down...", sig)

		// 给现有连接 5 秒的处理宽限期
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			log.Printf("Server shutdown error: %v", err)
		}
	}()

	logDebug("Starting proxy on %s", *listenAddr)
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalf("ListenAndServe error: %v", err)
	}
}

// --- CertManager & LRU Cache ---

// CertManager 负责管理和生成用于中间人攻击 (MITM) 的服务器证书。
//
// 架构角色：
// 作为证书中心，它利用根证书 (CA) 为目标域名动态签发临时证书，并使用 LRU 缓存提高复用效率。
//
// 线程安全性：
// 该结构体是线程安全的，内部使用 sync.Mutex 保护缓存访问与证书签发逻辑。
type CertManager struct {
	caCert    *x509.Certificate // 根证书对象
	caPrivKey interface{}       // 根证书私钥
	cache     *LRUCache         // 证书 LRU 缓存
	mu        sync.Mutex        // 保护缓存与签发逻辑的互斥锁
}

// NewCertManager 创建并初始化一个新的 CertManager。
//
// 参数：
// ca - 已加载的 CA 证书对
// cacheSize - 缓存中允许保留的最大证书数量
//
// 返回值：
// 指向初始化后的 CertManager 实例
func NewCertManager(ca tls.Certificate, cacheSize int) *CertManager {
	cert, _ := x509.ParseCertificate(ca.Certificate[0])
	return &CertManager{
		caCert:    cert,
		caPrivKey: ca.PrivateKey,
		cache:     NewLRUCache(cacheSize),
	}
}

// loadCA 从指定的文件路径加载 CA 证书和私钥。
//
// 参数：
// certPath - CA 证书 PEM 文件路径
// keyPath - CA 私钥 PEM 文件路径
//
// 返回值：
// tls.Certificate - 加载后的证书对
// error - 加载失败时的错误信息
func loadCA(certPath, keyPath string) (tls.Certificate, error) {
	return tls.LoadX509KeyPair(certPath, keyPath)
}

// GetCertificate 获取指定域名的 TLS 证书。
//
// 实现逻辑：
// 1. 首先尝试从缓存中获取。
// 2. 若缓存未命中，则调用 generateServerCert 动态签发新证书并存入缓存。
//
// 参数：
// domain - 目标域名（如 "google.com"）
//
// 返回值：
// *tls.Certificate - 可用于 TLS 握手的证书指针
// error - 签发过程中的异常情况
func (cm *CertManager) GetCertificate(domain string) (*tls.Certificate, error) {
	cm.mu.Lock()
	if cert, ok := cm.cache.Get(domain); ok {
		cm.mu.Unlock()
		return cert, nil
	}
	cm.mu.Unlock()

	// 缓存未命中，执行动态签发
	// TODO: 优化并发性能 (Thundering Herd 问题)
	// 当前实现在高并发场景下，若多个请求同时访问同一个未缓存的域名，
	// 会导致多次重复签发证书。建议引入 singleflight 模式，
	// 确保同一时刻针对同一域名只进行一次签发操作。
	cert, err := cm.generateServerCert(domain)
	if err != nil {
		return nil, err
	}

	cm.mu.Lock()
	cm.cache.Add(domain, cert)
	cm.mu.Unlock()

	return cert, nil
}

// generateServerCert 为特定域名动态签发被 CA 信任的服务器证书。
//
// 关键算法：
// 1. 生成 2048 位的临时 RSA 私钥。
// 2. 构造证书模板，包含通配符域名 (Wildcard) 以增强兼容性。
// 3. 使用 CA 私钥对模板进行签名。
//
// 参数：
// domain - 需要签发的域名
//
// 返回值：
// *tls.Certificate - 签发成功的证书对象
func (cm *CertManager) generateServerCert(domain string) (*tls.Certificate, error) {
	logDebug("Generating cert for %s", domain)

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)

	// 确定通配符域名逻辑：
	// 算法逻辑：将域名按点号分割，若层级大于等于 2（如 a.b.com），
	// 则提取最后两段（b.com）构造通配符（*.b.com）和基础域名（b.com）。
	// 这样可以使一个证书覆盖同一二级域名下的多个三级域名，显著减少签发压力。
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
		NotBefore: time.Now().Add(-time.Hour), // 提前一小时以兼容时钟偏差
		NotAfter:  time.Now().AddDate(0, 0, 7), // 有效期 7 天，平衡安全性与复用性

		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{domain},
	}

	if wildcard != "" {
		template.DNSNames = append(template.DNSNames, wildcard, baseDomain)
	}

	// 使用 CA 证书和 CA 私钥进行签名
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, cm.caCert, &priv.PublicKey, cm.caPrivKey)
	if err != nil {
		return nil, err
	}

	return &tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}, nil
}

// LRUCache 实现了一个固定大小的最近最少使用 (LRU) 缓存。
//
// 实现思路：
// 使用双向链表 (list.List) 维护访问顺序，使用 Map (map) 实现 O(1) 的查找。
// 每次访问或添加元素时，将其移至链表头部；当容量溢出时，移除链表尾部的旧元素。
type LRUCache struct {
	size int                      // 缓存最大容量
	ll   *list.List               // 存储 cacheItem 的双向链表
	data map[string]*list.Element // 快速索引 Map
}

// cacheItem 存储在 LRU 链表中的实际数据项。
type cacheItem struct {
	key  string           // 缓存键（域名）
	cert *tls.Certificate // 缓存值（TLS 证书）
}

// NewLRUCache 创建一个新的 LRUCache 实例。
func NewLRUCache(size int) *LRUCache {
	return &LRUCache{
		size: size,
		ll:   list.New(),
		data: make(map[string]*list.Element),
	}
}

// Get 从缓存中获取证书，并将其标记为最近使用。
func (c *LRUCache) Get(key string) (*tls.Certificate, bool) {
	if ele, ok := c.data[key]; ok {
		c.ll.MoveToFront(ele) // 命中后移至头部
		return ele.Value.(*cacheItem).cert, true
	}
	return nil, false
}

// Add 向缓存中添加或更新证书。
func (c *LRUCache) Add(key string, cert *tls.Certificate) {
	if ele, ok := c.data[key]; ok {
		c.ll.MoveToFront(ele)
		ele.Value.(*cacheItem).cert = cert
		return
	}
	ele := c.ll.PushFront(&cacheItem{key, cert})
	c.data[key] = ele
	if c.ll.Len() > c.size {
		c.removeOldest() // 容量溢出时剔除
	}
}

// removeOldest 移除缓存中最近最少使用的项。
func (c *LRUCache) removeOldest() {
	ele := c.ll.Back()
	if ele != nil {
		c.ll.Remove(ele)
		delete(c.data, ele.Value.(*cacheItem).key)
	}
}

// --- Proxy Server ---

// ProxyServer 是 HTTPS 代理的核心服务器结构。
//
// 设计模式：
// 实现 http.Handler 接口，作为代理逻辑的调度器。
type ProxyServer struct {
	CertManager         *CertManager         // 证书管理器，用于 MITM
	Client              *http.Client         // 用于向上游服务器发起请求的客户端
	UpstreamProxy       *url.URL             // 可选的上游代理服务器
	RequestInterceptor  RequestInterceptor   // 请求拦截器
	ResponseInterceptor ResponseInterceptor  // 响应拦截器
}

// bufferedConn 用于包装 net.Conn 并处理 bufio.Reader 中的缓冲数据。
type bufferedConn struct {
	net.Conn
	r io.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) {
	return b.r.Read(p)
}

// peekSNI 预读 ClientHello 以提取 SNI，且不破坏原始连接。
func peekSNI(conn net.Conn) (string, net.Conn, error) {
	br := bufio.NewReader(conn)

	// TLS 记录头 5 字节，ClientHello 通常前 1024 字节足够
	data, err := br.Peek(1024)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return "", &bufferedConn{Conn: conn, r: br}, err
	}

	sni := parseSNI(data)
	return sni, &bufferedConn{Conn: conn, r: br}, nil
}

// parseSNI 解析 TLS ClientHello 字节流中的 SNI 扩展。
func parseSNI(data []byte) string {
	if len(data) < 43 {
		return ""
	}

	// 检查是否为 TLS Handshake (0x16)
	if data[0] != 0x16 {
		return ""
	}

	pos := 5 // 跳过 Record Header
	if len(data) < pos+4 {
		return ""
	}

	// Handshake Type 必须是 Client Hello (0x01)
	if data[pos] != 0x01 {
		return ""
	}

	pos += 38 // 跳过 Handshake Header, Version, Random

	// Session ID
	if pos >= len(data) {
		return ""
	}
	sessionIDLen := int(data[pos])
	pos += 1 + sessionIDLen

	// Cipher Suites
	if pos+1 >= len(data) {
		return ""
	}
	cipherSuiteLen := int(data[pos])<<8 | int(data[pos+1])
	pos += 2 + cipherSuiteLen

	// Compression Methods
	if pos >= len(data) {
		return ""
	}
	compressionLen := int(data[pos])
	pos += 1 + compressionLen

	// Extensions
	if pos+1 >= len(data) {
		return ""
	}
	extensionsLen := int(data[pos])<<8 | int(data[pos+1])
	pos += 2

	end := pos + extensionsLen
	if end > len(data) {
		end = len(data)
	}

	for pos+4 < end {
		extType := int(data[pos])<<8 | int(data[pos+1])
		extLen := int(data[pos+2])<<8 | int(data[pos+3])
		pos += 4

		if extType == 0x00 { // SNI extension type
			if pos+2 >= end {
				return ""
			}
			pos += 2 // Server Name List Length
			if pos < end && data[pos] == 0x00 {
				pos++
				if pos+1 >= end {
					return ""
				}
				nameLen := int(data[pos])<<8 | int(data[pos+1])
				pos += 2
				if pos+nameLen <= end {
					return string(data[pos : pos+nameLen])
				}
			}
		}
		pos += extLen
	}

	return ""
}

// ServeHTTP 处理所有传入的代理请求。
//
// 业务逻辑：
// 1. 识别 CONNECT 方法（HTTPS 隧道请求），调用 handleConnect 处理。
// 2. 识别普通 HTTP 请求，强制重定向至 HTTPS。
func (p *ProxyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
	} else {
		// 强制 HTTPS 跳转策略
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

// handleConnect 处理 HTTPS 代理的隧道建立过程。
//
// 实现步骤：
// 1. 劫持 (Hijack) 客户端连接，脱离标准 HTTP Server 逻辑。
// 2. 返回 200 Connection Established 告知客户端隧道已就绪。
// 3. 动态获取目标域名的证书，与客户端进行 MITM TLS 握手。
// 4. 使用 http.Server 处理握手后的连接，支持 HTTP/1.1 和 HTTP/2。
func (p *ProxyServer) handleConnect(w http.ResponseWriter, r *http.Request) {
	destHost := r.URL.Host
	targetHost, targetPort, _ := net.SplitHostPort(destHost)
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

	// 1. 劫持底层 TCP 连接
	rawClientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	// 2. 响应客户端 CONNECT 请求
	_, err = rawClientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if err != nil {
		rawClientConn.Close()
		return
	}

	// 3. 嗅探 SNI 并调用拦截器
	sni, clientConn, err := peekSNI(rawClientConn)
	if err != nil {
		log.Printf("Failed to peek SNI for %s: %v", targetHost, err)
		// 即使失败也继续，不中断连接。
	}

	// 4. 执行中间人 (MitM) TLS 握手
	// 注意：证书应匹配客户端期望的域名 (SNI 或 CONNECT Host)
	certHost := sni
	if certHost == "" {
		certHost = targetHost
	}
	cert, err := p.CertManager.GetCertificate(certHost)
	if err != nil {
		log.Printf("Failed to get certificate for %s: %v", certHost, err)
		clientConn.Close()
		return
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2", "http/1.1"}, // 启用 HTTP/2 支持
	}

	// 作为服务器与客户端握手
	tlsClientConn := tls.Server(clientConn, tlsConfig)
	if err := tlsClientConn.Handshake(); err != nil {
		logDebug("TLS handshake failed with client for %s: %v", certHost, err)
		tlsClientConn.Close()
		return
	}
	// 注意：连接关闭由 http.Server 管理，此处不需要 defer Close，
	// 除非 Serve 返回错误且未关闭连接。但在 SingleConnListener 中，
	// 我们将连接传递给 Server，Server 负责关闭它。

	// 5. 使用 http.Server 处理 HTTP/1.1 和 HTTP/2 请求
	// 创建一个 TunnelHandler，它将请求转发到上游
	tunnelHandler := &TunnelHandler{
		proxy:       p,
		targetHost:  targetHost, // 原始目标主机
		targetPort:  targetPort,
	}

	// 创建一个单连接 Listener
	listener := &SingleConnListener{
		conn: tlsClientConn,
	}

	// 启动内部 Server
	// Server 会自动协商 H1/H2
	innerServer := &http.Server{
		Handler: tunnelHandler,
	}

	logDebug("MitM Session started for %s (SNI: %s, Proto: %s)", targetHost, sni, tlsClientConn.ConnectionState().NegotiatedProtocol)
	
	if err := innerServer.Serve(listener); err != nil && err != http.ErrServerClosed {
		// ErrServerClosed 是正常退出（如果调用了 Shutdown，但这里通常是连接关闭）
		// 如果是 listener 关闭导致的错误，通常可以忽略
		if !strings.Contains(err.Error(), "use of closed network connection") {
			logDebug("Inner server error for %s: %v", targetHost, err)
		}
	}

	logDebug("MitM Session closed for %s", targetHost)
}

// handleHTTP 处理普通的 HTTP 请求。
func (p *ProxyServer) handleHTTP(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Plain HTTP not supported, use HTTPS", http.StatusForbidden)
}

// --- New Types for HTTP/2 Support ---

// TunnelHandler 处理隧道内的 HTTP 请求，将其转发到上游。
type TunnelHandler struct {
	proxy       *ProxyServer
	targetHost  string
	targetPort  string
}

func (h *TunnelHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 1. 重建请求 URL
	// r.URL 在 Server 接收时通常是相对路径 (H1) 或绝对路径 (H2)
	// 我们需要确保它是绝对路径以便 Client.Do 使用
	if r.URL.Scheme == "" {
		r.URL.Scheme = "https"
	}
	if r.URL.Host == "" {
		r.URL.Host = r.Host
		if r.URL.Host == "" {
			// 如果 Header 中也没有 Host，回退到 targetHost
			r.URL.Host = net.JoinHostPort(h.targetHost, h.targetPort)
		}
	}
	
	// 清理 RequestURI (Client.Do 不允许设置)
	r.RequestURI = ""
	
	logDebug("[%s] Request received: %s %s", h.targetHost, r.Method, r.URL.String())

	// 2. 应用请求拦截器
	if h.proxy.RequestInterceptor != nil {
		if err := h.proxy.RequestInterceptor.OnRequest(r); err != nil {
			logDebug("[%s] Request intercepted error: %v", h.targetHost, err)
			http.Error(w, "Request Intercepted", http.StatusBadGateway)
			return
		}
	}
	logDebug("[%s] Request received: %s %s", h.targetHost, r.Method, r.URL.String())
	// 3. 转发请求
	// 注意：p.Client 已配置 Transport (含 H2 支持)
	// 我们可能需要调整 SNI。http.Transport 默认使用 URL.Host 作为 SNI。
	// 如果需要强制使用 UpstreamSNI，可能需要自定义 Transport 或 Context。
	// 但通常 URL.Host 就是正确的 SNI。

	// Fix: 对于 GET 和 HEAD 请求，必须显式清空 Body，否则 http.Transport 会认为有 Body 并尝试发送，
	// 导致上游服务器报错 "Request with a GET or HEAD method cannot have a body"。
	// http.Server 传入的 Request.Body 即使为空也是一个非 nil 的 Reader。
	if r.Method == "GET" || r.Method == "HEAD" {
		r.Body = nil
		r.ContentLength = 0
	}

	resp, err := h.proxy.Client.Do(r)
	if err != nil {
		logDebug("[%s] Forward error: %v", h.targetHost, err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	logDebug("[%s] Response received: %s", h.targetHost, resp.Status)

	// 4. 应用响应拦截器
	if h.proxy.ResponseInterceptor != nil {
		if err := h.proxy.ResponseInterceptor.OnResponse(resp); err != nil {
			logDebug("[%s] Response intercepted error: %v", h.targetHost, err)
			http.Error(w, "Response Intercepted", http.StatusBadGateway)
			return
		}
	}

	// 5. 写回响应
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

// SingleConnListener 将单个 net.Conn 适配为 net.Listener。
// 用于让 http.Server 服务于一个已经建立的连接。
type SingleConnListener struct {
	conn net.Conn
	mu   sync.Mutex
	done bool
}

func (l *SingleConnListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.done {
		// 阻塞直到 Close 被调用，或者直接返回 Closed。
		// http.Server 在 Accept 返回错误时会停止。
		// 为了防止 Server 自旋，这里应该只返回一次 Conn，第二次返回 Error。
		return nil, net.ErrClosed
	}
	l.done = true
	return l.conn, nil
}

func (l *SingleConnListener) Close() error {
	return nil
}

func (l *SingleConnListener) Addr() net.Addr {
	return l.conn.LocalAddr()
}

// --- Filters & Interceptors ---

// RequestInterceptor 定义了请求拦截器接口。
type RequestInterceptor interface {
	// OnRequest 在请求发送给上游前调用。
	// 注意：若要修改 Host 头，请直接修改 req.Host 字段，而非 req.Header。
	OnRequest(req *http.Request) error
}

// ResponseInterceptor 定义了响应拦截器接口。
type ResponseInterceptor interface {
	OnResponse(resp *http.Response) error
}
