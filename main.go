/*
Package main 提供了 WeWeGo 高性能 HTTPS 代理工具的实现。

WeWeGo 是一个基于 中间人攻击 (MITM) 技术的代理服务器，主要用于 HTTPS 流量的透明拦截、检查与过滤。
其核心功能包括：
1. 动态签发受信任的根证书 (CA)。
2. 针对目标域名实时生成并缓存中间人证书。
3. 支持 HTTP CONNECT 隧道的劫持与解密。
4. 提供可扩展的请求/响应过滤接口。

设计模式：
- 采用单例/配置模式管理代理服务器。
- 使用 LRU 缓存算法优化证书生成性能。
- 插件化过滤器设计，支持自定义流量处理逻辑。

并发安全性：
- 证书管理器 (CertManager) 采用互斥锁 (sync.Mutex) 保证并发环境下证书签发与缓存的一致性。
- 代理服务器为每个连接启动独立的 Goroutine 处理，具备高并发处理能力。

版本：v1.0.0
*/
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
	flag.CommandLine.Parse(os.Args[2:])

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
		},
	}

	// 如果指定了上游代理，则配置 Transport 使用该代理
	if upstreamURL != nil {
		transport.Proxy = http.ProxyURL(upstreamURL)
	} else {
		// 显式禁用系统代理，确保上游连接为直接连接
		transport.Proxy = nil
	}

	proxy := &ProxyServer{
		CertManager:   cm,
		UpstreamProxy: upstreamURL,
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
		log.Printf("Received signal %v, shutting down...", sig)

		// 给现有连接 5 秒的处理宽限期
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			log.Printf("Server shutdown error: %v", err)
		}
	}()

	log.Printf("Starting proxy on %s", *listenAddr)
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
	if os.Getenv("PROXY_DEBUG") == "1" {
		log.Printf("[DEBUG] Generating cert for %s", domain)
	}

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
	CertManager   *CertManager // 证书管理器，用于 MITM
	Client        *http.Client // 用于向上游服务器发起请求的客户端
	UpstreamProxy *url.URL     // 可选的上游代理服务器
}

// bufferedConn 用于包装 net.Conn 并处理 bufio.Reader 中的缓冲数据。
type bufferedConn struct {
	net.Conn
	r io.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) {
	return b.r.Read(p)
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
// 4. 同时与真实上游服务器建立 TLS 连接。
// 5. 调用 transferWithLogging 开始解密并转发流量。
func (p *ProxyServer) handleConnect(w http.ResponseWriter, r *http.Request) {
	destHost := r.URL.Host
	host, _, _ := net.SplitHostPort(destHost)
	if host == "" {
		host = destHost
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	// 1. 劫持底层 TCP 连接
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	// 2. 响应客户端 CONNECT 请求
	_, err = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if err != nil {
		clientConn.Close()
		return
	}

	// 3. 执行中间人 (MitM) TLS 握手
	cert, err := p.CertManager.GetCertificate(host)
	if err != nil {
		log.Printf("Failed to get certificate for %s: %v", host, err)
		clientConn.Close()
		return
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		MinVersion:   tls.VersionTLS12,
	}

	// 作为服务器与客户端握手
	tlsClientConn := tls.Server(clientConn, tlsConfig)
	if err := tlsClientConn.Handshake(); err != nil {
		if os.Getenv("PROXY_DEBUG") == "1" {
			log.Printf("[DEBUG] TLS handshake failed with client for %s: %v", host, err)
		}
		tlsClientConn.Close()
		return
	}
	defer tlsClientConn.Close()

	// 4. 与真实上游服务器建立 TLS 连接
	var upstreamConn net.Conn
	if p.UpstreamProxy != nil {
		// 4.1 通过上游代理建立连接
		proxyConn, err := net.DialTimeout("tcp", p.UpstreamProxy.Host, 10*time.Second)
		if err != nil {
			log.Printf("Failed to connect to upstream proxy %s: %v", p.UpstreamProxy.Host, err)
			return
		}

		// 4.2 发送 CONNECT 请求建立隧道
		connectReq := &http.Request{
			Method: http.MethodConnect,
			URL:    &url.URL{Opaque: destHost},
			Host:   destHost,
			Header: make(http.Header),
		}
		if err := connectReq.Write(proxyConn); err != nil {
			proxyConn.Close()
			log.Printf("Failed to write CONNECT request to proxy: %v", err)
			return
		}

		// 4.3 读取代理响应
		br := bufio.NewReader(proxyConn)
		resp, err := http.ReadResponse(br, connectReq)
		if err != nil {
			proxyConn.Close()
			log.Printf("Failed to read CONNECT response from proxy: %v", err)
			return
		}
		if resp.StatusCode != http.StatusOK {
			proxyConn.Close()
			log.Printf("Proxy returned non-200 status: %s", resp.Status)
			return
		}

		// 4.4 在建立的隧道上进行 TLS 客户端握手
		// 注意：需使用 br 确保不丢失 http.ReadResponse 已读取的缓冲数据
		var combinedConn net.Conn = &bufferedConn{Conn: proxyConn, r: io.MultiReader(br, proxyConn)}
		tlsUpstreamConn := tls.Client(combinedConn, &tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: host,
		})
		if err := tlsUpstreamConn.Handshake(); err != nil {
			tlsUpstreamConn.Close()
			log.Printf("TLS handshake with upstream %s via proxy failed: %v", destHost, err)
			return
		}
		upstreamConn = tlsUpstreamConn
	} else {
		// 4.1 直接与真实上游建立 TLS 连接
		var err error
		upstreamConn, err = tls.Dial("tcp", destHost, &tls.Config{
			MinVersion: tls.VersionTLS12,
		})
		if err != nil {
			log.Printf("Failed to connect to upstream %s: %v", destHost, err)
			return
		}
	}
	defer upstreamConn.Close()

	if os.Getenv("PROXY_DEBUG") == "1" {
		log.Printf("[DEBUG] MitM Session started for %s", host)
	}

	// 5. 开始双向解密转发
	p.transferWithLogging(tlsClientConn, upstreamConn, host)

	if os.Getenv("PROXY_DEBUG") == "1" {
		log.Printf("[DEBUG] MitM Session closed for %s", host)
	}
}

// transferWithLogging 管理客户端与服务器之间的解密流量转发。
//
// 核心逻辑：
// 采用双向循环，从客户端读取请求并应用 RequestFilter，然后转发给服务器；
// 从服务器读取响应并应用 ResponseFilter，然后转发给客户端。
//
// 约束：
// 该方法会一直阻塞直到连接断开。
func (p *ProxyServer) transferWithLogging(client net.Conn, server net.Conn, host string) {
	clientReader := bufio.NewReader(client)
	serverReader := bufio.NewReader(server)

	for {
		// 1. 读取并解析客户端解密后的 HTTP 请求
		req, err := http.ReadRequest(clientReader)
		if err != nil {
			if err != io.EOF && !strings.Contains(err.Error(), "closed") {
				if os.Getenv("PROXY_DEBUG") == "1" {
					log.Printf("[DEBUG] Error reading request from %s: %v", host, err)
				}
			}
			return
		}

		if os.Getenv("PROXY_DEBUG") == "1" {
			log.Printf("[DEBUG] [%s] Request received", host)
		}

		// 2. 应用请求过滤器 (可在此时修改 Header 或拦截请求)
		if err := DefaultRequestFilter(req); err != nil {
			if os.Getenv("PROXY_DEBUG") == "1" {
				log.Printf("[DEBUG] [%s] Request filtered: %v", host, err)
			}
			return
		}

		// 3. 将请求转发给真实上游服务器
		if err := req.Write(server); err != nil {
			if os.Getenv("PROXY_DEBUG") == "1" {
				log.Printf("[DEBUG] [%s] Error writing to server: %v", host, err)
			}
			return
		}

		// 4. 读取真实上游服务器的响应
		resp, err := http.ReadResponse(serverReader, req)
		if err != nil {
			if err != io.EOF && !strings.Contains(err.Error(), "closed") {
				if os.Getenv("PROXY_DEBUG") == "1" {
					log.Printf("[DEBUG] [%s] Error reading response: %v", host, err)
				}
			}
			return
		}

		if os.Getenv("PROXY_DEBUG") == "1" {
			log.Printf("[DEBUG] [%s] Response received: %s", host, resp.Status)
		}

		// 5. 应用响应过滤器 (可在此时注入脚本或记录数据)
		if err := DefaultResponseFilter(resp); err != nil {
			if os.Getenv("PROXY_DEBUG") == "1" {
				log.Printf("[DEBUG] [%s] Response filtered: %v", host, err)
			}
			return
		}

		// 6. 将响应写回客户端
		if err := resp.Write(client); err != nil {
			if os.Getenv("PROXY_DEBUG") == "1" {
				log.Printf("[DEBUG] [%s] Error writing to client: %v", host, err)
			}
			return
		}
		resp.Body.Close()
	}
}

// handleHTTP 处理普通的 HTTP 请求。
// 当前策略：仅作为占位符，因为绝大多数流量已在 ServeHTTP 中重定向至 HTTPS。
func (p *ProxyServer) handleHTTP(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Plain HTTP not supported, use HTTPS", http.StatusForbidden)
}

// --- Filters ---

// RequestFilter 定义了请求过滤器的函数签名。
type RequestFilter func(*http.Request) error

// ResponseFilter 定义了响应过滤器的函数签名。
type ResponseFilter func(*http.Response) error

// DefaultRequestFilter 是默认的请求过滤器，不执行任何操作。
var DefaultRequestFilter RequestFilter = func(req *http.Request) error {
	return nil
}

// DefaultResponseFilter 是默认的响应过滤器，不执行任何操作。
var DefaultResponseFilter ResponseFilter = func(resp *http.Response) error {
	return nil
}
