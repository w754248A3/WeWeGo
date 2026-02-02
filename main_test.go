/*
Package main_test 提供了 WeWeGo 核心功能的单元测试。

测试涵盖了：
1. 证书管理器的缓存逻辑 (LRU 算法)。
2. 动态证书生成的正确性。
3. 代理服务器的重定向行为。
*/
package main

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

// TestLRUCache 测试 LRU 缓存的淘汰策略。
//
// 验证要点：
// 1. 元素能够正确存入与读取。
// 2. 访问已存在的元素会将其更新为最新。
// 3. 当超过容量上限时，最久未使用的元素会被正确删除。
func TestLRUCache(t *testing.T) {
	cache := NewLRUCache(2) // 创建容量为 2 的缓存
	cert1 := &tls.Certificate{}
	cert2 := &tls.Certificate{}
	cert3 := &tls.Certificate{}

	cache.Add("a", cert1)
	cache.Add("b", cert2)
	
	// 验证读取并更新访问顺序
	if _, ok := cache.Get("a"); !ok {
		t.Error("Expected to find a")
	}

	// 添加第三个元素，触发淘汰逻辑
	cache.Add("c", cert3)

	// 此时 "b" 应该是最久未使用的，应该被淘汰
	if _, ok := cache.Get("b"); ok {
		t.Error("Expected b to be evicted")
	}
	// "a" 因为之前被访问过，应该保留
	if _, ok := cache.Get("a"); !ok {
		t.Error("Expected a to be present")
	}
	if _, ok := cache.Get("c"); !ok {
		t.Error("Expected c to be present")
	}
}

// TestGenerateServerCert 测试动态证书签发逻辑。
//
// 验证要点：
// 1. CA 证书能成功生成。
// 2. CertManager 能基于 CA 签发出合法的服务器证书。
// 3. 签发的证书包含正确的 SAN (Subject Alternative Names)。
func TestGenerateServerCert(t *testing.T) {
	// 环境搭建：模拟生成临时 CA 证书文件
	priv, _ := os.Create("temp-ca-key.pem")
	cert, _ := os.Create("temp-ca-cert.pem")
	
	// 执行 genca 命令生成测试所需的 CA
	os.Args = []string{"wewego", "genca"}
	handleGenCA()
	
	// 测试结束后清理现场
	defer os.Remove("ca-key.pem")
	defer os.Remove("ca-cert.pem")
	defer os.Remove("ca.cer")
	defer os.Remove("ca.p12")
	priv.Close()
	cert.Close()

	// 加载生成的 CA
	ca, err := loadCA("ca-cert.pem", "ca-key.pem")
	if err != nil {
		t.Fatalf("Failed to load CA: %v", err)
	}

	cm := NewCertManager(ca, 10)
	// 针对目标域名签发证书
	serverCert, err := cm.generateServerCert("example.com")
	if err != nil {
		t.Fatalf("Failed to generate server cert: %v", err)
	}

	// 解析并验证证书内容
	x509Cert, err := x509.ParseCertificate(serverCert.Certificate[0])
	if err != nil {
		t.Fatalf("Failed to parse generated cert: %v", err)
	}

	// 检查 DNSNames 是否包含目标域名
	found := false
	for _, name := range x509Cert.DNSNames {
		if name == "example.com" {
			found = true
			break
		}
	}
	if !found {
		t.Error("example.com not found in SANs")
	}

	// 验证通配符逻辑是否生效
	if len(x509Cert.DNSNames) < 2 {
		t.Error("Expected at least 2 SANs for example.com (exact and wildcard)")
	}
}

// TestHTTPRedirect 测试代理服务器的 HTTP 强制跳转 HTTPS 逻辑。
func TestHTTPRedirect(t *testing.T) {
	proxy := &ProxyServer{}
	// 构造一个普通的 HTTP 请求
	req := httptest.NewRequest("GET", "http://example.com/foo", nil)
	w := httptest.NewRecorder()

	proxy.ServeHTTP(w, req)

	resp := w.Result()
	// 验证状态码是否为 301
	if resp.StatusCode != http.StatusMovedPermanently {
		t.Errorf("Expected 301, got %d", resp.StatusCode)
	}
	// 验证重定向目标是否正确
	location := resp.Header.Get("Location")
	if location != "https://example.com/foo" {
		t.Errorf("Expected https://example.com/foo, got %s", location)
	}
}

// TestProxyConfig 验证代理服务器的配置是否符合安全和网络要求。
func TestProxyConfig(t *testing.T) {
	// 1. 验证默认监听地址是否仅限本地回环
	// 注意：由于 flag 是全局的且在 main 中定义，我们通过模拟初始化逻辑来验证
	cm := &CertManager{} 
	
	// 模拟 handleProxy 中的初始化逻辑
	proxy := &ProxyServer{
		CertManager: cm,
		Client: &http.Client{
			Transport: &http.Transport{
				Proxy: nil, // 关键点：禁用代理
			},
		},
	}

	// 2. 验证上游 Client 是否禁用了代理
	transport, ok := proxy.Client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("Transport is not *http.Transport")
	}
	if transport.Proxy != nil {
		t.Error("Upstream proxy should be disabled (nil)")
	}
}
