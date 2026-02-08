package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// --- Concurrency Tests ---

// TestCertManager_Concurrency 验证 CertManager 在高并发下的线程安全性。
// 重点检查是否存在数据竞争 (需配合 go test -race 使用)。
func TestCertManager_Concurrency(t *testing.T) {
	// 1. 初始化 CertManager
	// 使用自签名 CA 方便测试
	caCert, caKey, err := generateTempCA()
	if err != nil {
		t.Fatalf("Failed to generate temp CA: %v", err)
	}
	ca, err := tls.X509KeyPair(caCert, caKey)
	if err != nil {
		t.Fatalf("Failed to load temp CA: %v", err)
	}

	cm := NewCertManager(ca, 10)
	domain := "concurrent.test.com"

	// 2. 启动多个 Goroutine 并发获取证书
	concurrency := 50
	var wg sync.WaitGroup
	wg.Add(concurrency)

	start := time.Now()
	for i := 0; i < concurrency; i++ {
		go func() {
			defer wg.Done()
			cert, err := cm.GetCertificate(domain)
			if err != nil {
				t.Errorf("GetCertificate failed: %v", err)
				return
			}
			if cert == nil {
				t.Errorf("Returned nil certificate")
			}
		}()
	}
	wg.Wait()
	duration := time.Since(start)
	t.Logf("Processed %d requests in %v", concurrency, duration)

	// 3. 验证缓存状态
	// 虽然并发请求，但最终缓存中应该只有一个 entry (或者被更新多次，但结构完整)
	cm.mu.Lock()
	if _, ok := cm.cache.Get(domain); !ok {
		t.Errorf("Certificate not found in cache after concurrent access")
	}
	cm.mu.Unlock()
}

// generateTempCA 辅助函数：生成临时 CA 供测试使用
func generateTempCA() ([]byte, []byte, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	
	privBytes, _ := x509.MarshalPKCS8PrivateKey(priv)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})

	return certPEM, keyPEM, nil
}

// --- Resource Cleanup Tests ---

// MockConn 模拟 net.Conn 用于追踪 Close 调用
type MockConn struct {
	net.Conn
	Closed int32 // 原子计数器
	ReadBuffer *bytes.Buffer
	WriteBuffer *bytes.Buffer
}

func NewMockConn(data string) *MockConn {
	return &MockConn{
		ReadBuffer: bytes.NewBufferString(data),
		WriteBuffer: new(bytes.Buffer),
	}
}

func (m *MockConn) Read(b []byte) (n int, err error) {
	return m.ReadBuffer.Read(b)
}

func (m *MockConn) Write(b []byte) (n int, err error) {
	return m.WriteBuffer.Write(b)
}

func (m *MockConn) Close() error {
	atomic.AddInt32(&m.Closed, 1)
	return nil
}

func (m *MockConn) SetDeadline(t time.Time) error { return nil }
func (m *MockConn) SetReadDeadline(t time.Time) error { return nil }
func (m *MockConn) SetWriteDeadline(t time.Time) error { return nil }


