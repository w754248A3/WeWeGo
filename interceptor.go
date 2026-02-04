package main

import (
	"log"
	"net/http"
)

// FixedInterceptor 是一个始终返回固定配置的拦截器实现。
type FixedInterceptor struct {
	FixedResolveHost string // 固定的解析目标主机名/IP
	FixedUpstreamSNI string // 固定的上游 TLS SNI
}

// NewFixedInterceptor 创建一个新的固定配置拦截器。
func NewFixedInterceptor(resolveHost, upstreamSNI string) *FixedInterceptor {
	return &FixedInterceptor{
		FixedResolveHost: resolveHost,
		FixedUpstreamSNI: upstreamSNI,
	}
}

// OnIntercept 实现 DNSAndSNIInterceptor 接口。
// 它会根据是否配置了上游代理动态决定是否启用远程解析。
func (i *FixedInterceptor) OnIntercept(ctx *InterceptContext) (*InterceptResult, error) {
	log.Printf("[FixedInterceptor] Request for %s:%s (SNI: %s). Result: ResolveHost=%s, UpstreamSNI=%s",
		ctx.TargetHost, ctx.TargetPort, ctx.SNI, i.FixedResolveHost, i.FixedUpstreamSNI)

	return &InterceptResult{
		ResolveHost: i.FixedResolveHost,
		UpstreamSNI: i.FixedUpstreamSNI,
	}, nil
}

/*
使用示例 (在 main.go 的 handleProxy 中):

func handleProxy() {
    // ... 前置逻辑
    
    // 创建一个固定将所有请求导向 1.1.1.1 并使用固定 SNI 的拦截器
    interceptor := NewFixedInterceptor("1.1.1.1", "custom.domain.com")
    
    proxy := &ProxyServer{
        CertManager: cm,
        Interceptor: interceptor, // 注册拦截器
        // ... 其他配置
    }
    // ... 后续逻辑
}
*/




// DemoInterceptor 演示了如何同时实现请求和响应拦截器。
// 它展示了修改路径、添加/删除 Header 的功能。
type DemoInterceptor struct{
	UpstreamHost string // 上游代理主机名/IP
}

func NewDemoInterceptor(upstreamHost string) *DemoInterceptor {
	return &DemoInterceptor{
		UpstreamHost: upstreamHost,
	}
}

// OnRequest 处理请求拦截。
// 演示功能：
// 1. 修改请求路径：将路径重置为 / (仅用于演示重写能力)
// 2. 修改 Host 头：将 Host 修改为指定值（需修改 req.Host 字段）
// 3. 删除 Header：Host（防止与 req.Host 冲突导致重复发送）
// 4. 添加 Header：X-Upstream-Url
func (d *DemoInterceptor) OnRequest(req *http.Request) error {
	//log.Printf("[DemoInterceptor] Processing request: %s %s (Host: %s)", req.Method, req.URL.Path, req.Host)

	var url = "https://" + req.Host + req.URL.Path+"?" +req.URL.RawQuery
	//log.Printf("[DemoInterceptor] Request URL: %s", url)

	// 1. 修改路径
	req.URL.Path = "/"

	// 2. 修改 Host 头 (必须直接修改 req.Host 字段)
	req.Host = d.UpstreamHost

	// 3. 删除 Header 中的 Host 字段
	req.Header.Del("Host")
	req.Header.Del("host")

	// 4. 添加/设置 Header
	req.Header.Set("X-Upstream-Url", url)

	return nil
}

// OnResponse 处理响应拦截。
// 演示功能：
// 1. 在响应中添加自定义 Header
func (d *DemoInterceptor) OnResponse(resp *http.Response) error {
	//log.Printf("[DemoInterceptor] Processing response from: %s", resp.Request.Host)

	// 添加响应 Header
	//resp.Header.Set("X-Modified-Response", "true")

	return nil
}

/*
使用示例 (在 main.go 的 handleProxy 中):

func handleProxy() {
    // ... 前置逻辑
    
    demo := &DemoInterceptor{}
    
    proxy := &ProxyServer{
        CertManager: cm,
        RequestInterceptor:  demo, // 注册请求拦截器
        ResponseInterceptor: demo, // 注册响应拦截器
        // ... 其他配置
    }
    // ... 后续逻辑
}
*/
