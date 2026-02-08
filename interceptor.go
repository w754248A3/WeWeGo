package main

import (
	"net/http"
	"net/url"
)

// DemoInterceptor 演示了如何同时实现请求和响应拦截器。
// 它展示了修改路径、添加/删除 Header 的功能。
type DemoInterceptor struct{
	UpstreamHost string // 上游代理主机名/IP
	PathReplace  string // 替换路径的字符串
}

func NewDemoInterceptor(upstreamHost, pathReplace string) *DemoInterceptor {
	return &DemoInterceptor{
		UpstreamHost: upstreamHost,
		PathReplace:  pathReplace,
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

	var urlValue = req.URL.String()
	//log.Printf("[DemoInterceptor] Request URL: %s", url)

	// 1. 修改路径
	newURL, err := url.Parse("https://" + d.UpstreamHost + d.PathReplace)
	if err != nil {
		logDebug("[DemoInterceptor] Error parsing URL: %v", err)
		return err
	}
	req.URL = newURL
	// 2. 修改 Host 头 (必须直接修改 req.Host 字段)
	req.Host = d.UpstreamHost
	
	// 3. 删除 Header 中的 Host 字段
	req.Header.Del("Host")
	req.Header.Del("host")

	req.Header.Set("Host", d.UpstreamHost)

	// 4. 添加/设置 Header
	logDebug("head url: %s", urlValue)
	req.Header.Set("X-Upstream-Url", urlValue)

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
