package main

import (
	"context"
	"net"
	"time"
)

func NewUserDNS(customDNSServer string) *net.Dialer {

	// 1. 定义自定义的 Resolver
	// 这里通过覆盖 Dial 方法，强制所有的 DNS 查询都走 udp 协议去连接 customDNSServer
	resolver := &net.Resolver{
		PreferGo: true, // 强制使用 Go 内置的 Resolver，而不是 CGO (系统) Resolver
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: time.Millisecond * time.Duration(2000), // 设置 DNS 查询超时时间
			}
			// address 参数原本是系统默认的 DNS 地址，这里我们要忽略它，
			// 强制返回连接到我们自定义 DNS 服务器的连接。
			return d.DialContext(ctx, "udp", customDNSServer)
		},
	}

	// 2. 创建一个使用该 Resolver 的 Dialer
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		Resolver:  resolver, // 注入自定义 Resolver
	}

	return dialer
}
