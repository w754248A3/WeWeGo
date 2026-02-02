# WeWeGo - 高性能 HTTPS 代理工具

WeWeGo 是一个使用 Go 编写的具备 MitM（中间人攻击）能力的 HTTPS 代理工具。它能够动态为目标域名签发证书，从而允许代理服务器查看和修改 HTTPS 流量。

## 功能特性

- **CA 生成**：一键生成自签名 CA 证书及私钥，支持多种格式（PEM, DER, PKCS#12）。
- **动态证书签发**：根据 SNI 自动生成服务器证书，支持通配符域名及 LRU 缓存。
- **HTTP 强制重定向**：自动将所有明文 HTTP 请求重定向至 HTTPS。
- **双向流式转发**：高效的流量转发，支持自定义请求与响应过滤器。
- **优雅关闭**：支持 SIGINT/SIGTERM 信号处理，确保连接正常关闭。

## 快速开始

### 1. 编译

确保已安装 Go 1.21+ 环境，在项目根目录执行：

```bash
go build -o wewego main.go
```

### 2. 生成并导入 CA 证书

首先生成 CA 证书：

```bash
./wewego genca
```

执行后会生成以下文件：
- `ca-cert.pem`: PEM 证书（macOS/Linux 导入）
- `ca-key.pem`: CA 私钥（请妥善保管）
- `ca.cer`: DER 证书（Windows 双击安装）
- `ca.p12`: PKCS#12 证书包（浏览器导入，密码为空）

**安装步骤：**
- **Windows**: 双击 `ca.cer` -> 安装证书 -> 本地计算机 -> 将所有的证书都放入下列存储 -> 浏览 -> **受信任的根证书颁发机构**。
- **浏览器**: 在设置中搜索“证书”，将 `ca.p12` 或 `ca-cert.pem` 导入到“受信任的根证书颁发机构”。

### 3. 启动代理服务器

```bash
./wewego proxy --listen :8443
```

参数说明：
- `--cacert`: CA 证书路径（默认 `ca-cert.pem`）
- `--cakey`: CA 私钥路径（默认 `ca-key.pem`）
- `--listen`: 监听地址（默认 `:8443`）
- `--certCacheSize`: 内存证书缓存数量（默认 200）

### 4. 调试模式

设置环境变量 `PROXY_DEBUG=1` 以查看详细的 TLS 握手及证书生成日志：

```bash
$env:PROXY_DEBUG=1; ./wewego proxy
```

## 自定义过滤器

您可以通过修改 `main.go` 中的 `DefaultRequestFilter` 和 `DefaultResponseFilter` 来实现自定义逻辑。

示例：修改请求头

```go
var DefaultRequestFilter RequestFilter = func(req *http.Request) error {
    req.Header.Set("X-Proxy-By", "WeWeGo")
    return nil
}
```

示例：拦截特定域名

```go
var DefaultRequestFilter RequestFilter = func(req *http.Request) error {
    if strings.Contains(req.Host, "forbidden.com") {
        return fmt.Errorf("access denied")
    }
    return nil
}
```

## 技术细节

- **并发处理**：基于 Go 原生协程，支持高并发连接。
- **内存安全**：证书仅驻留内存，进程退出即销毁。
- **合规性**：仅使用官方标准库及 `x/crypto`。
- **性能**：使用 32KB 缓冲区进行 `io.Copy`。

## 许可证

MIT License
