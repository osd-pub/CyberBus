# Cloudflare Quick Tunnel WSS 兜底

CyberBus 可选地使用官方 `cloudflared` connector，把 EasyTier 的 WebSocket 入口暴露为临时匿名 WSS relay。功能默认关闭，Cloudflare 只承载外层连接；Noise、账号授权和业务 ACK 仍由 CyberBus 验证。SDK 不自动下载二进制、不登录 Cloudflare、不改变 TUN、系统路由或 DNS。

## 启动 relay

```sh
cargo build -p cyberbus-transport --example cloudflare_relay --features cloudflared
./target/debug/examples/cloudflare_relay /absolute/path/to/cloudflared
# READY wss://<random>.trycloudflare.com/
# 输入换行或 EOF 关闭并回收 connector
```

Rust 宿主启用 `cyberbus` 的 `cloudflared` feature 后，可以使用 `CloudflareRelay::start(CloudflareRelayConfig)`、`endpoint()`、`subscribe_state()` 和 `close()`。启动超时、Drop、取消和子进程退出都有明确状态；宿主必须保持 Tokio runtime 直到 close 完成。

## SDK 配置

所有参与设备使用同一个当前存活的 URL：

```json
{
  "bootstrap_peers": ["tcp://relay.example.invalid:11010"],
  "cloudflare_fallback": {
    "peers": ["wss://<random>.trycloudflare.com/"],
    "after_ms": 10000
  }
}
```

省略或设为 `null` 即关闭。`after_ms` 默认 10 秒，支持范围为 1 秒到 300 秒，最多 4 个 `wss://<single-label>.trycloudflare.com/` URL。客户端校验公共 CA、主机名、443 端口、路径和无查询参数；WSS 不接受自签名证书。Android 客户端只需 URL，不需安装 cloudflared。

正常路径先启动。持续没有远端虚拟设备路由达到延迟后才加入 WSS；已有远端路由会重置等待计时。它不会替换已有主路径、重复发送业务或因单个远端设备不可达而强行启用。关闭 NetworkStop 或 SdkClose 时一起关闭。

Cloudflare Quick Tunnel 的 URL 每次启动都可能变化，分发和撤换由宿主负责。它是临时开发兜底，不是生产中继、可用性承诺或业务成功证明。参考官方 [Quick Tunnels](https://developers.cloudflare.com/tunnel/get-started/quick-tunnels/) 与 [WebSockets](https://developers.cloudflare.com/network/websockets/)。
