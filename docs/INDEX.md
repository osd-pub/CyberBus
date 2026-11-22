# 文档索引

- [应用接入指南](INTEGRATION.md)：给 Rust、C/JNI、Android、Swift 应用开发者。
- [Web SDK](WEB_SDK.md)：浏览器 Logto SPA、Web Crypto 凭证派生、EasyTier WebAssembly 和出站 TCP。
- [构建与打包](BUILDING.md)：工具链、平台依赖、离线 smoke 和发布检查。
- [协议](protocol.md)：Protobuf schema、消息、ACK、RPC 和 descriptor。
- [SDK API](sdk-api.md)：命令、事件、认证、目录和存储语义。
- [原生绑定](native-bindings.md)：C ABI、JNI、Swift 的内存和生命周期。
- [安全策略](security.md)：凭证、存储、租约和 block 状态。
- [Logto/OIDC 部署](logto-deployment.md)：自部署服务的公共配置和安全要求。
- [Cloudflare 兜底](CLOUDFLARE_FALLBACK.md)：可选官方 cloudflared Quick Tunnel WSS relay。
- [未解决事项](UNRESOLVED.md)：当前实现的验证边界和后续工作。

协议源码在 `proto/`，Rust crates 在 `crates/`，平台 sample 在 `examples/`，打包代码在 `packaging/`。历史实验报告、私有部署脚本、工作树和带本机路径的证据不属于公开 SDK 接入面。
