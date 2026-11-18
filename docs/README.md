# CyberBus 开发文档

从 [应用接入指南](INTEGRATION.md) 开始，再按 [构建与打包](BUILDING.md) 准备目标平台。CyberBus 把 EasyTier、Noise、OIDC/PKCE 和 Protobuf 组合为一个原生 SDK；应用只通过命令、结果和事件访问能力。

[协议](protocol.md) 是跨语言契约，[SDK API](sdk-api.md) 解释状态机，[native-bindings.md](native-bindings.md) 解释 ABI 所有权。需要自部署登录服务时阅读 [logto-deployment.md](logto-deployment.md)，需要网络兜底时阅读 [CLOUDFLARE_FALLBACK.md](CLOUDFLARE_FALLBACK.md)。

当前仍有真实跨平台运行和规模验证边界，见 [UNRESOLVED.md](UNRESOLVED.md)。
