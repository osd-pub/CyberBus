# cyberbus-auth

认证 crate 提供 OIDC/PKCE、凭证校验、账号绑定、授权状态和 `SecureStore` 契约。宿主只传公共部署配置；token、网络 seed、app PSK 和私有网络材料不会出现在 SDK Protobuf 结果中。

首次使用选择 `StoreMode::CreateNew`，已安装状态选择 `StoreMode::Existing`。`DevelopmentFileStore` 是明文开发存储，`MemoryStore` 仅用于易失测试；打开失败不能自动降级为新建。生产宿主应提供带机密性、完整性、原子替换和唯一 owner 的实现。

具体操作和事件顺序见根目录 [应用接入指南](../../docs/INTEGRATION.md) 与 [安全策略](../../docs/security.md)。
