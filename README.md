# CyberBus

CyberBus 是一个可嵌入应用的 Rust 多平台 SDK：应用通过统一的 Protobuf 命令、结果和事件接口完成 OIDC/PKCE 登录、EasyTier 设备发现、端到端加密消息以及可选 RPC。核心网络和凭证材料由 SDK 管理，宿主应用只负责 UI、业务 Protobuf 和平台存储适配。

> 当前仓库是源码和本地打包工程，版本 `0.1.0` 尚未声明已发布到 crates.io、Maven Central 或 Swift Package Index。部署配置必须替换为你自己的 OIDC issuer、native client、resource 和中继地址。

## 给接入方的最快路径

1. 阅读 [应用接入指南](docs/INTEGRATION.md)，先确定存储、事件线程和生命周期边界。
2. 用 [构建指南](docs/BUILDING.md) 编译 Rust、C/JNI、Android 或 Apple 目标。
3. 复制 [公共配置示例](deploy/test-client.json) 为你自己的配置，只保留公开 pin；不要加入 token、seed、client secret 或管理凭据。
4. 从 [协议 schema](proto/cyberbus/easytier/v1/sdk.proto) 生成应用消息；命令和事件都使用 Protobuf bytes。
5. 运行 `cargo run -p cyberbus --example sdk_lifecycle` 验证离线创建、事件消费和关闭流程，再接入真实登录。

## 最小架构

```text
应用 UI / 业务线程
        │  SdkCommand / SdkResult / SdkEvent (Protobuf)
        ▼
CyberBus Client ── OIDC/PKCE ── 你的 Logto/OIDC 服务
        │
        ├── EasyTier + Noise：认证后的设备网络和业务消息
        └── 可选 Cloudflare Quick Tunnel WSS 兜底（默认关闭）
```

网络登录成功不会自动开网；应用必须明确提交 `NetworkStart`。每个实例只有一个事件消费者，发送结果只代表 SDK 已受理，最终设备状态和业务 ACK 通过关联事件返回。

## 主要入口

- [应用接入指南](docs/INTEGRATION.md)：Rust、C/JNI、Android、Swift 的初始化、登录、设备、数据和关闭顺序。
- [构建与打包](docs/BUILDING.md)：工具链、离线 smoke、平台依赖和本地包。
- [Cloudflare WSS 兜底](docs/CLOUDFLARE_FALLBACK.md)：官方 `cloudflared` connector 的可选配置和限制。
- [协议与消息](docs/protocol.md) / [SDK API 细节](docs/sdk-api.md)：字段、状态机、ACK、RPC 和事件约束。
- [原生绑定](docs/native-bindings.md)：C ABI、JNI、Swift 的 buffer 所有权与存储边界。
- [认证部署参考](docs/logto-deployment.md)：自部署 OIDC/Logto 时的安全要求；不会替你部署服务。
- [当前未解决事项](docs/UNRESOLVED.md)：已知真实跨平台、网络恢复和规模验证边界。

## 安全边界

公开配置只描述 issuer、client、resource、redirect URI、bootstrap peer 和功能策略。SDK 不接受 token、refresh token、seed、app PSK 或管理员密钥作为配置输入。`DevelopmentFileStore` 是明文开发存储，只适合受信测试目录；生产应用应实现带机密性、完整性、原子替换和唯一所有者的 `SecureStore`，或显式启用平台 keyring。

## 状态

核心 Rust SDK、协议、C/JNI 包装、Android sample、EasyTier 探针以及可选 Cloudflare connector 已在源码中。完整的 Windows/iOS 运行时、跨网络 ACK 恢复、256 节点规模和所有平台消费者验收仍在 [未解决事项](docs/UNRESOLVED.md) 中，不能用单元测试或包构建替代。

许可证：CyberBus 自有代码采用 [MIT](LICENSE-MIT) 或 [Apache-2.0](LICENSE-APACHE)；`vendor/easytier` 按其随附许可证和 [NOTICE](packaging/NOTICE.md) 使用。
