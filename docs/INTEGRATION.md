# CyberBus 应用接入指南

本文面向把 CyberBus 嵌入桌面、Android 或 Apple 应用的开发者。实现的权威定义是 `proto/cyberbus/easytier/v1/sdk.proto` 和 `common.proto`；本文解释调用顺序和容易出错的边界。

## 1. 安装和公共配置

源码 workspace 中直接依赖：

```toml
[dependencies]
cyberbus = { git = "https://github.com/osd-pub/CyberBus.git", tag = "v0.1.0" }
cyberbus-auth = { git = "https://github.com/osd-pub/CyberBus.git", tag = "v0.1.0" }
prost = "0.14"
tokio = { version = "1.48", features = ["rt-multi-thread", "macros", "time"] }
```

在仓库尚未创建 release tag 前，也可以使用 `path` 依赖或固定 commit。SDK 当前没有把包发布到公共 registry。公共 JSON 的最小形状是：

```json
{
  "issuer": "https://auth.example.com/oidc",
  "client_id": "example-native-client",
  "resource": "https://api.example.com/cyberbus",
  "product_id": "my-app",
  "native_clients": {"example-native-client": "my-app"},
  "redirect_uri": "http://127.0.0.1:18765/callback",
  "bootstrap_peers": ["tcp://relay.example.invalid:11010"],
  "offline_access": true,
  "enable_p2p": true,
  "persist_grant": false
}
```

Android 把 redirect URI 换成 `cyberbus://auth/callback`。`native_clients` 是允许的 client 到 product 映射；`bootstrap_peers` 只是传输入口，不是业务授权。`ClientConfig::from_json` 会拒绝 token、seed、secret、PSK 等字段和未知的 Cloudflare 字段。

## 2. 创建实例和事件消费者

创建时必须明确选择存储意图：首次可信安装用 `StoreMode::CreateNew`，已有安装用 `StoreMode::Existing`。已有状态缺失、损坏或 marker 不匹配必须失败；不能捕获错误后自动改成新建。快速离线 smoke 可以使用易失的 `MemoryStore`，开发文件存储使用 `DevelopmentFileStore`：

```rust
use cyberbus::{Client, ClientConfig, StoreMode};
use cyberbus_auth::MemoryStore;

let config = ClientConfig::from_json(public_json)?;
let client = Client::new(
    config,
    Box::new(MemoryStore::default()),
    StoreMode::CreateNew,
).await?;
let mut events = client.take_event_receiver().await.expect("one consumer");
// 在提交第一个业务命令前启动专用事件任务。
let first = events.recv().await;
```

`take_event_receiver` 只能成功一次。UI 不应直接占用它，也不应让慢 UI 阻塞命令 owner；请在独立任务中把事件转换成应用状态。`poll_event(timeout)` 的超时和 EOF 都返回 `None`，原生绑定会另外报告终止状态。

## 3. 登录、恢复和开网

提交 `AuthStart { intent: LOGIN | REGISTER }` 后，`SdkResult.auth_started` 返回 `operation_id` 和 `authorization_uri`。宿主打开浏览器或受限 WebView；回调时原样提交同一个 `operation_id` 和完整 callback URI。不要在宿主解析 code、state、nonce，也不要把授权 URL、code 或 token 写日志。等待 `AuthEvent` 进入 `AUTHENTICATED` 后，再显式提交 `NetworkStart`。

冷启动恢复只能由明确的 `AuthRestore` 完成，且需要 `persist_grant=true` 与可靠存储；默认配置是内存授权，重启后应重新登录。`on_resume()` 在应用回到前台或网络恢复前调用，成功后再放开业务按钮。`SdkClose` 是本地实例关闭，`AuthLogout` 才清除授权；关闭时先发送 `SdkClose`，持续消费终态事件直到 EOF，再释放 native handle。

## 4. 设备和公开 Profile

登录后先提交 `UpdatePublicProfile`，再 `NetworkStart`。Profile 只放设备名、版本、能力和应用认为可公开的配置；不要放 host name、路径、token、seed 或私有业务设置。调用 `WatchDevices` 后，第一条事件是 snapshot，之后按 revision 处理 added/updated/offline/removed/reset。查询使用唯一的 16 字节 `query_id`；设备 ID 是 32 字节，来自 SDK 安装身份，应用不可自行生成替换。

`SdkResult` 是同步接纳结果。`GetDevices`、`GetDeviceDescriptor`、`RefreshDevices` 的最终结果在带相同 ID 的 `SdkEvent` 中交付；超时、partial、reset 和 UNKNOWN_OUTCOME 都必须由应用显式呈现，不能把空结果当成成功。

## 5. 应用数据与 RPC

应用自定义消息定义在自己的 `.proto` 中，使用 `DataMessage.fragment.application_type_url` 标识类型，并通过 `SubscribeData` 声明接收类型。发送方提交 `Send` 后，按 `DataStatus` 的 `RECEIVED`、`ACCEPTED`、`PROCESSED` 分阶段展示；接收应用完成自己的业务处理后才提交 `CompleteData(PROCESSED)`。业务完成前崩溃或连接丢失可能产生 `UNKNOWN_OUTCOME`，SDK 不会自动重放非幂等消息。

RPC 需要先通过 `RegisterHandler` 声明 method、请求/响应类型和 descriptor，再处理 `RpcEvent`，并按 `GrantRpcWindow` 管理信用窗口。注册 handler 不会自动实现业务；能力只有在应用确实能处理时才应写入 Profile。

## 6. C、JNI、Android、Swift

C ABI 位于 `include/cyberbus.h`：输入 buffer 只借用，输出 buffer 只能用 `cyberbus_buffer_free` 释放；所有结果仍是 Protobuf bytes。JNI `byte[]` 在边界复制，store callback 的 GlobalRef 要保持到 native close 完成。Android API 包装位于 `packaging/android-sdk/sdk`，构建使用 `scripts/package-android-sdk.sh`；sample 的 JNI glue 在 `examples/android-demo`。Swift wrapper 与 XCFramework 构建入口见 `packaging/apple` 和 [构建指南](BUILDING.md)。

所有绑定都遵循同一个顺序：启动事件消费者 → 创建/恢复 → Auth → Profile → NetworkStart → 业务 → SdkClose/排空 → close。平台生命周期只负责把系统回调转为这些明确操作，不应在 Kotlin/Swift/C 层复制授权、网络或 ACK 状态机。

## 7. 最小检查清单

- 配置不含任何凭据，issuer/resource/client 是你自己的部署值。
- 首次安装和已安装打开路径由宿主显式选择。
- 事件消费者在第一个命令之前启动，并且全程只有一个。
- 登录回调使用原始 URI 和 operation ID，SDK 负责 PKCE/OIDC 校验。
- Authenticated、NetworkStart、远端 snapshot、ACK 终态分别处理。
- 本地开发存储目录、授权 callback 和构建产物加入忽略规则。
- 关闭时先交付 `SdkClose`，再排空事件并释放 native 资源。

EasyTier 的裸字节连通性诊断见 `scripts/diagnose-easytier.py`；它只验证传输，不证明 Noise、账号授权或业务 ACK。Cloudflare 可选兜底见 [CLOUDFLARE_FALLBACK.md](CLOUDFLARE_FALLBACK.md)。
