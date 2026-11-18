# Rust 原生 SDK Protobuf 设计契约 v1

设计基线：2026-11-17。当前实现状态见 [应用接入指南](INTEGRATION.md) 和 [未解决事项](UNRESOLVED.md)。契约入口为 [sdk.proto](../proto/cyberbus/easytier/v1/sdk.proto)，`proto3 package cyberbus.easytier.v1`。本文的 MUST/必须是实现验收约束，Protobuf 编译成功本身不执行尺寸、权限或状态机校验。

## 1. 本轮基线与边界

目标是包含 EasyTier 与 Logto 客户端的 Rust 原生 SDK：浏览器登录/托管注册、同账号设备 watch、双向应用数据、公开设备 config、声明和调用 Protobuf 方法。宿主通过 Rust 对象或语言 adapter 调用，不操作 OAuth grant，也不取得原始 EasyTier 流。所有业务载荷使用 Protobuf binary；没有默认 JSON 编码分支。

本契约与 [技术方案](design.md)、[Logto 签发脚本](../deploy/logto-user-token.js) 使用以下统一基线：

| 项目 | 本契约 |
| --- | --- |
| 账号 seed | 官方 PKCE 登录后，由 Logto custom access token JWT claim 下发 |
| 网络配置 | 同一受验证 JWT claim 中的 `max_devices=256`、`virtual_cidr="10.144.0.0/20"`、`control_port=11000`、`config_version="1"` |
| 地址候选 | `/20` 共 4094 个可用主机地址；路由/peer 视图优先，历史已验证地址次之，有预算的轮转探测兜底 |
| 设备容量 | SDK 正常稳态支持 256 台，含本机；不是无中心状态下的抗恶意全局注册硬上限 |
| 内部转发 | SDK 可选、默认关闭、显式注册方法和 allowlist；不提供通用系统 VPN |

virtual_cidr/control_port/max_devices 不写死在 proto 字段默认值中；受信 JWT 配置是运行输入，本文给出 v1 部署值和拒绝不兼容值的规则。EasyTier 使用 no-tun 应用内数据面，不改系统路由/DNS，不向应用开放通用代理、exit node、proxy CIDR、系统 VPN 或默认管理监听。首选 NativeDataPlane；平台/API 不兼容时可显式启用 SDK 私有 LoopbackBridge/SOCKS/port_forward，将受限 loopback 流接入固定虚拟端点。私有桥使用随机 loopback 端口，禁止绑定 `0.0.0.0` 或向应用交付通用代理入口，须验证本次随机 bridge capability 或完整 Noise 身份，仅接受规定目标，并纳入取消/关闭和完整资源回收。不得因入口是 localhost 就视为可信。

可选内部服务转发还必须限于宿主明确注册的应用服务，绑定设备、方法、目的端点、额度和生命周期；不得由 peer 提交任意 host/port 触达系统服务。具体转发方法可以使用应用自有 Protobuf，不是此版本通用接口的一部分。私有传输桥不会绕过认证，默认代理仍关闭，入站须以实际 ACL 阻止未绑定虚拟端口回落到系统服务；UPnP/NAT-PMP 自动路由器映射默认关闭。

## 2. 三个边界与生成接口

1. **本地控制面**：`SdkCommand → SdkResult`，`SdkEvent` 由 adapter 回调/异步 Stream 交付。`command_id` 关联一次本地提交，命令的 `ok` 只表示接纳。`AuthStarted.operation_id`、watch/subscription ID、message/call/query ID 分别关联后续事件，不能混用。
2. **握手前记录**：只允许 `PreSessionRecord`，包含非秘密版本 hello 或 Noise 握手字节，不含身份声明、设备名、config、capabilities 或业务数据。
3. **经认证 peer 会话**：Noise 传输密文中的 `WireEnvelope`；不会将整个本地 command/event 搬上网络。peer 身份来自会话绑定，本地事件的 `peer_device_id` 由 SDK 填充，不能信任应用载荷自报 sender。

`service cyberbusSdkControl` 是供 prost/tonic 或其他语言生成器检查的接口契约，不意味着自动启动 gRPC/HTTP listener，也不要求 SDK 链接 gRPC runtime。`Execute`/`SubscribeEvents` 可由进程内对象实现；Rust adapter 提供稳定语义入口：

| Rust/adapter 入口 | Protobuf 等价 |
| --- | --- |
| `begin_auth` / `auth_start(Login/Register)`、`complete_auth` / `auth_callback`、`cancel_auth` / `auth_cancel` | 对应 AuthStart/AuthCallback/AuthCancel 与 AuthEvent |
| `get_auth_state()` | GetAuthState / SdkResult.auth_state，当前状态/锁存查询，不触发refresh |
| `restore_auth()` | AuthRestore(operation_id)，按创建时可信存储策略恢复；AuthEvent 报告终态 |
| `logout(policy)` | AuthLogout / SdkResult.auth_logout，本地关闭与云端操作结果分开 |
| `close()` | SdkClose / SdkResult.sdk_closed；终止操作、结算 result 后关闭事件生产端 |
| `watch_devices(callback)`、取消 watch | `WatchDevices` / `StopWatchDevices`、`DevicesEvent` |
| `get_devices()` | GetDevices(query_id) / SdkEvent.devices_query，一致快照不进入 SdkResult |
| `refresh_devices(budget)` | RefreshDevices(query_id, budget) / SdkEvent.refresh_devices，完成或 partial |
| `get_device_descriptor(peer, conditional_revision)` | GetDeviceDescriptor / SdkEvent.device_descriptor，unchanged/完整公开 profile/错误 |
| `block_device(peer)` / `unblock_device(peer)` | BlockDevice / UnblockDevice → SdkResult.device_block；变化时另发 device_block_changed |
| `get_blocked_devices(optional peer)` | GetBlockedDevices(query_id) → SdkEvent.blocked_devices，列表或单设备状态 |
| `subscribe_data(type_urls, callback)` | `SubscribeData` / `UnsubscribeData`、`DataReceived` |
| `send(peer, message)`、取消/确认处理 | `Send` / `CancelData` / `CompleteData` |
| `register_handler(capability, handler)` | `RegisterHandler`，函数指针/闭包只由 adapter 保存 |
| `invoke(peer, method, request)` | `RpcRequest(UNARY)` + 一个请求 item + request `RpcEnd` |
| `open_stream(peer, method)` | `RpcRequest(BIDI)` + 双向 chunk/end/window/cancel |
| `set_local_descriptor` / `update_public_profile` | UpdatePublicProfile / SdkResult.public_profile |
| `get_schema` / `pull_descriptor` | PullDescriptor / SdkEvent.descriptor，按 digest 拉取 FileDescriptorSet |

handler、数据订阅和 watch 的回调注册必须先建立 adapter 本地引用，再提交命令；命令失败则撤销引用。每个 adapter 先接通事件流再提交命令，不能在返回 `ok` 后才订阅而丢失首个事件。一个运行时只有一个活动本地控制 adapter；多语言宿主若需多订阅者由这个 adapter 分发，避免重复执行 handler。进程内 callback 由语言 adapter 生成/实现，Protobuf 本身不能序列化闭包。

`event_sequence` 是 adapter 生命周期内从 1 开始严格递增的交付序号，不替代设备目录 revision。事件中的 `runtime_id` 标识本地目录/账号网络代际，防止账号切换后旧事件污染新运行时；目录在登录前已存在，设备事件的该字段始终为16字节，auth 事件可为空。拒绝未知 command/body；不得把空 oneof 当作成功。所有枚举的 UNSPECIFIED、未知数值，在要求业务枚举的位置均拒绝。

本地 GetDevices/RefreshDevices/GetDeviceDescriptor/GetBlockedDevices 的 query_id 由调用者生成16字节，整个 adapter 的所有 query（包括 PullDescriptor）期间唯一。SdkResult.ok 表示接纳，随后每个已接纳 query 恰一个有相同 query_id 的终态 SdkEvent；拒绝时直接 SdkResult.error 且无后续 query 事件。事件允许先于 result 到达，adapter 必须先登记 query handle；同 ID 的重叠/重复提交返回 CONFLICT，不重新执行。最多4个未完成本地查询，并为终态预留总计24MiB队列预算；不足在接纳前 RESOURCE_EXHAUSTED。query error 在其对应结果事件内，不能用没有 query_id 的 NetworkState.error 代替。账号/网络代际切换先终结旧 query，旧代际终态只结算原 handle，不能更新新代际目录。

## 3. Logto 登录、注册与 claim

唯一LogtoAdapter使用Logto Native Authorization Code + PKCE S256流程；优先复用满足能力的官方SDK，G0也可选择基于成熟Rust OAuth/OIDC库的协议适配器（不手写密码学），同一实例只选一个授权owner，不承诺已有官方Rust SDK。客户端最小自定义 API scope 只有 `network:join`，OIDC 所需标准 scope 按官方登录流程处理。不得以 scope 名义申请管理权限或 M2M 身份。`AuthStart(REGISTER)` 仅进入 Logto 托管注册页面，SDK 不接收密码，注册资料仅由托管页面处理。issuer/client/resource/redirect URI 允许表由可信宿主配置提供，不允许 peer 覆盖。

`AuthStart` 返回随机 `operation_id`、授权 URL 和过期时间；URL 只供本地打开浏览器。操作默认有效10分钟，过期产生 FAILED/DEADLINE_EXCEEDED 终态。`AuthCallback` 必须携带同一 operation ID 和原始回调 URI。SDK 限制同时一个待完成认证操作，逐项验证 operation、过期、redirect 精确匹配、OAuth state、PKCE、OIDC nonce。callback 命令 `ok` 表示已接纳处理；最终结果在同一 operation 的 `AuthEvent`。重复 callback 在 pending 时返回 CONFLICT，终态后返回 CONFLICT，不重复换 token。取消与成功竞争时由同一串行认证所有者选定一个终态；取消后的迟到响应不得产生第二个终态或安装登录态；涉及grant轮换的请求仍由原owner结算，不能丢弃所有权或重放，见§3.1。Logto托管页面/所选LogtoAdapter的具体signup参数由实现适配，不在此声称某个未经验证的参数可用。

AuthRestore 仅携带调用者生成的 operation_id，存储策略由 Client::new 的可信 config 固定，不接收 token/grant、任意存储路径或临时策略覆盖。默认内存模式冷启动没有可恢复 grant；接纳后 AuthEvent(RESTORING) 再给 FAILED/UNAUTHENTICATED，提示重新授权。存在平台安全存储授权且没有reauth latch时，仅由同一LogtoAdapter执行真实在线恢复/刷新，再验证完整JWT/claim及§3.1租约和凭证基线；满足全部条件才给AUTHENTICATED，不自动开浏览器或start_network。已有latch须给REAUTH_REQUIRED，静默restore不能清除；冷启动不继承旧租约，须先恢复受保护active/pending/高水位记录并真实核验再授予新租约，失败保持closed。restore默认30秒预算；与start共享认证所有者，可用AuthCancel取消。AuthCancel对已取消/已终结/未知合法ID幂等返回ok，不再产生第二个终态。

SDK 验证 resource access token 的签名、算法允许表、固定 issuer/discovery/JWKS、audience、顶层非空 sub、iat/exp/nbf（最大时钟偏差 60 秒）、`network:join`、顶层真实 client_id 及可信 Native client 绑定。拒绝 ID token 代替 access token、M2M grant、缺失真实 client 绑定，以及 `azp`/`client_id` 冲突；原生应用 client 类型由部署允许表确认。不得从未验签 JWT、用户可写 custom data 或 callback 自报字段建立账号身份。

固定 claim 键为 **`https://cyberbus.x.aixgg.com/easytier/credentials/v1`**，值为以下对象；这是 HTTPS token 内 JSON claim 的定义，**不是 peer JSON 编码**：

```json
{
  "version": 1,
  "product_id": "example-product",
  "credential_epoch": "1",
  "account_seed_secret_hex": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  "max_devices": 256,
  "virtual_cidr": "10.144.0.0/20",
  "control_port": 11000,
  "config_version": "1"
}
```

上面是公开示例测试材料，不能用于真实网络。该 claim 必须是包含上述8个必填字段的平铺对象，不重复放 `issuer/iss/sub`，不接受旧 `product/epoch/config/cidr/port` 别名或嵌套配置。账号绑定中的 issuer/subject 只取已验证 JWT 顶层 `iss/sub`；issuer 使用与部署 `ET_ISSUER` 完全一致的固定 HTTPS `/oidc` 值。`product_id` 必须是非空字符串并匹配可信 client→product 映射。`credential_epoch` 必须是无前导零的十进制字符串（允许 `"0"`），解析值不超过 u64。`account_seed_secret_hex` 必须是64位小写 hex，解码恰好32字节作为派生公式中的account_seed，不允许空白、`0x` 或任意客户端覆盖。

`version` 必须是整数1，`max_devices` 必须是整数256，`virtual_cidr` 必须精确为 `"10.144.0.0/20"`，`control_port` 必须是整数11000；禁止布尔值/数值字符串充当整数。`config_version` 必须为非空ASCII字符串、长度≤64字节，且匹配 SDK 明确支持的部署配置版本（当前 `"1"`），不转成数值、不进行归一化。缺失/未知 claim 字段、未知 version/config_version、错误类型和不兼容配置均拒绝启动，不回落到旧 `/24` 或其他网络。JSON 对象重复 key 必须拒绝，不能依赖解析器最后一个值覆盖。

seed 必须由 Logto 受信 custom JWT 签发逻辑从服务端秘密和 `(JWT.iss, JWT.sub, product_id, credential_epoch)` 稳定派生；不同设备同绑定得到相同 seed，客户端不能任意指定 product_id 或 credential_epoch。hook 顶层额外输出 client_id，Logto 保留标准 iss/sub/aud/exp 的所有权。seed/config 只从已验证官方 Logto JWT 取得，不再调用独立 HTTP bootstrap API，不做设备目录注册。固定 bootstrap/relay 联系点是宿主受信传输配置，不是第二个下发 seed/CIDR 的 API。claim 缺失、seed/绑定/配置无效返回 `INVALID_CLAIMS`；resource/scope/client/custom-claim 签发部署错误返回 `LOGTO_CONFIGURATION`；网络失败返回 `UNAVAILABLE`，不提示“调用引导 HTTP API”。

v1仅支持public subject：最终resource JWT的sub必须等于hook输入token.accountId，同账号同产品的所有Native client必须保持相同sub，禁止pairwise或其他sub重写，并须在真实签发/刷新验收中确认sub、seed及派生network_name/network_secret跨端一致，见[Logto部署前提](logto-deployment.md)。

Logto会将完整hook返回值交给审计流程；上述claim键中的credentials与叶子字段中的secret会触发固定版现有redactor对credential/secret子串的匹配，分别遮罩整个claim对象和seed叶子值，不得去掉这些敏感标记，固定版常规部署无需修改Logto核心源码；但生产seed发行前必须按[部署日志验收](logto-deployment.md)真实验证目标版本的审计存储与日志均不含seed，不匹配这些规则的目标版本须先升级或补齐脱敏，仅禁止脚本console.log不足以完成验收，未通过不得发行生产seed。

OAuth grant/token、authorization code、PKCE verifier、seed、派生 secret 必须留在原生认证/网络所有者内存或明确的安全存储策略里；不得进入 public config、descriptor、WireEnvelope、日志、错误文本或 Tauri UI。JWT 是签名而非加密，含 seed 的 token 必须按秘密处理；禁止发送 peer 以“证明登录”。本地 callback URI 也只传给原生所有者，不能转播到 peer。logout 先关业务 gate 和流，再停网络、清目录和种子，最后清 OAuth 材料；旧 runtime 完成结果不能重新开网。

AuthLogout.cloud_policy 缺省为 LOCAL_ONLY；显式值支持 REVOKE_GRANT、END_SESSION、REVOKE_AND_END_SESSION，未知/UNSPECIFIED 拒绝。可选 cloud_budget 缺省30秒，合法范围(0,30秒]，不覆盖本地关闭预算。本地先关闭 gate、取消运行操作、回到仅self诊断目录并清除内存/持久授权；如需云操作，唯一LogtoAdapter只能临时私有持有完成该操作所需的材料，结束/超时即清除，不能恢复本地登录态。云端 END_SESSION 仅走Logto支持的流程/创建时允许的回调，不在命令中接收任意跳转地址。成功 local cleanup 后可立即发 LOGGED_OUT；该事件只表示本机状态，不表示云撤销成功。

logout 恰返回一次 SdkResult.auth_logout，而不是 ok：local_closed 表示本机 gate 已关闭且授权材料清理完毕，local_error 在local_closed=true时缺省、false时必须报告本地清理失败；云结果用 cloud_status/cloud_error 独立表达 NOT_REQUESTED、SUCCEEDED、FAILED、UNSUPPORTED、UNKNOWN_OUTCOME。NOT_REQUESTED/SUCCEEDED时cloud_error缺省，其他终态必须给出非零错误码。组合策略只有两项均确认成功才为 SUCCEEDED，任一确认失败为 FAILED，响应丢失/超时结果不确定则 UNKNOWN_OUTCOME；所选adapter/平台不支持时明确 UNSUPPORTED。云失败不得撤回已经完成的本地 logout；本地错误也不能假称 local_closed=true。云操作从不保证其他已持seed的 peer 立即被撤销。

SdkClose 是终态，本地固定关闭预算5秒、不隐式调用云退出。先关闭新命令/业务 gate，再给所有已接纳 auth/query/data/RPC 等未结束操作选定 CANCELLED（已可能提交的业务保留 UNKNOWN_OUTCOME）终态并排入其原有有界结果通道，注销 watch/data/handler，回收网络、私有桥和敏感材料。SdkClose 自身恰有一个 SdkResult.sdk_closed，必须先结算该 Execute 调用的 result/future，之后才关闭事件流生产端；已排队终态仍可被读取直到 EOF，不等待用户 callback executor 消费才兑现 close result。无法在预算内完全清理时返回 SdkClosed.cleanup_error，API 仍已终态关闭并继续由原生所有者回收，不把超时写成清理成功。此后命令返回 CANCELLED（不再产生事件），重复 close 幂等返回同一关闭结果；不可把 close 当作只返回接纳 ok 的普通命令。

共享seed仍不能让恶意旧实现自动失去组网能力；以下在线验证、租约和手动block是正常SDK必须执行的本地gate，不承诺向其他节点强制吊销、中心设备删除或自动迁网。

### 3.1 真实在线验证、租约与交互重新登录

唯一LogtoAdapter（满足能力的官方SDK，或G0验证的成熟Rust OAuth/OIDC库协议适配器）串行合并timer、resume、restore及自动刷新触发，同一实例只选一个grant/refresh owner、最多一个在途签发请求，不同时由Rust和官方SDK分别刷新。正常检查间隔为上次真实核验成功后**5分钟±20%（240–360秒）**；网络恢复/前台唤醒时距上次成功满300秒立即检查。真实检查必须实际访问Logto授权/token端点取得本轮签发的resource JWT并完整核验；缓存getAccessToken、本地重新验签、JWKS读取、peer活动均不算成功、不续租。

租约只在完整验收成功后授予，起点是**该轮真实签发请求开始的、包含休眠时间的单调时刻req_start**，不能用响应完成时间延长窗口。按[security.md第3节](security.md#3-凭证变更如何发现并提示重新登录)区分：**支持真实refresh的路径，网络材料deadline=req_start+600秒，独立于JWT.exp**；JWT.exp仍约束每次新token验收和API请求，API token过期不自动取消剩余网络材料租约、不等于撤销。**无offline_access/无可用refresh grant/无真实强刷能力的退化路径，deadline=min(token.exp,req_start+600秒)**。新响应验收时已超过其候选deadline则不授予该租约；旧租约先过期锁存后，后台迟到成功也不能清除锁存。

AuthEvent及GetAuthState用validation_request_started_at展示最近获准租约的请求开始时间，last_online_validation_at独立展示成功核验的完成时间；validation_lease_expires_at报告实际gate截止时间，access_token_expires_at报告独立API截止时间。Timestamp仅供展示，deadline由包含休眠的单调时钟执行；墙钟回拨不能延长租约。单次检查预算30秒，不能用此预算延长旧租约；短token周期可提前为API刷新。后台恢复在排队任何旧业务/handler/window/metadata前检查deadline，过期先关gate并锁存。平台不能可靠计入休眠时，唤醒先关gate真实核验。冷启动不继承旧进程剩余租约，restore先加载安全记录再真实签发核验，成功前不开网；不能从启动时间给缓存重新计10分钟，已有latch不能由restore清除。

refresh_supported必须有实际签发能力证据，申请过offline_access不等于支持。JS官方SDK公开clearAccessToken可清除所有access-token缓存，再由同owner取得实际签发；清缓存及所有resource取token调用须串行，须验明确实发出本轮请求。Android普通getAccessToken缓存优先，目前未验证公开强刷入口，G0通过前按refresh_supported=false降级。Rust协议适配器同样须通过G0的PKCE/回调、真实签发、刷新轮换、存储和单owner验证，不手写密码学、不宣称已实现或已有官方Rust SDK。不能真实刷新时立即提示interaction_recommended，最迟在上述较早deadline前提示交互；不假称force refresh，也不擅自增加权限。

| 认证观察 | 状态和gate行为 |
| --- | --- |
| 新签发JWT完整有效，材料/绑定/配置相同且无latch | 更新成功时间及基于req_start的租约；已运行网络继续，已停止网络不自动启动 |
| 经验证epoch或派生材料/受支持网络配置改变 | 先关gate，保存安全事务后REAUTH_REQUIRED / CREDENTIALS_CHANGED，不后台迁网 |
| OAuth明确invalid_grant、login_required等授权失效 | REAUTH_REQUIRED / SESSION_REVOKED并停网；枚举兼容保留，UI只称“登录授权已失效”，不据此断言管理员主动撤销 |
| DNS/未发出请求等暂时故障，能够确认未消费grant或适配器契约保证可安全重试 | DEGRADED，仅原租约内旧网可继续；5–60秒抖动退避且不越过deadline，不更新基线、不续租 |
| refresh已发出但响应丢失/超时，RT是否轮换不明 | DEGRADED + error.UNKNOWN_OUTCOME，refresh_grant_frozen=true、interaction_recommended=true；冻结该grant后台重试，不盲重放旧RT、不续租，不误报SESSION_REVOKED |
| 当前路径deadline耗尽而未完成合格核验 | 先关gate，持久锁存REAUTH_REQUIRED / VALIDATION_LEASE_EXPIRED，要求交互；支持真实refresh时不因JWT.exp单独触发 |
| JWT签名/claims/issuer/client/配置无效 | CONFIGURATION_ERROR + INVALID_CLAIMS/LOGTO_CONFIGURATION并关gate；不把无效输入当变更或授权失效，不用循环登录掩盖部署错误，保留原有latch |

HTTP 5xx/限流/普通超时本身不证明可安全重试。请求已送出且结果未知时，**30秒只是调用预算，不丢弃或转移refresh所有权**；原owner继续结算迟到响应及RT轮换，不新建第二请求/owner并发消费该grant。未知结果可推荐用户交互，但仍由原owner串行管理新授权；迟到响应只能结算原请求，不能覆盖新generation/grant。若旧租约尚未到期、完整验收同材料且无latch，原owner可解除冻结并授予从原req_start计算的租约；过期锁存后不能这样恢复。若已有latch则DEGRADED等观察保留reauth_required/reason，不能将其写回false。错误只带允许的OAuth code及脱敏网络事实，不带原始token响应。

### 3.2 跨退出与重启的安全记录

按精确 `(issuer, sub, product_id)` 在受保护存储中保存：**active（上次接受材料）的epoch及私有HMAC比较值、pending（待强交互接受材料）的epoch及私有HMAC比较值、epoch高水位、reauth latch及非秘密reason**。HMAC由独立本机存储密钥对有长度前缀的绑定/派生材料及网络配置上下文计算，仅内部恒定时间比较；实际比较覆盖network_secret、app_psk、binding_id，epoch亦独立检查，故root-only变更可检出。此记录不提供联网能力，不存seed/网络密钥，不进入事件/UI/日志/peer。安装身份、此记录和block表跨logout/close/重启保留，logout仅清OAuth授权及可用网络秘密；显式删除账号安全记录后必须重新强交互，不能restore旧基线。

**每个login/restore/refresh/NetworkStart使用同一记录检查**。已签名、甚至本轮新签发并不证明是最新：低于高水位的epoch一律拒绝并保持gate关闭，不回旧网；冷启动必须先比较active/pending，不能先覆盖再比较。记录缺失/损坏/加载失败不能静默当首次初始化；只允许可信创建流程确认的新账号首次强交互或显式删除后的强交互建立记录，恢复路径须失败关闭。

首次检出有效变更时先关双向gate，再将高水位、pending和reauth latch作为一笔安全存储事务原子可靠保存，**报告该变更操作完成/状态已可靠保存前必须提交成功**。原active保留，不能把尚未接受的新材料直接写成active。保存失败继续closed并报告本地UNAVAILABLE，security_state_persistence_pending=true；当前可查询的reauth_required仍为true但不可声称已持久化，不能回退到首次初始化或旧可信状态。所有会开gate的入口都拒绝此待修复状态。授权失效/租约耗尽触发的锁存也必须先关gate再可靠保存，写盘失败同样保持closed并报告错误。

锁存原因首次触发后保留到合格交互成功；reauth_required=true时reason必须是三种非零枚举之一，phase=REAUTH_REQUIRED必为true。交互等待、失败/取消、配置错误和logout状态可保留true及原reason。无latch时reason=UNSPECIFIED。state_revision是SDK实例内从1开始的单调认证状态版本，任何可观察状态变更+1，GetAuthState只读不增；跨实例不比较。

### 3.3 关网、交互确认与可查询状态

锁存触发先拒绝send/invoke/stream、metadata/schema、内部转发及NetworkStart，取消在途操作、清远端目录并reset到self，停止EasyTier/私有桥/旧会话并清理内存网络密钥；可能已执行的本地handle保留UNKNOWN_OUTCOME。本机get/watch、当前账号block管理及重新登录仍可用。refresh/restore/start、普通stop、logout或重启都不能清latch，后台仅私有比较并推进受保护记录，不安装新材料、不自动迁网。

只有用户发起、由唯一LogtoAdapter完成的真正强交互登录才能接受新材料。prompt=login/max_age=0等参数必须有目标adapter/平台的真实重新认证证据，普通SSO或缓存命中不能视为强认证。完整验证的新材料须不低于高水位、且pending存在时须匹配pending（不受首次锁存reason影响）。**本次交互期间若合法更高epoch的C到达，可原子推进pending/高水位并由本轮合格强交互接受C，无需再走一轮登录；同epoch不同材料不得自动替换已有pending**，须保持暂停并报告CONFLICT排查副本，旧active也不能据此清锁。运维root轮换应同时递增epoch，root-only检测不能判断同epoch两套材料谁更新。

合格强交互成功才能原子提交新active、清pending/latch并保留高水位；交互失败、取消、存储失败保持closed，不报告认证恢复成功。恢复结果为AUTHENTICATED但RemoteDisabled，**宿主仍须显式NetworkStart**，不恢复旧开网意图、不重放旧业务。不同账号独立处理，原账号安全记录不被覆盖。

GetAuthState不触发网络操作，通过SdkResult.auth_state返回与AuthEvent同形的≤64KiB原子状态，恢复丢失的通知；首次无账号返回LOGGED_OUT、state_revision=1，时间字段缺省。事件和查询均展示能力、成功/请求/到期时间、reauth原因、refresh_grant_frozen、security_state_persistence_pending和脱敏错误，不含任何比较值/secret。account摘要仅在AUTHENTICATED成功状态出现；交互等待或错误保留原latch，不能让UI因新事件而解除持续提示。状态通知可合并为最新完整状态并保留其state_revision，但不可无声遗漏锁存；查询是恢复手段，不能依赖单次弹窗。

`persist_grant` 是可信创建配置的显式选择，默认 false。SdkClose 清除实例内授权/网络材料而不等同于 AuthLogout：选定持久授权时保留 store 中 grant，冷启动仍须 AuthRestore 的真实签发/完整核验；AuthLogout 清除该持久授权。任何模式都不得保存网络 seed/派生密钥或恢复旧 lease，也不因 restore 自动启动网络。

## 4. 安装身份、派生和会话认证

安装级密钥为独立生成并安全保存的 X25519 静态密钥，不是硬件指纹。SDK 创建时即加载/生成安装身份并创建 self，失败则 SDK 创建失败，不能返回缺少 self 的成功实例。`device_id = SHA256(raw_installation_public_key)`，proto 使用 32 字节；显示时用 64 字符小写 hex。`boot_id` 在 SDK 创建时、每次进入新网络运行代际时分别新生成16字节。不能用 EasyTier peer ID、IP 或账号 sub 替代 device ID。

本契约明确派生，避免 protobuf 字段顺序或 JSON canonicalization 进入密码学输入：`E(parts...)` 按顺序对每个原始字节字段编码 `u32be(len) || bytes`，字符串使用原始UTF-8、不做 Unicode 归一化，拒绝孤立surrogate等非法Unicode；编码层允许NUL（长度前缀可无歧义区分），不添加与JWT签发脚本不同的字符串过滤。展示名称、URI等字段各自的控制字符校验不改变此派生编码。issuer/sub 取验证后的顶层 iss/sub，product_id/credential_epoch 取平铺 claim；credential_epoch 使用上节规范十进制 ASCII。

```text
scope = E("cyberbus/seed/v1", issuer, sub, product_id, credential_epoch)
salt  = SHA256(E("cyberbus/v1", scope))
prk   = HKDF-Extract-SHA256(salt, account_seed)
network_name   = "cg-et-mvp-" + lowercase_hex(HKDF-Expand(prk, "network-name", 16))
network_secret = base64url_no_padding(HKDF-Expand(prk, "network-secret", 32))
app_psk        = HKDF-Expand(prk, "app-handshake-psk", 32)
binding_id     = HKDF-Expand(prk, "session-binding-id/v1", 32)
```

Noise 固定 `Noise_XXpsk3_25519_ChaChaPoly_SHA256`。发起 TCP 连接者为 initiator；双方先各发一个 `ProtocolHello`（major=1、minor=0、nonce 32 字节、suite 精确匹配）。hello 不进行可降级的算法协商，未知版本/套件立即关流，不能回落明文。实际传给 Noise 初始化器的 prologue 精确为：

```text
prologue = E("cyberbus/easytier/session/v1", binding_id,
             ASCII(config_version), initiator_hello_raw, responder_hello_raw)
```

保留上述额外 HKDF 输出 binding_id（32字节），其派生上下文绑定 issuer/sub/product_id/credential_epoch；config_version 取本机已验证 JWT claim 的原始ASCII字节（如 `"1"` 编码为单字节0x31，不是u64数值），同样带 E 的长度前缀。hello 使用实际收发的 ProtocolHello protobuf 原始 bytes，不重新序列化，不包含外层 PreSessionRecord 和长度头。这样协议版本、namespace/epoch、配置版本和双方 hello 均在 Noise 握手 transcript 中绑定，不能只等握手后 SessionBind 才检查。binding_id/config_version 是初始化器本地输入，不添加到明文 hello；不同配置版本的双方握手失败，不静默选一方。固定 PSK 为 app_psk，握手应用 payload 为空。安装 X25519 密钥就是 Noise 静态 `s`；不能另报一个没有参与 Noise 的安装 key。

握手结束后 `session_id = SHA256(ASCII("cyberbus/easytier/session-id/v1") || handshake_hash)`。Noise Split 后每方向第一条传输密文必须是 `WireEnvelope(sequence=1, bind=SessionBind)`。验证静态 key、其 SHA256 device ID、绑定 ID、boot ID、容量和接收额度，然后才能发送 `SessionReady`。Ready 授予对方可在本机使用的权限；双方已收到并发送 bind+ready 才能进入 ESTABLISHED。未经认证不能发布设备目录、权限声明、config、capabilities、descriptor 或数据；握手前 IP/路由候选不成为可信设备。绑定失败只发送有界/脱敏错误或直接关流。

`SessionBind.requested_permissions`只在Noise传输加密后出现。**同账号、同产品且身份认证通过的设备默认可信，无额外逐设备审批或信任白名单；仅手动block会撤回该设备的数据/信息交换信任。** 为保留wire兼容，现有Permission字段继续表示双方支持并请求的功能位：本SDK默认请求并授予所有已支持的DISCOVER/READ_PUBLIC_CONFIG/DATA/RPC/PULL_DESCRIPTOR，不提供按设备静默关闭其中某项的另一套策略。内部转发只在宿主明确启用且注册目标handler时支持INTERNAL_FORWARD，此为全局功能/目标边界，不是额外设备信任审批。未知功能、未注册方法、类型/额度错误仍拒绝；对端旧实现不授予的功能仍须尊重，不得绕过。

对实际Noise静态公钥重算device_id后，必须先读取当前账号/产品的本地block策略，再发送ready、metadata或分派任何业务；blocked立即关流，不对peer公布block列表、原因或控制命令。`DISCOVER`/`READ_PUBLIC_CONFIG`/DATA/RPC/schema各自仍要求匹配的wire功能位，且每次排队/分派都重新检查本地block gate，防止握手完成与手动屏蔽竞争。

Wire sequence 每方向严格从 1 递增，不跳号、不复用、溢出前重建会话；session ID 与当前握手匹配。TCP 有序流上不做乱序重放缓存。Noise nonce 由标准库维护；不把 sequence 当自行设计 AEAD nonce。重连必须新 hello nonce、新 Noise 握手、新 session ID，旧 ciphertext/call 流状态不得迁移。共享 PSK 只证明对方持有账号网络秘密，不构成中心批准某台安装身份的证书。

连接状态单向推进 `HELLO → NOISE → BINDING → ESTABLISHED → CLOSED`；每方向恰一个 hello、一个 bind、一个 ready，Noise 消息数由固定 XXpsk3 模式限定。BINDING 只接收 bind/ready/close；ESTABLISHED 拒绝再次 bind/ready。Ping/Pong 仅在 ESTABLISHED 可用，nonce 为16字节、每会话最多一个未完成 ping，接收方原样回显，不能把 Pong 用作应用授权。正常存活探测间隔30秒±20%抖动（24–36秒），合法经认证的业务流量也刷新最后认证活动并清零失败计数；单次探测受当轮剩余30秒预算约束，不叠加未完成探测。没有业务会话的设备以60–120秒抖动抽样复核，不为255个远端保留全部长连接。offline 必须同时满足第6节180秒和跨轮真实失败条件。XXpsk3 的静态 key 可在握手中被主动参与者获知，不承诺安装公钥匿名性；公开应用声明和数据始终等到 PSK 认证及双向 ready 完成。

同 device ID 但 boot 不同不能仅凭旧缓存判定克隆：在当前视图对两条实例会话分别发新 Ping 挑战，10 秒窗口内两条认证会话均回应且 boot 不同才报 `DUPLICATE_DEVICE_ID` 并隔离；无法证实时重新探测，正常重启可更新旧 boot。

## 5. 记录 framing 和容量验证

在 EasyTier 虚拟 TCP 上使用 `u32be(N) || record_body`。没有换行、varint 长度、压缩或默认 JSON。**64 KiB 上限包含 4 字节长度头**：`1 <= N <= 65532`，总长最多 65536。该选择同时满足 Noise 密文自身 `<=65535` 的算法限制；传输明文最多 `65532-16=65516` 字节（16 字节 AEAD tag）。不要把 64 KiB 明文直接交给 Noise。

握手阶段 body 是编码后的 `PreSessionRecord`；握手完成阶段 body 是单个 Noise 传输密文，解密得到恰一个 WireEnvelope；不会在密文外再包 protobuf。不得猜测/自动探测明文与密文，必须由连接状态决定。Length 超限在分配内存前关闭；分段读取必须先收足四字节再收足 N，支持半帧和粘包。EOF 半帧、0 长、密文验证失败、错误阶段消息均终止会话。握手整个预算 10 秒；一条记录收到首字节后，后续头/body 无进展 5 秒即断开。等待下一条记录首字节属于会话空闲，由 24–36 秒 liveness 和其探测预算控制，不能每 5 秒断开正常空闲会话；活跃 RPC 的 deadline 更早则先取消 RPC。

| 对象 | 必须验证的上限与规则 |
| --- | --- |
| ID | 普通随机 ID 16 字节；device/session/binding/digest 32；静态 key 32；nonce 32；IP hint 4；可选 ID 缺省必须为空或正确长度 |
| 展示/接口字符串 | 已声明profile的name 1–128 UTF-8字节；method 1–128；type URL 1–512；语义版本 1–64；错误文本≤512；本地授权/回调 URI≤8192；这些字段拒绝非法UTF-8、NUL/控制字符（错误文本只允许普通换行）。账号身份/派生字符串按§3/§4原始值规则，不能套此展示过滤 |
| 公共 metadata | 整个 `PeerMetadata` 编码（含未知字段）≤16384；public_config Any 编码≤8192；capabilities≤64；公开 config+所有 capability 合计仍受 metadata 总额限制 |
| descriptor | 一个完整序列化 FileDescriptorSet≤262144（256 KiB），最多 128 文件、4096 总 message/enum/service 声明、类型嵌套≤32、依赖闭包齐全且无重名冲突 |
| data / RPC item | 单个完整逻辑 binary 默认且最高 1048576（1 MiB）；session 可协商更低；每片≤16384（16 KiB）；空消息 total=0/offset=0/空 bytes，仍消耗一个逻辑 item |
| 分片 | offset 从 0 起连续、不重叠/不越界；total_size/type_url/encoding 和同一消息所有头字段一致；总长度在分配前验证；缺片/超时不得触发应用回调 |
| 会话并发 | 每方向 data 在途≤8、由该方向发起 RPC≤16；descriptor 同时 pull≤1；全运行时 data+RPC重组预算≤32 MiB，descriptor≤1 MiB；另有出站排队预算≤8 MiB/会话、≤32 MiB/运行时 |
| 本地大对象 | snapshot≤256条、编码≤5 MiB；SdkCommand/SdkEvent≤5 MiB；所有 SdkResult≤64 KiB，查询大快照只在 SdkEvent.devices_query 中交付；本地对象不套 peer record 限制，但同样校验业务尺寸 |
| 防滥用 | 每 peer 新建 data/RPC/descriptor 合计≤64次/秒、burst128；每运行时未认证连接≤16、每来源≤2；违反限额拒绝或关闭，不创建无界任务 |

所有显式接收额度必须 >0 且不高于上述上限；proto 标量默认 0 **不是**自动协商默认值，构造 SessionBind 时 SDK 填入默认上限。sender 取本机配置与对方接收上限的较小值，receiver 始终按本机额度验收。time budget 为合法非负规范 WKT Duration，业务场景要求 >0，data/descriptor 默认30秒、RPC默认30秒，最大300秒；缺省由 SDK 在发送前填入，wire 缺省则拒绝。Timestamp 必须在 WKT 合法范围内，仅供展示与观测，不用于证明远端在线或排序。

protobuf 对非法重复 singular/oneof 字段通常采用 last-one-wins，因此**实现不能依赖 oneof 自动拒绝歧义**。在控制分派与网络分派前做有界 wire 结构扫描：一个 root 必须恰一个已知 body，禁止重复 root singular、重复 oneof tag 或不同 oneof 分支并存；嵌套 singular 也不得重复。未知普通字段在预算内可忽略，未知唯一 body/enum 拒绝；未知字段不能绕过总尺寸。禁止 groups、过深嵌套（控制消息≤32）、非法 varint/长度、超量 repeated；拒绝 trailing 非法数据。不能只看“parser 成功”就认定业务对象合法。允许 protobuf 合法的空应用 message；应用类型须由本地编译类型或显式批准的 descriptor 注册。宿主若选择 opaque protobuf 转交，SDK仍须做有界 protobuf wire 格式扫描、宿主承担类型校验，不能将 JSON/文本解释为默认格式。SDK 不从 type URL 下载代码。

## 6. 设备容量、快照和有序 watch

容量口径固定：`DevicesSnapshot.devices` 列表**包含 self**，恰好一个 `is_local=true`，最多 256 条，因此远端最多 255。device ID 唯一、按原始 32 字节升序；self 与远端都用 DeviceSnapshot。设备静态 key 必须能重算 ID，self 标志只由本机生成，peer 不能冒充。未通过 Noise+bind+ready 的候选不会进入列表，bootstrap/relay 若不是应用设备也不占设备名额。

登录前或尚未 start_network 时，`get_devices` 与 `watch_devices` 均允许调用且不触发登录/联网；初始快照恰有一条 self，**不允许空列表或空 self**。此时 self 已有安装 key/device_id、boot_id、is_local=true，presence=OFFLINE（表示远程服务尚未可用），last_authenticated_at/virtual_ipv4 缺省；若宿主尚未 set_local_descriptor，profile 整个字段缺省，表示尚未声明，不读取系统hostname、不伪造默认名称/版本。此例外只允许本地 OFFLINE self 诊断记录，不允许远端已认证记录或 PeerMetadata 省略profile。创建时生成16字节非空目录 runtime_id、revision=1；NetworkState.running=false。GetDevices 在同一目录串行点捕获快照，SdkResult.ok 接纳后由 SdkEvent.devices_query(query_id, snapshot) 返回，不创建watch；WatchDevices 的首条仍是相同形状的snapshot。后续登录/启停网络/切账号使目录进入新generation时，保留安装身份并重建仅self基线，通过reset通知持续订阅者，不复用旧账号远端。

NetworkStart须先检查§3.2同一安全记录及高水位，再要求已有宿主显式提交且通过全部校验的本机PublicProfile及相符handler；未声明/无效时SdkResult.error(INVALID_ARGUMENT)，不加入网络、不发送PeerMetadata。还必须无reauth锁存且当前在线验证租约有效，否则UNAUTHENTICATED并报告对应AuthEvent；成功认证/解除锁存不能替代此显式命令。首次声明前profile缺省、没有config_revision；首次有效声明才初始化config_revision=1。已持久化的有效声明可加载，但不得将未初始化计数当作一个在线profile。

RefreshDevices 接受 query_id 和可选budget，缺省30秒、显式值须在(0,30秒]；仅已启用账号网络可接纳，否则 SdkResult.error(NETWORK_NOT_READY)。共享同一有界发现scheduler，合并并发刷新但每个query各自预算从接纳时开始，不能叠加扫描任务。结束发一个 RefreshDevicesResult，包含该query覆盖轮次的attempted/verified/deferred、完成时目录revision；三个计数均按该query去重候选统计且≤512，verified≤attempted，晚于该有界候选批次的新候选留给后续轮次。未覆盖的已知候选、预算耗尽、路由未就绪或本机网络未知均partial=true，不因未探测设备离线。partial=false只表示该有界候选视图已处理，不证明全网4094地址全部探明；预算耗尽可无error，网络/取消原因以error说明。Refresh不自动追加大快照，应用通过watch更新或另发GetDevices读取。失败/取消同样必须给该query终态事件。

Noise完成只证明会话身份认证；本轮候选的verified及正常60–120秒复核退避，须以目录owner通过全部声明/安全栅栏校验并接纳该会话Metadata为依据。普通EOF或临时probe自然截止须保留同FIFO中Up→Metadata→Down的已认证前缀；显式取消、停网、block及网络/地址代际变化仍立即拒绝旧事件。仅Noise成功但尚无接纳的Metadata保持deferred/partial并按既有未完成重试策略处理；本地owner排队或缺Metadata本身不新增离线规则中的count_failure，不伪造远端不可达失败。

256 是正常 SDK 在稳定连通视图内的支持容量/稳态接纳上限，不宣称无需中心状态就能抗恶意强制全局注册。正常节点对已认证且新鲜在线的候选集合按 `device_id` 排序，仅接纳前256。257台且视图一致时最后一台进入 `CAPACITY_EXCEEDED`，关闭应用 gate/活动业务；其余节点不将其列为已接纳远端。被排除的本机保留仅 self 的诊断快照（self OFFLINE），network 事件报告容量失败，不把自己加入那256台的工作网络。其他已接纳设备离线且经过退出窗口后，重新排序可接纳等待者。不得以“先到先得”实现稳定视图排序。

实现须在不泄露公开 metadata/业务的前提下，允许候选完成最小身份认证并短暂收集排序信息；控制候选视图最多512个有效身份、TTL 30秒并有连接/速率预算，超限报 RESOURCE_EXHAUSTED，不能声称处理无限恶意身份。离线缓存不作为“仍在线”抢占名额；为保证 snapshot≤256，在接纳新在线设备前优先删除离线缓存并发出 removed。分区或视图未收敛期间，不同节点可能接纳不同集合，全局同时活跃数可能超过256；只能在稳定视图收敛后执行同一排序。共享 seed 的恶意节点可不遵守 gate/排序，也可生成身份抢占名额，本方案不提供抗 Sybil 或强一致准入。

路由中的地址只作为发现候选；控制服务使用 claim control_port，发现不全扫4094作为正常主路径。每轮最多16并发连接、30秒总预算，超时报告 partial、未探测项不下线；历史/路由优先，兜底轮转游标保证公平覆盖。有界补扫另限每轮最多256地址或20秒，正常最多每5分钟一轮；应用持久会话最多16条、闲置LRU回收。路由/地址冲突必须先隔离会话并重新认证。IP 不成为设备身份，不因一次扫描未调度或路由不可见就计入设备失败。

`runtime_id` 是本地目录/账号网络生命周期16字节随机 generation，创建SDK即存在；目录revision从1起，每次可见目录事务+1，失败/无变化不增加，耗尽前换runtime。`PublicProfile.config_revision` 是该安装身份的独立profile版本；二者不能相互比较。

watch 注册必须在目录锁或等价串行队列内完成“登记订阅 → 捕获 S_r → 排队首个 snapshot”，之后只交付 `r+1` 起的 diff。首个 callback 永远是 `snapshot`，首个 event 的 previous_revision=0、revision=r，嵌套 snapshot 的 runtime/revision 必须相同。不得先发送 diff 再补 snapshot。

| change | 精确定义 |
| --- | --- |
| added | 已认证且通过容量/权限检查的新设备完整记录 |
| updated | 已有设备完整替代记录和精确 FieldMask；包括 config、capability、boot、地址或 offline→online |
| offline | 距最后经认证活动至少180秒，且自最后成功以来跨至少两个探测轮次累计≥3次真实失败；保留记录、presence=OFFLINE。本机网络未知、未调度、轮次预算耗尽不计失败；不得因本机网络未知批量标远端 offline，恢复后重新安排跨轮认证探测 |
| removed | 离线保留10分钟后删除，或明确容量淘汰/本地策略删除；不是远程“删除安装身份”的全局证据 |
| reset | 丢失有序增量后原子替换整个 snapshot，原因 OVERFLOW/RUNTIME_CHANGED/RESYNC |

diff 的 previous_revision 必须等于订阅者上次已交付 revision，revision=previous+1。watch 持续跨 runtime 时按 reset 交付新 runtime 的 self-only 或新目录快照，不混入旧 generation；初次注册仍用 snapshot。退出也以 runtime reset 清除旧账号设备，旧 account metadata 不再保留。

每 watch 待交付队列最多256事件或8 MiB，额外预留一个最大5 MiB reset 槽。溢出时在目录序列化点丢弃未交付 diff，捕获最新 snapshot，以一个 reset 替换；reset.previous_revision 是最后实际交付的 revision，reset.revision 是新快照 revision，允许跨号。消费者用 reset 整体替换状态，然后接受新快照之后的 diff。reset 排队期间再次变化导致溢出可替换尚未交付 reset，不得排多个旧 reset；adapter 不得让 callback 并发乱序，慢回调不能阻塞网络任务。取消 watch 后抑制尚未开始的回调，已执行的回调允许收尾；callback 内可重入取消，不能死锁。

每 adapter 最多4个 watch、16个 data subscription、64个 handler；订阅 ID 重复返回 CONFLICT，取消未知 ID 幂等成功。每个被接纳的本地 command 恰有一个 SdkResult；watch/订阅注册成功后的事件可以先于 result 送达，但不能先于 adapter 本地 callback 引用注册。adapter 事件队列须将 watch diff 走上述 reset 机制，data/RPC 按各自额度施加背压；不得悄悄丢弃业务终态。无法交付且超过业务 deadline 时终止操作并释放资源。

### 6.1 默认可信与本地持久block

BlockDevice/UnblockDevice只接受32字节peer_device_id，匹配的是实际安装X25519公钥SHA256，不是IP、EasyTier peer ID、设备名、boot_id或应用标签；禁止block/unblock self。可屏蔽已离线/目录已删除的安装ID，SDK不得因为找不到当前IP就把block降级为空操作；重连时必须从Noise实际静态key计算相同ID再检查。安装key更换意味着新的device_id，不承诺识别为旧设备或自动继承旧ID的block。

block持久作用域为精确 `(verified issuer, verified sub, product_id)`，**不含credential_epoch、seed、boot或runtime**，不同账号/产品隔离，epoch/root轮换、重启、普通logout/close不清除。只允许当前已验证账号上下文操作；reauth锁存期间可保留这个上下文做本地管理，首次登录前/普通logout清除上下文后返回UNAUTHENTICATED，不能自报scope查询其他账号。持久block集合最多1024个ID、按原始字节排序；不能TTL/LRU淘汰安全策略，容量或安全存储失败则RESOURCE_EXHAUSTED/UNAVAILABLE，不报告block成功。创建/登录时加载失败必须保持该账号gate关闭，不能回落成“没有block”。

每scope独立block revision从1起并持久化，有效变化+1；重复block/unblock幂等且不增版本、不重复发变化事件。BlockDevice先在串行策略点关闭该ID所有入站/出站gate，再原子持久化策略；完成前不得再开始该ID的新callback/handler、data/RPC、metadata/capability/config或schema收发/推送和内部转发，取消其在途操作、排队消息、重组、window与schema pull，清理peer声明/schema缓存关联并关所有会话/私有桥流。已执行业务只能协作取消，不回滚副作用；无法确认执行结果的本地handle返回UNKNOWN_OUTCOME，尚未执行的返回PERMISSION_DENIED/CANCELLED。已在途网络字节不可召回，但本机后续接收/分派必须丢弃，不能再向peer发送业务终态或block原因。

若该设备存在于本地目录，移除并发DeviceRemoved(PERMISSION_DENIED)，不用探活失败制造offline；block列表独立保存，不占256条应用快照名额，也不将同一设备反复重新added。停止对该ID的主动应用探测；未知IP来连时只允许为识别实际静态key必需的最少认证握手，禁止ready后的任何应用信息交换。block只约束本机SDK，不撤销对方共享网络secret，不更改全网IP占用/容量排序或命令其他设备block，因此不能据此重用其地址或保证从其他peer消失。

成功block/unblock返回SdkResult.device_block，包含scope、device_id、有效blocked、persisted_blocked、persistence_pending、持久revision及运行期state_revision；状态变化另发SdkEvent.device_block_changed，事件可先于result。持久化/清理失败返回SdkResult.error；block失败必须保持运行期deny，blocked=true、persisted_blocked保留原值、persistence_pending=true，另发有效状态变化事件并允许查询，不能假报持久成功。持久revision不变，实例内每scope从1开始的state_revision递增；修复成功后清pending并递增相应版本，重复命令仅在已可靠完成时才幂等成功。unblock写盘失败同样保留deny并报错。UnblockDevice先成功持久删除该ID，再恢复默认可信，发相同形状blocked=false的结果/事件；不重放旧业务/旧callback、不复活旧会话，只在网络租约有效且无reauth锁存时安排新的认证发现。解除block不能解除reauth latch，也不自动start_network。

GetBlockedDevices(query_id, optional peer_device_id)只读本地有效/持久策略，不联系peer。缺省filter返回当前scope所有blocked=true项（含写盘失败的运行期deny），filter存在时返回恰一项并用blocked=false表示未屏蔽；每项独立报告persisted_blocked和persistence_pending，不将运行期deny冒充重启后有效。运行期deny也计入1024上限，容量耗尽且无法为新block保留deny时先关闭整个账号业务gate再报RESOURCE_EXHAUSTED，不能淘汰旧策略或继续新目标业务。筛选ID须32字节且非self。通过SdkResult.ok接纳后恰发一个BlockedDevicesQueryResult(snapshot/error)，快照带scope、持久block revision和运行期state_revision，与directory revision无关，完整编码≤64KiB；查询结果和DeviceBlockChanged不含peer metadata或secret。block状态事件不可无声丢弃，慢adapter须背压或明确报错，并可通过该查询恢复；账号切换不能将旧scope事件解释为新账号状态。这些消息只在SdkCommand/SdkResult/SdkEvent存在，**不新增或改变WireEnvelope控制消息**。

## 7. 公开 config、能力声明与 descriptor

public/private配置严格分离：NetworkStart.private_config只供本地，SDK从不自动复制字段到PeerMetadata；公开配置由宿主显式构造PublicProfile.public_config:Any并校验类型/尺寸。公开含义是对当前账号/产品已认证、默认可信且未block的peer可见；不得填token、seed、私钥或任意用户隐私。RPC方法仍必须实际注册并满足接口/流控契约，不另设逐设备授权审批。

GetDeviceDescriptor获取PublicProfile，不是FileDescriptorSet。输入query_id/peer_device_id及可选conditional_revision（存在时≥1）；self允许离线查询，未声明profile返回同query的NOT_FOUND。远端需当前账号网络、有效租约且无reauth锁存，并先检查未block，再检查READ_PUBLIC_CONFIG；被block不能读取旧缓存。只有当前generation、距认证获取≤30秒且未offline/conflict的缓存可返回，事件from_cache=true并带authenticated_at，不能假装实时读取。否则内部复用新认证会话的初始PeerMetadata（双向bind/ready完成并支持对应功能后发送当前有效profile），最多30秒且服从会话/握手预算，不新增peer HTTP API。revision与条件相同则unchanged仅返回config_revision，否则给完整profile，错误给同query的error；仍受16KiB metadata预算，不顺带传私有config或schema，缺省/无效远端profile为PROTOCOL_ERROR。

公开 profile 初始 revision=1，使用安装身份范围持久化的单调计数器；更新前先原子持久化下一 revision 和 profile，再发布。重启不得复用旧 revision；持久化丢失则恢复可信 profile 计数或重新生成安装身份，不能发送低版本覆盖旧缓存。`UpdatePublicProfile.expected_revision` 是 CAS；输入 profile.config_revision 必须为0，由 SDK 分配；expected=0 只用于尚无 profile 的初始化。更新 mask 必须非空，只允许 `device_name`、`public_config`、`config_semantic_version`、`capabilities`；禁止重叠/未知路径，列表和 Any 整体替换，clear 使用 mask+缺省字段。

`DeviceUpdated.changed_fields` 使用 DeviceSnapshot 相对路径：`profile.device_name`、`profile.public_config`、`profile.config_revision`、`profile.config_semantic_version`、`profile.capabilities`、`boot_id`、`presence`、`last_authenticated_at`、`virtual_ipv4`，不得修改 device_id/installation_public_key/is_local。profile push 的 mask 包含实际变化字段及 config_revision；offline→online 至少含 presence。应用可直接用完整 device 替换记录，mask 仅辅助增量 UI，不要求应用自行拼接 Any 内部字段。

新 profile 原子递增一次 revision，并向所有有 READ_PUBLIC_CONFIG 的已建会话主动 push 完整 PeerMetadata；慢会话仅合并保留最新待发 profile，不能无限排队。接收同 revision 同内容可忽略，同 revision 内容不同为 CONFLICT；低版本为 STALE_REVISION、不回滚；高版本完整替换并产生本地 updated。公开 config、capability 注册/注销任一变化都改变同一 profile revision。handler 注册必须与 capability 声明原子一致；未注册/注销中的方法不可凭旧声明执行。直接更新 capabilities 仅允许引用当前已注册 handler，新增/变更 handler 用 RegisterHandler；纯数据消费者也可以不声明 RPC 能力。

capability.method_id 在 profile 内唯一；request/response type URL 必须形如 `type.googleapis.com/<protobuf.full.Name>` 或可信注册的同结构前缀，不解析远程 URL。semantic_version 使用 SemVer2，含主次补丁且不允许前导零；调用者选择确切已声明版本，不自动猜测兼容版本。最低实现支持 UNARY/BIDI，CLIENT/SERVER_STREAMING 为保留可扩展能力；未实现类型返回 UNSUPPORTED，不能伪装 bidi。当声明 descriptor 时 digest 必须32字节，指向 exact serialized FileDescriptorSet 的 SHA256。

RegisterHandler 提供 descriptor_set 时，SDK 验证方法及 request/response 类型确实存在、类型闭包完整，将该集合序列化一次并按原字节存储用于 pull；计算 digest 后写入公开 capability，调用者若同时提供不同 digest 则拒绝注册。不应每次重新序列化后假设 hash 不变。已存在 method 的同一注册命令视为替换 handler/能力，先验证全部新状态再原子切换，对新调用生效；已有调用继续使用原 handler 直到终态。入站调用的本地 RpcEvent 携带接纳时绑定的 handler_id，后续该调用事件保持同一归属，宿主无需根据当前方法表猜测旧调用属于哪个注册；该本地路由字段不进入 peer WireEnvelope。注销拒绝新调用，已有调用同样可收尾；关闭网络则取消全部活动调用。UpdatePublicProfile、RegisterHandler、UnregisterHandler 成功时 SdkResult.public_profile 返回最终完整 profile，不另发含糊的 ok。

descriptor **按需 pull**：metadata 只带 digest，不广播 FileDescriptorSet。`DescriptorQuery` 携带 query ID/digest/timeout，服务端先检查 PULL_DESCRIPTOR 和 digest 是否对应当前公开 capability，然后以 DescriptorChunk 分片，每片≤16KiB、总量≤256KiB。接收方按 offset 连续重组，校验 SHA256，再解析 FileDescriptorSet；不能每片各解析成完整集合。查询 deadline 到期清理状态并返回 DescriptorError；没有独立 descriptor cancel，最多一个活动 pull，可关闭会话取消。整个集合及其依赖一起受256KiB上限，超限不得发送单个大记录、无界递归 import 或隐式网络 fetch。descriptor 可能不提供，返回 NOT_FOUND/UNSUPPORTED 不影响已编译应用类型正常调用。

## 8. 低级 send/receive 与确认

`DataMessage.fragment` 提供两种显式二进制格式：PROTOBUF_MESSAGE 的 protobuf_bytes 是 application_type_url 指向的消息编码；PROTOBUF_ANY 是整个 google.protobuf.Any 的编码，解包后的内层 type_url 必须与 application_type_url 一致，Any.value 仍是目标消息的 Protobuf binary。JSON、原始 UTF-8、任意 blob 不能因用了 bytes 就隐式合法；应用要传任意 blob，需定义自己的 `message Blob { bytes value = 1; }` 后编码。type URL 选择允许的解码器，不作为鉴权依据。

本地 `send` 接受一个完整 DataMessage（offset=0、total=实际长度），SDK 分成≤16KiB wire 片；local `DataReceived` 也只交付重组完整消息。peer 从会话确定，同 message ID 所有片的 in_reply_to/requested_ack/timeout/类型/总长必须一致。发送双方每个逻辑 message 都用独立随机16字节 ID，in_reply_to 仅关联应用回复，不自动创建调用状态或确认对方成功。

SDK 在第一个片到达时启动接收 timeout，发送端从命令接纳开始计算完整 deadline；传送前扣除本地排队耗时，并把剩余预算填入所有 wire 片。相对 timeout 不依赖跨端时钟同步；网络单程耗时无法从相对预算精确扣除，发送端 deadline 始终优先，迟到响应丢弃。不因收到后续片而延长超时。

| ACK | SDK/应用承诺 |
| --- | --- |
| RECEIVED | 全量重组、类型/长度/权限校验通过并进入有界 SDK 内存；不保证已交付应用，更不保证落盘 |
| ACCEPTED | 已找到唯一订阅者/处理器，成功进入其有界队列，应用接受处理责任；不保证已完成 |
| PROCESSED | 应用通过 CompleteData 明确报告完成；业务是否事务落盘由应用契约决定 |

requested_ack 必须为三种之一；receiver 按 RECEIVED→ACCEPTED→PROCESSED 单调发送，最多发送到请求阶段。更高阶段蕴含较低阶段，不得降低。接收方无匹配 subscription 返回 NOT_FOUND，多订阅者对相同 type URL 的重叠注册返回 CONFLICT，不做隐式多播。订阅 type URL 数≤64。SDK 自动发 RECEIVED，在成功进入已注册订阅有界队列后自动发 ACCEPTED；应用也可 CompleteData(ACCEPTED) 幂等确认，但不能撤回。只有应用可报 PROCESSED，尚未 ACCEPTED 时禁止 PROCESSED。每订阅队列最多64消息/4MiB、全运行时总计≤16MiB，满时不得丢弃并假称 ACCEPTED，应 DataError(RESOURCE_EXHAUSTED)。

DataCancel 是协作式终止：未开始的重组/排队可撤销，已开始业务尽力通知，不能回滚副作用。应用收到 PeerDataCancel 后尽快停止，并用 CompleteData(error=CANCELLED) 回报；终态后的重复 cancel/ack 忽略，未知有效 ID cancel 幂等忽略。DataError 是该 message 的终态失败；本地接纳成功不妨碍后续错误。终态后不得发送新的确认或成功。data 在途槽在达到 requested_ack 或终态时释放；等待 PROCESSED 的慢应用仍占槽，避免无界积压。

## 9. RPC request/chunk/end/cancel 与背压

调用方先发送 RpcRequest，method/type/streaming/version 必须匹配目标已声明 capability。请求本身不带业务 payload，每个 RpcChunk 的 fragment 采用上一节的二进制规则；call ID 是调用方在当前 peer 命名空间唯一的16字节 ID，收到重复活跃 call 不重复分派 handler。双方都可以发起调用，极低概率 ID 冲突按 CONFLICT 拒绝。

每方向 logical item 的 item_sequence 从0连续增长，item 内分片 offset 连续；同一方向不交错两个 item，可交错其他 call。请求方向的类型必须是 request_type_url，响应必须是 response_type_url。**UNARY**：恰一个 request item + request end，成功时恰一个 response item + response end；失败响应可0 item+error end。**BIDI**：任一方向0到多 item，可在请求 half-close 前响应；response end 终结整个 call 并停止请求发送/处理。request RpcEnd 只表示请求 half-close，error 必须缺省。response RpcEnd 可带错误，item_count 必须匹配完整接收/发送 item 数；错误终态允许丢弃在途不完整 item，成功终态不允许。RpcCancel 可由任一方发送，终结 call、通知 handler、释放资源，但不能撤销已完成副作用。

初始每 call 每方向接收窗口由接收方 SessionBind.receive_limits 声明，默认 **65536 payload bytes + 4 logical items**。发送第一片先扣一个 item credit，每片扣实际 protobuf_bytes 长度的 byte credit（包括 Any 外壳）；两个额度都足够才允许开始/继续。空 item 扣一个 item credit、不扣 bytes。RpcWindow 是接收方给予指定方向 sender 的增量，不能伪造给自己发送方向加额度。

接收方可在 fragment 从网络缓冲安全移入已预留且有界的重组区后返还 byte credit，使1MiB item 不会卡在64KiB窗口；logical item credit 仅在应用消费/丢弃完整 item、释放队列槽后返还。**先预留 total_size，再返还 credit**，防止靠 window 产生无界重组。任意时刻未消费的 byte credit≤65536、item credit≤4（协商更低时从低值），grant 加法溢出/超过接收额度视作 PROTOCOL_ERROR。credit 只针对 payload，不包括 envelope 头；request/end/cancel/window/错误有独立小型控制队列，最多128条/64KiB，不能被数据窗口堵住；控制队列耗尽则关流。

每 call 最多4个未消费完整 item、合计≤4MiB，仍受会话/运行时32MiB重组预算约束；不足时在分配前 RESOURCE_EXHAUSTED，不先 ACK 再丢弃。窗口为0时等待、取消或 deadline，不忙循环，不无限 buffering。应用 handler 通过 adapter bounded Stream 收发；unary adapter 自动封装 request/end 和单响应验证，bidi adapter 在每次消费后反馈 window。register_handler 仅注册闭包，不创建网络监听。

RPC deadline 从本地提交开始；wire timeout 为发送时剩余正预算，receiver 从首次 RpcRequest 起计时，max300秒。到期时 caller 发 RpcCancel(DEADLINE_EXCEEDED)，callee 尽力停 handler 并返回一次带 deadline 错误的 response end（若 call 尚未终态）；任何一端先选定的终态获胜，之后 cancel/end 幂等忽略。终态后的 chunk/window 丢弃并计违规，持续违规关流。缺失 request 的未知 call chunk/end/window 为协议错误，不能分配隐式调用；未知 call cancel 幂等忽略。

## 10. 重试、去重与错误终态

本方案**不承诺 exactly-once**。TCP/Noise 只提供当前流的可靠有序传输，连接断开不证明远端没执行。Data RECEIVED/ACCEPTED、RpcRequest 已发送均不能作为重试无副作用的证据。

去重 key 为 `(runtime binding, authenticated peer device_id, boot_id, kind, message_id/call_id)`，跨重连但只在本进程保留；活跃槽受前述并发预算，终态 tombstone 每 peer 最多1024、整个运行时最多8192、TTL10分钟，LRU提前淘汰可导致再次执行。tombstone 只保留 ID、请求摘要和终态/ACK，不缓存1MiB响应。相同 ID 不同请求内容返回 CONFLICT；data 摘要输入为 `E(in_reply_to, requested_ack十进制ASCII, application_type_url, encoding十进制ASCII, 完整payload)`，不包含 offset、timeout、WireEnvelope/session/sequence；RPC 重复 request 的声明比较 method/type/streaming/version，不比较随重试减少的 timeout，payload 重放不支持恢复。若应用使用 protobuf map，data 的完整 binary 必须保持逐字节一致，SDK不做语义等价归一化。重试不得延长初次接纳时的 deadline。

data 重复头/完整内容一致时不重复交付，返回已知 ACK/错误；活跃重发需继续验证完整内容，不能只凭首片就宣称匹配。重复 RPC 活跃请求不能创建第二 handler；相同声明可复用原调用状态，但重连不支持恢复流。已结束 RPC 的重复请求返回 CONFLICT（结果不缓存，请求者查询应用业务状态），不能伪造已成功响应。重组片一旦当前流重复/倒序仍按分片错误处理，去重逻辑不许可流内 offset 回退。

SDK 默认不自动重放 data/RPC；断线且无确定终态返回 UNKNOWN_OUTCOME。应用只有明确声明幂等操作或提供业务持久化 idempotency key 后才决定重试；同 ID 缓存未命中、进程重启、TTL/LRU淘汰、不同 boot 都可能再执行。客户端 timeout/cancel 与业务提交竞争的结果必须由应用查询/补偿，不声称自动回滚。

同一已认证 device/boot 可以同时存在输出流与 crossed 入站流。某一流正常 EOF 只构成该流退休，不等于 peer 的安全撤销；另一条当前 generation/address、gate 有效且仍存活的已接纳流上的入站工作、应用交付和 CompleteData 继续由其原所有者结算。已结束流上的未定 outgoing 工作只报告一次 UNKNOWN_OUTCOME，不重放，也不迁移旧密文或 RPC/call 流状态。stop、block、认证/地址代际变化、容量排除及隔离仍按各自作用域完整关闭 gate 和取消工作，不能借普通 EOF 的保留规则绕过。

命令接纳前验证错误走SdkResult.error；logout/close的执行与清理结果走各自的typed SdkResult，不能用一个通用ok掩盖失败。已接纳异步auth/query/data/RPC/schema pull分别走有operation/query/message/call ID的终态事件，网络整体错误走NetworkState.error。Wire中只有脱敏ProtocolError，不携带claim/token/原始callback；认证失败可直接关流而不暴露内部原因。`retryable`和retry_after是调度提示，不保证重试安全。所有error字段一旦出现code必须非UNSPECIFIED，成功时整个error字段缺省。

## 11. 兼容性、验证与后续落地

字段号发布后不可复用，删除字段必须 reserved；v1 不对未知 root body 默默成功。普通未知字段可在尺寸内跳过，新的消息种类、suite、RPC streaming 类型需要显式版本/能力支持。Any/descriptor 不等于自动执行任意方法，仍受注册类型、handler、权限和资源限额约束。

本轮只验证 schema 能编译、binary encode/decode 和 oneof 的实际行为，临时生成物/工具放 `/tmp`，不改根依赖。必要命令形式：

```sh
python -m grpc_tools.protoc \
  -I proto -I <grpc_tools内置_proto目录> \
  --python_out=<临时目录> \
  --descriptor_set_out=<临时目录>/sdk.pb --include_imports \
  proto/cyberbus/easytier/v1/sdk.proto
```

编码验证覆盖本地 command/result、Any payload、设备 snapshot+diff/reset、wire data 分片、RPC 流、descriptor，以及 oneof 赋值清除旧分支和拼接编码的 last-one-wins；后者验证的是必须额外做结构校验的原因，不能当作 parser 自动拒绝的证明。schema 验证不证明 Rust/prost 适配、Logto custom JWT 签发权限和官方 SDK 平台集成、Noise 库套件可用性、EasyTier no-tun/内部转发隔离、分区容量收敛或跨平台联网已经实现。后续实现须按本文运行时约束进行独立互操作与安全边界验收。

本轮实际执行记录（2026-11-17）：系统未安装独立 protoc/Python Protobuf；在 `/tmp/cyberbus-proto-check-20261117` 创建隔离 venv，安装 `grpcio-tools 1.80.1`、`protobuf 6.33.6`，内置编译器报告 `libprotoc 31.1`。编译通过，生成 Python 模块和包含全部5个 WKT依赖的 descriptor set，所有生成物均在该临时目录。

必要二进制检查全部通过：本地 auth command/result 与 FieldMask；Any 打包/解包；恰一个 self+255远端快照及 snapshot/added/updated/offline/removed/reset；恰1MiB合法应用 Protobuf 的64片×16KiB重组；unary/bidi 的 request/chunk/window/end/cancel；恰256KiB合法 FileDescriptorSet 的16片×16KiB重组与 SHA256；oneof 设置清除旧分支、拼接输入 last-one-wins、空 body 和未知字段行为。静态遍历 WireEnvelope 可达消息图，确认不包含本地 auth/control 类型或 token/seed/private_config 字段；此检查不替代 Any 内容和运行时秘密隔离校验。片段记录的 `protobuf编码长度+16字节Noise tag+4字节头` 均在64KiB内，这是长度算术检查，没有执行 Noise 加密。

本次对齐复核也已执行并通过：重新编译schema；核对JWT示例8个平铺字段与design/签发脚本一致；核对既有command/result/event字段号未重排，SdkResult不包含snapshot（原14号及名称保留为reserved）；AuthRestore、SdkClose、GetDevices、RefreshDevices、GetDeviceDescriptor及各结果/事件编码往返；验证可选cloud_policy/conditional_revision的presence、独立本地/云logout结果、profile/unchanged/error oneof；验证预登录仅self且profile/lastauth/IP缺省，以及大于64KiB快照只进入query事件。另检查E编码允许NUL且保持无歧义，修改binding_id/config_version/任一hello均改变prologue输入；这是编码与输入绑定检查，未执行实际Noise握手。新facade消息静态可达性检查确认全部留在本地控制面。临时增量检查脚本同样仅存于`/tmp/cyberbus-proto-check-20261117`。


本次冻结增量验证（2026-11-17）：沿用上述隔离工具重新编译；与增量前descriptor逐项比较，既有字段号/类型/oneof/reserved及枚举值保持不变，WireEnvelope可达的26个消息、6个枚举descriptor完全一致。新增BlockDevice/UnblockDevice/GetBlockedDevices/GetAuthState命令、optional筛选presence、oneof清除/last-one-wins、AuthEvent查询/事件及UNKNOWN_OUTCOME/frozen/persistence状态、独立请求/成功/lease/API时间均完成binary roundtrip；1024项屏蔽列表示例编码41040字节，未超过64KiB。脚本及生成物仍只在/tmp，未修改项目依赖；这些是schema/编码兼容检查，不是SDK安全状态机测试。

独立verifier及后续实现应重点校验：G0各平台唯一LogtoAdapter的真实签发/强交互证据与Rust备选；RT请求已发出后丢响应、30秒预算及迟到轮换结算；包含休眠的lease、短JWT.exp两路径和冷启动；active/pending/highwater/latch每个原子提交/崩溃点、logout/重启/回退、同epoch冲突和同轮更高epoch接受；安全记录写盘失败始终closed；block写盘失败的有效deny与持久状态区分、metadata/schema/业务及callback竞争。真实OAuth、Noise、跨端后台恢复和业务取消须另行集成验收，编译/roundtrip不能证明其已实现。
