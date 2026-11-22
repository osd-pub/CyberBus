# 上层 SDK 接口契约

状态：核心 Rust SDK、C/JNI 绑定与 sample 已实现；实际验收范围见 [应用接入指南](INTEGRATION.md) 和 [未解决事项](UNRESOLVED.md)。正式消息类型见 [sdk.proto](../proto/cyberbus/easytier/v1/sdk.proto)，终端协议见 [protocol.md](protocol.md)。下文 snake_case 名称描述操作语义；当前统一入口为 `Client::execute(SdkCommand)` 或 `execute_bytes`，事件由单一 receiver 读取。

> 浏览器入口是独立的 `@cyberbus/web`，不实现本文件的 Protobuf `SdkCommand`/`SdkResult`/`SdkEvent` facade 或 CyberBus Noise 应用层握手。它提供 Logto SPA 登录、相同凭证 claim 校验/派生，以及 `@easytier/browser` 出站 overlay TCP。浏览器不能入站监听或创建 TUN；详见 [Web SDK](WEB_SDK.md)。

## 1. 创建与登录/注册

当前 `Client::new(config, secure_store, store_mode).await` 创建 SDK，由内部唯一 AuthManager 管理授权；`take_event_receiver` 转移事件接收权，`on_resume` 检查前台恢复时的验证租约。公开配置只含固定 issuer、Native client ID、API resource、允许产品、redirect URI、受信 bootstrap/relay 配置及本地策略；不含 client secret、M2M、seed 或服务器 root key。

可信宿主可在创建配置中显式选择 `persist_grant`，默认 false，现有 sample 默认仅内存。选择 true 只允许同一受信 store/唯一授权 owner 保存可恢复 grant；公开命令不接受 token 导入。`SdkClose` 关闭本实例并清运行期材料、保留宿主已选择的持久授权以供下次真实 `AuthRestore`；`AuthLogout` 才清除本机持久授权。恢复必须重新在线签发和核验，不能从磁盘恢复旧 lease、seed 或开网意图。开发文件模式下选择持久授权也属于明确的测试/宿主选择，不代表 Keystore 保护。

| 接口 | 输入 | 结果和约束 |
| --- | --- | --- |
| `begin_auth` | login 或 sign_up 意图、受支持平台回调配置 | AuthOperation（操作 ID、托管授权 URL）；SDK 管理 PKCE/state/nonce；Android 由宿主选择浏览器或 WebView 展示 |
| `complete_auth` | 同一操作 ID、平台回调 URL | 交给同一 LogtoAdapter 验证并交换 token，AuthState 事件报告成功/取消/错误 |
| `cancel_auth` | 操作 ID | 幂等取消；迟到 callback 不产生第二次登录结果 |
| `restore_auth` | 操作 ID；使用创建 SDK 时选定的存储策略 | 有可用平台安全存储 grant 时恢复/刷新；默认内存模式冷启动需重新授权，命令不接收 token 或任意存储路径 |
| `get_auth_state` | 无 | GetAuthState → SdkResult.auth_state，原子查询当前状态/锁存，不触发refresh；可恢复丢失通知 |
| `logout` | 本机清理/可选云退出策略 | 先关网络与活动流；本机已关闭和 Logto 撤销成功分别返回 |
| `close` | 无 | 终态；清理网络、任务、映射、订阅与私有材料 |

注册是托管页面的注册意图；使用所选LogtoAdapter验证支持的first-screen/interaction参数，参数及首次注册后回调/新用户权限均须实测。SDK 不提供接收账号密码的注册 API，也不调用 Management create-user。登录结果给账号摘要/状态，原始 access/refresh token、网络 seed 不进入 Protobuf 公开消息。

核心为 Rust，目标 Android/Windows/macOS/iOS/Linux，首期 Android App 和 macOS CLI。当前使用基于成熟 Rust OAuth/OIDC 库的协议适配器，已通过真实 Logto PKCE 登录和 refresh 验证；Android JNI 复用同一实现。同一实例只有一个 grant owner，平台 bridge 不另行持有或刷新 grant。其余平台包和规模验收以实施计划为准。原有 cyberbus.easytier.v1 namespace 保持兼容。

### 1.1 可查询认证状态与真实刷新

AuthEvent与get_auth_state返回同形状态：phase、reauth_required/reason、单实例单调state_revision、refresh_supported、interaction_recommended、refresh_grant_frozen、security_state_persistence_pending，以及最近成功核验完成时间last_online_validation_at、获准租约的请求开始时间validation_request_started_at、网络截止validation_lease_expires_at和独立API截止access_token_expires_at。事件/查询均不含seed、网络秘密或私有比较值；初始LOGGED_OUT、revision=1，时间缺省。事件在同一adapter串行，查询只读不增版本。

正常每5分钟±20%（4–6分钟）真实请求Logto签发并完整核验resource JWT，恢复网络/前台时距上次成功满5分钟立即检查。缓存getAccessToken、本地验签/JWKS读取不算成功。单次30秒预算、唯一owner、不得重叠。真实refresh支持路径的网络材料lease截止为本轮请求开始的含休眠单调时刻req_start+600秒，验收成功才授予，响应完成不延长；JWT.exp约束新token验收/API请求，不取消剩余网络lease。无offline_access/可用grant/真实强刷能力时refresh_supported=false，截止取min(token.exp,req_start+600秒)，立即明确提示交互，不能假force refresh。

暂时网络故障仅DEGRADED、原lease内继续旧网；只有可确认未消费grant或adapter保证安全时才重试。refresh已送出但响应丢失/超时可能轮换RT，须DEGRADED + UNKNOWN_OUTCOME，refresh_grant_frozen=true并推荐交互，冻结该grant后台重试、不盲重放旧RT、不续租。30秒是预算，不丢弃所有权：原owner继续结算迟到响应/RT轮换，不另起请求或owner；新交互也由同owner串行管理，旧generation迟到响应不得覆盖新grant。原lease未过期、无锁存且同材料的完整迟到成功才可解冻并从原req_start授租；过期后后台成功不能解锁。

当前 Rust adapter 直接管理唯一 refresh grant，已完成真实签发/轮换验证，Android JNI 共用它。JS/Android 官方 SDK 的缓存与强刷差异仅作为替代 adapter 的调研背景；若今后替换，仍须证明真实签发与单 owner。当前授权请求在需要 offline access 时使用 `prompt=login consent`，以取得真实 refresh grant；普通 SSO 不自动算重新认证。

后台唤醒先检查lease，再允许任何旧业务；平台无含休眠单调时钟则先关gate真实核验。冷启动不继承旧lease，restore先加载安全记录再真实签发核验，成功前不开网；不能给缓存从启动起重算10分钟。epoch或实际派生材料变更→REAUTH_REQUIRED/CREDENTIALS_CHANGED；租约耗尽→VALIDATION_LEASE_EXPIRED。invalid_grant/login_required→兼容枚举SESSION_REVOKED，UI称“登录授权已失效”，不证明管理员撤销；JWT到期/peer失败不当撤销。无效claims/签名/绑定/未知配置→CONFIGURATION_ERROR，关闭gate、保留已有锁存，提示修复部署，不伪装变更或反复诱导登录。

### 1.2 持久安全记录与重新登录

每个账号/产品保护记录包含active（上次接受材料）的epoch/HMAC比较值、pending（待强交互接受材料）的epoch/HMAC比较值、epoch高水位及reauth锁存/原因。比较值用独立本机密钥对长度前缀的账号绑定/派生网络材料和配置上下文做HMAC，只在内部恒定时间比较；实际覆盖network_secret/app_psk/binding_id，root-only也能检测。记录不存seed/网络密钥、不对外暴露，跨logout/close/重启保留。所有login/restore/refresh/start先检查同一记录；已签名/本轮签发不保证最新，低于高水位拒绝，不先覆盖基线。记录丢失/损坏/写盘失败保持closed，不能解释为首次使用；可信首次创建或显式删除后的账号记录只能经强交互建立。

发现有效变化先关gate，再原子可靠提交highwater/pending/latch，提交后才能报告完成；失败返回脱敏本地错误、security_state_persistence_pending=true，继续closed，不能假报持久成功。锁存时停止旧网、取消业务/metadata/schema/转发并reset目录到self；可能已执行的结果保留UNKNOWN_OUTCOME。reason在锁存期间非零，交互等待、失败/取消、logout和配置错误均保留原锁存；get_auth_state可持续查询。logout清授权和网络秘密，不能清此安全记录或block表。

只有用户发起且有adapter证据的真实强交互登录完整成功才可解锁：材料不低于高水位，pending存在时须匹配pending（不受首次锁存reason影响）。交互期间合法更高epoch的C可推进pending/highwater并由本次强交互接受；同epoch不同材料不替换已有pending，保持暂停并报CONFLICT排查副本，运维root轮换应同时递增epoch。成功原子提交active、清pending/latch，失败/取消/存储失败保持closed；后台refresh、restore、start、logout或重启均不能解除。成功仍为RemoteDisabled，需宿主显式start_network，不迁网、不重放旧业务。

## 2. 声明本机与启停网络

`set_local_descriptor` 提交本机应用名称、版本、公开配置 `Any`、配置类型/版本、能力列表和 descriptor 摘要。SDK 校验后产生新 revision，可在离线先保存，联网后发布；声明成功不等于已被远端拉取。

公开配置由应用主动挑选字段。私有配置只能传给本机 handler/应用，不能包含在 descriptor 的“其余字段”中自动传播。设备能力用稳定 service/method ID、请求/响应 type URL 和 RPC 种类描述；没有实际 handler 的能力不能标记 ready。

`start_network` 要求已验证账号、有效lease、无reauth锁存/待修复安全记录，以及有效的本机公开声明；统一核对持久安全记录后启网。`stop_network` 本机优先关闭并保留业务本地状态。默认远程关闭；登录/恢复成功不自动start，宿主必须明确调用。

`device_id` 来自 SDK 安装身份，应用不能自行覆盖；boot ID、实际 IP、认证状态和目录 revision 由 SDK 填写。上层可选业务 installation 标签，只作公开关联，不能替代密码身份或授权。

## 3. 设备查询与回调

```text
subscription = client.watch_devices(options, callback)
client.get_devices() -> 一致快照
client.refresh_devices(budget) -> 完整或 partial 刷新结果
subscription.close() -> 停止该订阅
```

回调首条为 snapshot，后续为 added/updated/offline/removed/reset。快照和增量带 generation/revision；更新字段包括公开配置和能力，不仅在线状态。revision 在同一 generation 严格递增；重连引起 revision 不能连续恢复时重发 reset/snapshot。

SDK 创建时即可建立安装身份并查询/订阅本地目录。尚未登录或联网时返回只含本机的 OFFLINE 诊断快照；尚未声明时 profile 缺省，未分配的 IP/认证时间缺省，不自动公开系统主机名。远端记录和发给 peer 的声明必须通过完整校验。

callback 在调用者提供的 executor 上串行投递，SDK 不持内部锁调用上层；可在 callback 里调用其他 SDK 方法，但不能同步阻塞等待自己 executor 的下一事件。订阅可取消；取消返回后不再开始新 callback，已在执行的 callback 等待/取消语义由绑定显式返回。handler 与目录 callback 使用不同有界队列，慢应用不会无限占内存。

断网导致全局状态未知时输出网络/目录 degraded 或 partial 状态，不直接给全部设备发 offline。离线必须符合 [技术方案](design.md#5-面向规模的发现与回调) 的探测规则。offline 后可保留最后声明，removed 才移除；缓存信息包含最后验证时间，不伪装实时配置。

GetDevices/RefreshDevices/GetDeviceDescriptor分别对应本地命令，接纳后由带query_id的SdkEvent给恰一个终态，不把大快照装进64KiB SdkResult；拒绝直接返回error。RefreshDevices预算默认/最大30秒，可partial，不保证遍历全网；GetDeviceDescriptor条件revision命中返回unchanged，否则完整公开profile，schema另按需pull。快照恰一个self+最多255远端，max_devices=256含本机；稳定257节点按device_id只接纳前256，其余CapacityExceeded，分区未收敛不承诺全局硬上限。

### 3.1 默认信任与手动屏蔽

同账号、同产品且Noise认证通过的设备默认可信，无逐台审批；类型/方法/容量/显式全局转发开关仍按协议校验。只通过本地手动block撤回指定设备的数据与信息交换。

| 接口 | 本地Protobuf契约 |
| --- | --- |
| `block_device(device_id)` | BlockDevice → SdkResult.device_block；先双向deny、取消业务/metadata/schema/转发和未开始callback，持久成功才返回成功 |
| `unblock_device(device_id)` | UnblockDevice → SdkResult.device_block；先持久删除策略再回默认可信，仅重新认证发现，不复活旧流 |
| `get_blocked_devices(optional device_id)` | GetBlockedDevices(query_id, optional peer_device_id) → SdkEvent.blocked_devices；只查本地有效及持久状态 |

作用域为(issuer,sub,product_id,实际Noise静态key的SHA256 device_id)，跨epoch/logout/重启保留；不按IP/名称/boot匹配，不允许self，不允许自报其他账号scope。reauth暂停仍可管理保留的当前账号；普通logout后无当前账号时需重新认证才能查询。block移除可用目录声明及缓存，阻止后续数据/RPC/config/capability/schema收发与回调；已开始业务只能协作取消，本地终态继续交付。最小身份认证及底层路由控制可能仍有流量，不是全网踢出；换安装key是新身份。

DeviceBlockChanged事件和查询均报告blocked（实际deny）、persisted_blocked、persistence_pending、持久revision及实例内每scope的state_revision。写盘失败必须保留运行期deny并返回error，另发有效状态变化事件，不假称重启有效；持久revision不变、state_revision推进，unblock失败不开放gate。缺省查询含运行期deny，指定ID查询恰一项，无屏蔽则blocked=false。每scope最多1024项，不能TTL/LRU淘汰；容量耗尽无法保留新deny时先关整个账号gate再报错。解除block不解除reauth、不自动开网，不返回旧缓存。以上控制不进入WireEnvelope。

## 4. 数据和自定义接口

| 接口 | 语义 |
| --- | --- |
| `subscribe_data(filter, callback)` | 订阅已经认证、类型/大小校验后的入站 Protobuf 消息；注册后才声明可接收能力 |
| `send(device_id, payload, options)` | payload 为 Protobuf `Any`，返回 message handle；ACK 级别、deadline、idempotency 由 options 明确 |
| `register_handler(method_descriptor, handler)` | 绑定自定义方法及请求/响应类型；注册成功后产生能力 updated；返回可注销句柄 |
| `invoke(device_id, method_id, request, options)` | unary 调用，返回类型化响应或明确错误/结果未知 |
| `open_stream(device_id, method_id, options)` | 当前支持双向流；发送/接收受信用窗口和有界队列控制。CLIENT_STREAMING / SERVER_STREAMING 为协议保留能力，未实现时返回 UNSUPPORTED，见 [protocol §7](protocol.md#7-公开-config能力声明与-descriptor) |
| `get_device_descriptor(device_id, conditional_revision)` | 获取已认证公开声明，unchanged 可只返回版本；不拉取设备私有配置 |
| `get_schema(device_id, descriptor_hash)` | 按需拉取有界 FileDescriptorSet，缓存不执行对端代码 |

`send` 成功受理只代表 SDK 持有该消息；远端 received/accepted/processed 分开报告。应用回调必须显式确认业务 processed 或返回业务错误，SDK 不能在开始回调时冒充已完成。上层收到重复 message ID 时使用 SDK 的去重上下文，但进程崩溃/远端结果丢失仍可能产生结果未知。

对未暴露 method、未注册类型、不匹配 schema、超限帧、过期调用明确拒绝。`Any.type_url` 只是类型标识，不是下载/执行 URL；SDK 不根据任意 URL 发 HTTP 请求。跨版本的兼容解析、默认值和未知字段按 Protobuf 规则处理，语义不兼容需新 major method/type。

## 5. 应用集成顺序

1. 编写业务 `.proto` 并生成本应用类型；声明哪些字段是同账号可见的公开配置，哪些方法可被远端调用。
2. 创建 SDK、注册 auth/state/device/data callbacks、注册处理器并设置本机 descriptor。
3. 调用登录或注册，在托管页面完成 Logto；Android 可选择浏览器或 WebView，其余流程不变，SDK 验证专用 JWT。
4. 显式 start network；先收到当前 snapshot，再根据 added/updated/offline 更新 UI。
5. 用远端 device ID 发送应用消息或调用声明的方法；按 ACK/业务结果显示状态，不显示 raw IP/映射端口。
6. stop/logout/close 时取消订阅和处理器，处理真实关闭结果。恢复网络后重新核对设备身份和 descriptor，而非重放旧非幂等业务。

SDK 正式发布至少提供一组双端样例：注册/登录 → 声明名称/公开配置 → callback 出现远端 → 交换自定义 Protobuf → RPC 查询配置 → 修改声明触发 updated → 下线触发 offline。该路径同时验证 facade、LogtoAdapter、EasyTier、协议与应用 handler，不能只生成 schema 就计为 SDK 完成。

Rust 的 `take_event_receiver()` 转移单 consumer `EventReceiver`，保留 `recv().await` 和 `try_recv()` 语义。每个 watch 独立限制为256事件或8 MiB，另预留5 MiB reset；溢出按最新快照重置，previous_revision取实际交付版本。StopWatchDevices在串行点清除未交付事件，返回后不再开始该watch的新交付；目录换代清除旧代队列。一般结果/业务事件使用独立有界队列。C ABI和protobuf保持原样。


### Host authorization persistence

`ClientConfig.persist_grant` is a trusted host policy flag and defaults to `false`.
The public deployment samples keep that default; the SDK continues to support the
explicit development file store without requiring a platform keystore. Setting
`persist_grant: true` opts into refresh-grant storage through the single AuthManager
and its selected store. Configuration never accepts an access token, refresh token,
seed, or other secret as input.

`SdkClose` cancels owned work and clears in-memory authorization while preserving a
previously opted-in stored grant. A new SDK instance can explicitly submit
`AuthRestore`, observe `RESTORING` then `AUTHENTICATED`, and explicitly start its
network. `AuthLogout` clears both in-memory and stored grants. Persistence does not
start a network or restore authorization implicitly.
