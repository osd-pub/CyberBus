# 设备屏蔽、凭证变更检测与账号恢复

日期：2026-11-17。约束为 **仅部署 Logto 与 EasyTier**；不新增凭证服务器、设备注册服务器或通知服务。本文定义 SDK 安全契约；核心认证、屏蔽与锁存已实现，验证范围见 [未解决事项](UNRESOLVED.md)。当前按用户要求使用开发文件存储，不引入 Keystore，OAuth grant 默认只驻内存。参考 JWT 脚本仍只读取部署级 `ET_CREDENTIAL_EPOCH`；第 5 节的账号级恢复字段尚未接入脚本。

## 1. 默认信任与保护边界

**同账号、同产品、完成 Noise 认证的设备默认可信，无须逐台批准。** 认证需要持有账号网络材料及参与握手的安装私钥，未认证路由候选不能读取业务信息。默认可信允许交换应用主动声明的名称、公开配置、能力、schema，并使用已注册的数据/RPC 接口；它不发布私有配置、不开放任意系统端口，也不替应用注册新方法。

此策略以使用便利为优先。网络种子泄露者可生成安装密钥并表现为新的同账号设备；本地黑名单不能阻止其更换身份再次加入。种子和安装私钥同时泄露时，仅靠同一密码身份不能区分顺序使用的克隆。隔离旧种子需要恢复账号控制权并更换网络凭证，见第 5 节。

## 2. 手动 block 的精确定义

屏蔽项按 `(issuer, sub, product_id, device_id)` 存放在本机受保护的持久存储。device_id 是 Noise 实际静态公钥的 SHA-256；设备名、IP、EasyTier peer ID、boot ID 不能替代它。重启、地址变化、重新登录和 epoch 变化不清除屏蔽项；切账号仅切换命名空间。

| 状态 | 行为 |
| --- | --- |
| TRUSTED（缺省） | 完成认证、容量及协议检查后，允许已声明的业务数据和信息交换 |
| BLOCKED（用户手动设置） | 本机停止向该身份发送和接收业务数据、声明、公开配置、能力、schema、RPC 及应用服务转接 |

`block_device` 在本地串行策略点先关闭双向 gate，再取消会话、待发队列、未完成 RPC/descriptor 拉取、handler 和映射，清除对端可用目录中的声明缓存。成功返回前，屏蔽项必须持久化且 gate 已生效；持久化失败仍保持运行期关闭并返回错误，不假称重启后有效。已进入内核/网络的字节、已执行的 callback 和业务副作用无法撤回。

每次投递/发送/重连均核对策略版本。屏蔽前排队的 metadata/data/handler callback 不得在屏蔽成功后启动；本地操作终态、取消通知和屏蔽结果仍须交付。目录可发移除事件，屏蔽列表仅保留本地身份诊断信息，不继续刷新远端名称/配置，不向业务查询返回旧声明。

为识别对端并拒绝，可能仍需有预算的 Noise 身份认证；明文 hello、EasyTier 路由/保活和中继控制不属于应用信息交换。block 不保证底层覆盖网零报文或全网踢出设备。其他设备各自维护本地策略，peer 没有修改本机屏蔽表的协议命令。

`unblock_device` 删除屏蔽项，回到默认可信；下次连接重新认证、获取声明，不恢复旧流、不重放旧业务。换名称/IP后继续屏蔽；换安装密钥是新身份，按默认可信处理。屏蔽被克隆的 key 同时拒绝原设备和克隆。

256 台是支持容量，不是抗恶意全局配额；入站握手、目录、屏蔽列表和事件队列仍须有界。

## 3. 凭证变更如何发现并提示重新登录

### 3.1 检测来源与时限

SDK 内 `CredentialMonitor` 复用唯一 Logto adapter，通过现有 OAuth token endpoint **实际签发新的专用 resource access token**。不新增 HTTP API，不把 Logto 当设备表，也不依靠 peer 转述安全版本。

| 触发/预算 | 默认策略 |
| --- | --- |
| 正常运行 | 距上次真实签发核验成功 5 分钟±20%检查一次；重试不得超出租约截止时间 |
| 网络恢复、App 回前台/系统唤醒 | 距上次成功检查满 5 分钟则立即检查；租约已过期先关业务 gate |
| 单次检查 | 30 秒预算；确定可安全重试的失败才带抖动指数退避，不重叠 refresh，不延长原租约 |
| 离线验证租约 | 真实签发且验证成功后授予，截止取该次请求开始时刻加 10 分钟；到期停网并要求重新登录 |
| 冷启动恢复 | 恢复安全存储 grant 后先完成真实签发核验，成功前不开网；旧 token/seed 不能延长租约 |

周期和租约是产品初值，集成实测可调整；租约越长，未发现变更窗口越长。后台暂停不能保证定时执行，恢复调度时先检查截止时间、关 gate，再处理业务。使用包含休眠时间的单调时钟；平台不具备时唤醒即先验证，不能靠回拨墙钟延长。新进程不继承旧进程剩余租约。

成功时间用于 UI 与下一轮调度，租约起点使用本轮实际请求开始的单调时刻，避免排队或迟到响应增加授权窗口；只有完整核验且 gate 未因到期锁存时才能授予新租约。

持续互联建议申请 `offline_access`，由唯一 LogtoAdapter 独占 refresh token（官方 SDK 或基础验证阶段选定的成熟 Rust OAuth/OIDC 实现，二者互斥）。**再次调用可能命中缓存的 `getAccessToken` 不算检查成功**；adapter 须有可验证的强制刷新/缓存失效路径，取得本轮实际签发响应，不在 Runtime 另建 OAuth refresh owner。平台支持须在 G1 验证。缺少 refresh 授权或无法强制刷新时，不能声称具备后台检测；在初始 access token 到期或 10 分钟租约到期的较早时间停网并提示交互登录，不擅自增加客户端权限。

JWT `exp` 仍用于验证新 token；租约是 SDK 使用已派生网络材料的本地策略，不延长 JWT 的 API 有效期。刷新成功且材料未变，只更新租约，不弹窗。

### 3.2 比较与分类

完整验签及 issuer/sub/product/client/audience/scope/配置检查成功后才比较。同账号上下文中 `credential_epoch` 改变，或 SDK 私有层恒定时间比较发现派生网络材料改变，均为 `CREDENTIALS_CHANGED`。因此只换 root 而忘记改 epoch 也能检测。seed、网络密钥及其指纹不进入回调/UI/日志/peer 报文。不同账号不是同账号换凭证。

| 实际结果 | SDK 动作与 UI 语义 |
| --- | --- |
| 新 token 合法、材料相同 | 更新成功时间/租约，保持会话，无需重新登录 |
| 新 token 合法、epoch 或材料不同 | 停止旧网，`REAUTH_REQUIRED / CREDENTIALS_CHANGED`；“账号网络凭证已更新，请重新登录后连接设备” |
| OAuth 明确返回 `invalid_grant`、`login_required` 等授权失效 | 停网，`REAUTH_REQUIRED / SESSION_REVOKED`；“登录已失效，请重新登录” |
| 无网、DNS、5xx/限流等暂时故障，且可确认未消费 grant 或可安全重试 | `DEGRADED` 并退避；租约内已有网络可继续，“暂时无法验证登录状态”，不声称凭证已变 |
| refresh 已送达但响应丢失，轮换结果不明 | `DEGRADED / UNKNOWN_OUTCOME`，冻结该 grant 的后台重试并推荐交互登录，不重放可能已消费的 refresh token；不续租，最迟原租约到期停网 |
| 租约耗尽仍无法验证 | 停网，`REAUTH_REQUIRED / VALIDATION_LEASE_EXPIRED`；“长时间无法验证账号，远程连接已暂停，请联网后重新登录” |
| 新 token 缺 claim、错签名、错误绑定、未知配置 | 停网并报告 claims/部署错误；无效 token 不是可信变更，不能用循环登录掩盖配置错误 |

access token 到期、peer 离线、握手失败或没有可达设备，都不能证明网络凭证改变。peer 消息至多触发限速验证，不能更新租约或授权。服务器须协调多副本更新，禁止旧副本继续签旧 epoch；已观察的 epoch 回退必须拒绝，不能退回旧网。当前部署 epoch 为规范 u64；账号版本的比较/编码在扩展脚本前另行定义。

`invalid_grant` 只证明当前 grant 不可用，也可能是过期或轮换重用，不单独证明管理员主动撤销。超时不天然可重试：若无法确认请求未送出或未消费 grant，按结果未知处理。30 秒预算结束不转移 refresh 所有权；唯一 owner 继续结算可能的迟到响应，不能另起 refresh 并发消费同一授权。安全错误分类仅使用允许的 OAuth code/网络事实，不向应用转交原始 token 响应。

前台调度正常、Logto 可用且副本一致时，通常在变更后下一次 4–6 分钟检查完成，另加最多 30 秒请求预算；不是实时推送。Logto 不可达时，正常 SDK 最迟在最近成功验证所对应请求开始后 10 分钟暂停。256 台约产生每 5 分钟 256 次刷新，用抖动分散并实测服务器负载。

### 3.3 关网、回调与重新登录

确认变更或明确撤销时，先关双向业务 gate、推进 generation，再停止发现/EasyTier、取消旧任务/RPC/映射、清除远端声明及网络秘密。本机业务、安装身份、屏蔽表保留；已发送但结果不明的操作返回 `UNKNOWN_OUTCOME`，不能一律声称未执行。目录 reset 到仅 self，认证状态由同一串行所有者通知上层。

SDK 锁存 `REAUTH_REQUIRED` 及非秘密原因，宿主显示持续状态和“重新登录”入口，同一状态不反复弹窗。事件丢失/重新订阅后可查询当前状态。锁存按账号/产品安全持久化；冷启动不能用缓存绕过。存储不可用或无法可靠恢复时要求重新交互登录。网络恢复、silent refresh、旧 generation 迟到响应和 start 都不能清除锁存或自动迁网。

为清除网络秘密后仍能检测回退，安全记录包含账号绑定、epoch 高水位、`active`（上次接受材料）、`pending`（待重新认证材料）两个私有带密钥比较值，以及锁存原因。比较值由本机独立存储密钥对有长度前缀的绑定/派生材料做 HMAC，只供 SDK 内部使用，不能用于联网或对外暴露；seed/网络密钥本身不写盘。记录跨正常退出、logout、重启保留，仅显式删除本机该账号安全记录时移除；删除后必须重新交互登录，不得由 restore 建立旧基线。

login/restore/refresh/start 的所有入口先核对同一安全记录和高水位，真实新签发也不能绕过此检查。发现变化先关 gate，再将高水位、pending 与锁存作为一笔安全存储事务保存，之后才能报告状态已可靠保存；失败保持关闭并报告本地错误，不当成首次使用。记录缺失/损坏不静默初始化后恢复网络。冷启动取得新材料后先与 active/pending 比较，不能先覆盖基线再比较。

用户主动点击后启动 Native PKCE 托管登录。需要强制交互时，adapter 使用目标平台已验证的重新认证参数（例如支持时的 `prompt=login` / `max_age=0`）；后台 refresh 或简单命中 SSO 缓存不算重新认证。成功后验证新 token；凭证变更锁存须匹配 pending，epoch 不低于高水位。期间服务器再次合法递增到更高 epoch，可原子推进 pending/高水位，并由本次合格交互确认接受；同 epoch 下再次出现不同材料不替换 pending，保持暂停并排查副本。运维应在换 root 时同时递增 epoch，root-only 检测是遗漏版本更新时的保护，不能解决无版本情况下多套材料谁更新的问题。

用户取消或服务器异常，保持暂停。仅本轮交互认证成功可原子将 pending 变为 active、清除 pending/锁存并保留高水位，回到 `AUTHENTICATED / RemoteDisabled`；宿主显式 `start_network` 进入新网并重新发现，不重放旧业务。写盘失败不开放 gate。切账号使用独立策略，原账号锁存保留。logout 可销毁旧授权，但不是恢复旧材料联网的入口。

这是正常 SDK 的策略；恶意旧实现可跳过监控、租约和锁存，在旧网继续互联，不构成即时密码学吊销，也不承诺永久脱离 Logto 后持续联网。

## 4. 区分要更换的密钥

| 材料 | 所有者/范围 | 恢复动作 |
| --- | --- | --- |
| OIDC JWT 签名私钥 | Logto 租户级 | 签名密钥泄露或计划轮换，不改变已导出网络种子 |
| JWT 脚本根密钥 `ET_ROOT_KEY_HEX` | 部署级，影响多个账号 | root 泄露时管理员更换，不是单账号常规恢复入口 |
| 账号安全版本/epoch | 单账号及产品，待扩展 | 递增后签发新材料，可信设备重新登录进新网 |
| 安装私钥 | 单设备本地 | 泄露时生成新身份，旧 key 保持屏蔽；新身份按默认可信处理 |

固定 Logto 源码的管理员 API（实际安装版本核对 OpenAPI）：

```text
GET    /api/configs/oidc/private-keys
POST   /api/configs/oidc/private-keys/rotate
DELETE /api/configs/oidc/private-keys/{keyId}
```

轮换路由支持签名算法及 grace period。旧 key/JWKS 缓存/token 有效期影响验签窗口；轮换不自动撤销全部 grant/refresh token，也不擦除 seed。例行签名 key 轮换若网络材料未变，正常验签刷新后无需提示网络凭证更新。管理凭据不发给 SDK。

依据：[Logto 配置路由](https://github.com/logto-io/logto/blob/4885ab76a96899c3d104841c259e4cf46ce8d48b/packages/core/src/routes/logto-config/index.ts)。

## 5. 不新增服务的单账号恢复

建议 Logto 保存最少的非秘密账号版本，管理员修改，JWT 脚本纳入派生/claim；不保存设备 IP、在线状态、能力或 seed。**这是后续脚本扩展，当前脚本不读取该值；不能只 PATCH 字段就声称单账号已换网。** 当前可执行的部署级 root/epoch 轮换影响整个部署。

已确认的管理员接口及拟定义字段：

```text
GET   /api/users/{userId}/custom-data
PATCH /api/users/{userId}/custom-data

PATCH body example: {"customData":{"networkEpoch":"2"}}
```

PATCH 为顶层浅合并，不是递归合并/原子自增；管理员串行更新且不回退。普通账号不得经 Account API 或其他启用路径覆盖对象，customData Edit 必须关闭/ReadOnly；嵌套字段没有天然独立权限。调用需 Management audience/权限，SDK 的 `network:join` 无权执行。

`context.user.customData` 来自服务器数据库，无需终端 customData scope；真实签发 resource token 重新读取，缓存 JWT 不会。脚本扩展须定义部署级和账号级 epoch 的组合编码、旧 claim 兼容及迁移边界，避免两种轮换互相回退。

来源：[管理 customData](https://github.com/logto-io/logto/blob/4885ab76a96899c3d104841c259e4cf46ce8d48b/packages/core/src/routes/admin-user/basics.ts#L105)、[JWT 用户上下文](https://github.com/logto-io/logto/blob/4885ab76a96899c3d104841c259e4cf46ce8d48b/packages/core/src/libraries/jwt-customizer.ts#L127)、[Account API 写入](https://github.com/logto-io/logto/blob/4885ab76a96899c3d104841c259e4cf46ce8d48b/packages/core/src/routes/account/index.ts#L111)、[刷新路径](https://github.com/logto-io/logto/blob/4885ab76a96899c3d104841c259e4cf46ce8d48b/packages/core/src/oidc/grants/refresh-token.ts#L298)。

管理员恢复流程：

1. 用户通过现有可信渠道联系管理员核验账号。当前没有“通知管理员并重置 EasyTier”的 Logto 原生端点。
2. 恢复账号控制权，更新认证因素、清理可疑会话/grant；否则有有效授权的攻击者仍可刷新获得新种子。
3. 已部署账号级扩展则递增目标账号版本；未扩展只能按运维计划轮换部署 root/epoch。所有副本一致。
4. 正常 SDK 真实刷新发现变更，停止旧网、保留屏蔽项并提示重新登录，不后台无感迁网。
5. 用户重新认证，显式启动新网。离线设备下次验证/启动走同一流程；恶意旧设备仍可能留在旧网，以可信设备迁移完成为恢复依据。

如需普通用户“一键重置本人网络”，先核实 Logto 支持的扩展和强身份复核；Custom JWT/Action 可运行脚本不意味着能注册任意 HTTP 路由。本版提供人工管理员恢复，不给客户端管理权限，不引入新服务。

## 6. 实现与验收边界

本地 `.proto` 覆盖屏蔽/解除/查询及认证状态回调；peer WireEnvelope 不提供远程修改屏蔽表的命令。运行期策略持久化、监控、真实刷新、锁存和 Noise/EasyTier 关网已实现；单元测试与真实登录/刷新、双端 block/unblock 证据分别记录，不能据此推定完整轮换和长时后台验收。账号级 epoch 另需脚本版本和迁移设计。

验收边界集中在 [UNRESOLVED.md](UNRESOLVED.md)：默认认证即可互通；block 后双向数据和信息停止；解除后重新拉取声明；缓存 token 不续租；root-only/epoch 轮换均可发现；Logto 短时故障不误报变更；租约到期、重启、取消登录不恢复旧网。真实服务器轮换、强制重新认证和后台计时仍未全部执行，schema 编译不替代这些验收。
