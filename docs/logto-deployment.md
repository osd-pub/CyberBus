# 自部署 Logto 初始化与运维

这份文档和 [参考脚本](../deploy/logto-user-token.js) 是服务器侧交付物。操作由部署管理员在 Logto 主机/受信管理环境执行；终端 SDK 不需要任何管理凭据。参考脚本不会自行修改服务器；任何测试/生产部署变更都必须由管理员显式执行并先备份，不能把本地脚本检查视为 Logto 已部署。

## 1. 目标版本与已有配置

先记录实际 Logto 版本/镜像 digest、数据库备份、Native/SPA 应用、API resource、用户角色、回调、Custom JWT 脚本和环境配置。不要以最新 docs 中的能力代替实际安装版本；必须测试 `crypto.subtle`、context.application、目标 JWT 输出和刷新路径。

本轮依据官方 docs `1f3998c5777176039287dc4049b8a9945927e907` 与 Logto 源码 `4885ab76a96899c3d104841c259e4cf46ce8d48b`。官方文档明确：自部署 Custom JWT 支持 Web Crypto、TextEncoder 等标准 API；不应 import Node 包。Actions 在 OSS v1.43.0 及以后可用，但本方案不依赖 Action，不能把该最低版本误用为 JWT 脚本兼容承诺。

一个租户的 user access token Custom JWT 配置可能已有其他业务逻辑。先导出、审阅并将 EasyTier 分支合并进现有函数；**不能直接 PUT 覆盖不相关 claim/脚本环境**。默认只影响本实验专用 resource，其他 audience 返回其原业务结果。

**生产发行前置：审计脱敏。** 已读版本会把完整 customizer 结果写入审计上下文。最终 claim 键固定为 `https://cyberbus.x.aixgg.com/easytier/credentials/v1`、种子字段为 `account_seed_secret_hex`；该版本 redactor 会规范化 key 并匹配 `credential/secret` 子串，分别屏蔽整个 claim 和叶子值。不得擅自去掉这些敏感标记或改成未覆盖的旧字段名。仅要求脚本“不 console.log”仍不足以防止其他出口泄露；必须完成实际版本的真实日志验收，才可配置生产根密钥和开放 scope。未完成时只用公开测试材料与隔离用户；目标版本没有这些规则时先升级或修正脱敏。固定版本依靠已有规则即可，常规初始化不要求修改 Logto 核心源码。

**Subject 策略。** 本参考方案仅支持 `public` subject；最终 resource JWT 的 `sub` 必须等于脚本输入的 `token.accountId`，且同产品所有 Native/SPA client 保持一致。保持 Logto/provider 的 public subject 策略，不启用 pairwise 或其他 sub 重写。部署者在受限测试环境核对内部身份与最终 sub；不将内部上下文写入公开日志，也不新增暴露 accountId 的业务 claim。仅验证两个 JWT seed 相等仍不够，还需验证双方最终 network_name/network_secret 一致。

## 2. 手动初始化步骤（推荐首轮）

1. 在管理控制台创建普通 **Native** Application；首期登记 macOS/Android 的精确回调，随后按五平台客户端配置补齐其余回调。关闭不使用的 Device Flow。多 Native client 对应同一产品时在服务器策略显式声明。
2. 需要浏览器 SDK 时创建独立 **SPA** Application，登记精确 callback（例如 `http://127.0.0.1:5173/callback.html`）并配置浏览器 origin 的 CORS。不要把 SPA 复用为 Native client，也不要给它 client secret。
3. 创建专用 API resource，记录固定 HTTPS audience（它是资源标识，不要求部署新 HTTP API）；创建 `network:join` scope。
4. 配置用户角色，授予该 scope。面向全部注册用户开放时使用目标 Logto 支持的默认用户角色，并实际验证新注册账号能获 scope；不把客户端改成管理员，也不假设 Post sign-in Action 在注册时执行。受邀模式由管理员分配角色。
5. 启用所需托管注册/登录方式，配置邮件/SMS/社交连接器及重定向策略。SDK 仅触发托管注册页面，验证和密码均由 Logto处理。
6. 在 Custom JWT 中选择 **User access token**，安装/合并 [logto-user-token.js](../deploy/logto-user-token.js)，填以下脚本环境变量；这是 Logto 的 script environment，不是终端环境或 `process.env`。
7. 设置 `blockIssuanceOnError=true`（控制台字段或目标版本管理 API），并以故意失败的隔离脚本验证服务器实际阻断目标资源签发；不能只凭配置读回为 true 就视为通过。版本/构建特性可能影响执行及阻断行为。客户端始终拒绝缺失/错误 claim，不能因 hook 被跳过或服务端仍签出普通 token 而加入空密码网络。
8. 用控制台 test context 验证目标用户/Native client，再用两个独立客户端经选定的 LogtoAdapter 登录同一账号，验证真实 JWT、刷新、首次注册以及跨账号/跨产品拒绝；Rust 协议适配方案须与官方客户端交叉核验。
9. 浏览器 SPA 使用同一套真实 PKCE 验证，并额外核对 token/JWKS CORS、popup callback 和 `browserClientIds` 拒绝路径。SPA 与 Native 必须得到相同账号/产品 seed 和派生材料。
10. 持续互联场景配置并验证 `offline_access` 的实际 refresh 授权；平台 adapter 要能绕过 access token 缓存，真实重走 token 签发并执行 Custom JWT。记录 SDK 强制刷新及交互重新认证能力；不支持时按 [凭证监控规则](security.md#3-凭证变更如何发现并提示重新登录) 在 token/租约到期提示登录，不能宣传后台检测已可用。

已读 Logto core 提交的普通脚本错误阻断条件实际为 `isDevFeaturesEnabled && blockIssuanceOnError`；生产 OSS 若采用该实现，普通异常也须阻断时还需设置 **Logto 服务进程环境** `DEV_FEATURES_ENABLED=true` 并重启各副本。这是全局特性开关，部署管理员应评估该目标版本的全部影响；它不是下表的脚本环境变量。该提交的显式 `api.denyAccess()` 会独立阻断，但运行时缺失/超时等普通异常仍须验证。依据为 [签发错误处理](https://github.com/logto-io/logto/blob/4885ab76a96899c3d104841c259e4cf46ce8d48b/packages/core/src/oidc/extra-token-claims.ts#L204) 与 [进程环境定义](https://github.com/logto-io/logto/blob/4885ab76a96899c3d104841c259e4cf46ce8d48b/packages/shared/src/node/env/GlobalValues.ts#L112)；实际镜像应重新核对，不能直接套用其他版本。

| 脚本环境变量 | 值/管理方式 |
| --- | --- |
| `ET_ISSUER` | 精确固定的 HTTPS issuer；本参考脚本要求以 `/oidc` 结尾、无尾斜杠/查询/userinfo，SDK 使用相同原值 |
| `ET_RESOURCE` | 专用资源的精确 audience |
| `ET_ROOT_KEY_HEX` | 管理员生成的 32 字节随机根密钥，编码为 64 位 hex；秘密配置 |
| `ET_PRODUCTS_JSON` | 产品数组，每项 `productId`、`nativeClientIds` 和可选 `browserClientIds`；纯 Web 产品的 `nativeClientIds` 可为空，但必须至少有一个 browser client；真实 client 全局只属于一个产品和一个 application-type 列表 |
| `ET_CREDENTIAL_EPOCH` | u64 范围十进制字符串，无前导零；初次可为 `1` |
| `ET_CONFIG_VERSION` | 非空可打印 ASCII 配置版本，最长 64 字节 |

根密钥可在受控服务器用 `openssl rand -hex 32` 生成，直接写入受限秘密配置；不要复制进版本库、公开终端输出归档或客户端。备份该密钥与数据库/脚本配置，丢失后无法恢复原网络身份。所有 Logto 副本共享同一份值。

公开部署清单可包含 issuer、resource、client ID、回调、产品、配置版本、受信 relay 端点、公钥；秘密清单包含根密钥和仅初始化时使用的管理员凭据，两者不打包到同一客户端配置。

## 3. 参考脚本与本地检查

[logto-user-token.js](../deploy/logto-user-token.js) 是复制到 Logto 编辑器的函数源码，不是客户端模块，也不会自行修改服务器。它对目标 resource 严格核对 scope、user/client/application 上下文并确定性生成专用 claim；不读写用户 custom data、不调用 Management API、不访问外部服务。

```sh
node deploy/check-claims.mjs
```

该检查用公开 fixture 和标准 Web Crypto 执行同一个脚本，核对派生一致/隔离和错误分支；不会连接真实 Logto、注册账号或产生生产根密钥。实际 Node 版本及检查计数以运行输出为准。

2026-11-22 的本地结果为 `PASS: 178 checks`，包含无 resource 的 opaque 用户 token 不受影响、非目标 audience 不附加秘密、同账号多 Native client 一致、Native/SPA 类型隔离、纯 Web 产品、产品/epoch/用户隔离和错误配置拒绝。它不执行服务器的 token 签发与错误处理层，真实注册/刷新/拒绝路径仍属于 G1。

[check-audit-redaction.mjs](../deploy/check-audit-redaction.mjs) 提供独立的审计脱敏检查。按文件头步骤将固定 SHA 的 4 个公开 Logto 源文件下载到 `/tmp`，使用 Node ≥22.13 执行；检查器先核对源文件 SHA-256，再执行原版 redactor、LogEntry 与审计中间件，数据库写入由 fixture 代替。它核对实际 hook 的完整 claim、单独 seed 叶子、输入 token/环境变量，以及其他业务 claim 的保留；不复制 Logto 核心到本仓库，也不应用源码补丁。

本轮结果为 `PASS: 15 audit checks`；它也用负对照确认字符串内容和裸根密钥字段不受该规则自动保护。该结果只证明固定源码的结构化审计路径，不能替代下一项实际部署验收。

**真实日志验收：** 在生产密钥安装前，用隔离用户与公开 canary 根密钥覆盖注册/登录/刷新、拒绝和普通异常，检查审计数据库、管理导出、worker/stdout、APM 和代理的请求/响应记录。凭证 claim 应为遮罩，原始 JWT、种子及根密钥不得保留；比较/检索只输出是否命中，不公开凭证。原版 redactor 按对象 key 工作，不会解析任意错误字符串里的 JSON，也不会扫描裸字符串；不得把 JWT/seed 拼进错误文本，另行关闭或配置会捕获明文响应的监控。测试面板本身会展示 hook 结果，只用公开测试根密钥。未通过时保持生产 scope/根密钥未启用。

## 4. 可自动化的管理 API 路径

部署自动化可由管理员环境调用 Management API 创建/核对应用、scope、角色、回调，并安装 JWT 配置。已读源码有以下配置路由，实际部署应先核对版本 OpenAPI：

```text
GET   /api/configs/jwt-customizer/access-token
PUT   /api/configs/jwt-customizer/access-token
PATCH /api/configs/jwt-customizer/access-token
```

配置字段包括 `script`、`environmentVariables`、`blockIssuanceOnError`。自动化应先 GET 并在私有位置备份/比较，处理 404 的首次创建和已有脚本的显式合并；资源/应用按 ID 查找后 upsert，不因重复初始化生成第二组不兼容 client。成功后读回核对，但不打印环境中的根密钥。

本轮交付手动部署文档和 hook 源码，不提供未经实际服务器核验的一键 root 安装脚本。未来自动初始化程序应读取服务器私有凭据文件或秘密管理器，不用命令行传 M2M secret；完成后移除临时初始化授权，正常客户端不继承它。

## 5. 更新、回退和排错

- **脚本逻辑升级**：先本地 fixture，再控制台 test context，再隔离真实用户；保留已备份版本。保留账号/产品/epoch 派生编码，避免升级造成所有设备换网。
- **配置变更**：改扫描超时/relay 不必换 credential epoch；网段/端口/协议 major 变更需要双版本迁移计划，旧 SDK 对未知版本明确报配置错误。
- **密钥/epoch 轮换**：所有副本协调更新，禁止残留副本继续签旧材料。正常客户端下次真实刷新比较 epoch 和派生材料（只换 root 也会检出），立即停旧网、提示用户重新登录；交互成功后由应用显式 start，不静默迁网。默认检查 5 分钟±20%、单次 30 秒、离线验证租约 10 分钟，不能承诺实时通知或旧设备密码学吊销。普通 OIDC 签名 key 轮换若 seed 未变，不触发网络凭证变更提示。
- **账号恢复**：当前脚本只实现部署级 epoch。单账号 `customData.networkEpoch` 的管理员流程及扩展缺口见 [安全方案](security.md#5-不新增服务的单账号恢复)，仅 PATCH 字段不会改变当前脚本输出。先恢复账号控制权并清除可疑授权，再轮换网络材料。
- **回退**：恢复旧脚本逻辑须保持已发行的安全版本高水位，不回退 root/epoch 使泄露旧材料重新生效；使用已备份的当前密钥配置，不生成新 root 冒充恢复。确需再次换材料走新的递增 epoch 与重新登录流程。记录旧 token/旧网仍存活的边界。
- **常见错误**：claim 缺失查 user/client-credentials 脚本类型、resource、scope/role、允许 client、hook 开关及 block policy；不同设备 seed 不同查 issuer/sub/product/epoch/root 副本配置；context.application 缺失先核目标版本，不能删 Native/SPA 类型校验后假装兼容；SPA 被拒先查 `browserClientIds`、application type 和 CORS，不能把 SPA 加入 Native 列表绕过。

控制台/管理日志不记录种子、带 claim 的有效 JWT 和脚本环境值。该访问控制源于凭证的实际用途：此 resource token 同时携带账号网络秘密，不能当作通用可转发身份摘要。
