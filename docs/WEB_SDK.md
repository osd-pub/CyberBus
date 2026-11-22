# Web SDK

状态：`packages/cyberbus-web` 已实现浏览器出站 overlay TCP SDK；Logto SPA 真实登录和刷新已在隔离测试部署验证；真实 Chrome 页面已通过 `@easytier/browser` JSPI/WASM + 本地 Wrangler relay + overlay TCP 目标的字节 smoke。生产环境仍需在真实 `wss://` relay 和远端目标上复验。

## 1. 能力边界

浏览器 SDK 使用 `@easytier/browser` 在页面内运行 EasyTier WebAssembly，提供：

- Logto SPA Authorization Code + PKCE S256 登录。
- 浏览器内 JWKS 验签、issuer/audience/client/scope/时间/nonce/ID token 校验。
- 与 Rust SDK 相同的 CyberBus credential claim 校验和 Web Crypto HKDF 派生。
- 启动 EasyTier browser instance，连接浏览器可访问的 `ws://`/`wss://` relay。
- 通过 `openPort(ipv4, port)` / `connectTcp(ipv4, port)` 打开出站 overlay TCP 流。

浏览器**不能**：

- 创建 TUN 或修改系统路由/DNS。
- 接受 overlay 入站连接或暴露真实监听端口。
- 使用 STUN、TCP/UDP hole punching 或成为可被其他 peer 主动连接的节点。
- 实现 CyberBus Noise 应用层握手、设备目录认证或 Protobuf Data/RPC。
- 替代 Rust Protobuf SDK 的设备目录、Data、RPC、公开 profile 和完整本地状态机。

`@easytier/browser` 的浏览器 adapter 只支持出站 WebSocket peer 和 overlay IPv4 TCP 数据面。不要把 `listenTcp` 的端口租约误认为浏览器入站端口转发。

## 2. 包与 API

包路径：`packages/cyberbus-web`，包名 `@cyberbus/web`。

```ts
import { CyberBusWeb } from "@cyberbus/web";

const client = CyberBusWeb.create({
  issuer: "https://auth.example.com/oidc",
  clientId: "logto-spa-client-id",
  resource: "https://api.example.com/cyberbus",
  productId: "example-product",
  redirectUri: `${location.origin}/callback.html`,
  peers: ["wss://relay.example.com/"],
  offlineAccess: true,
});

await client.login();
await client.startNetwork();

const stream = await client.openPort("10.144.0.20", 8080);
await stream.writeAll(new TextEncoder().encode("hello"));
const result = await stream.read();
await stream.close();
```

公共配置只包含 issuer、SPA client、resource、product、redirect URI、relay peer、可选固定 overlay IPv4 和策略。不得包含 token、refresh token、seed、network secret、app PSK、PKCE verifier 或 client secret。

未配置 `ipv4` 时，默认地址由仅存在于页面内存的随机 installation ID 派生；刷新页面或重建 client 可能得到不同 overlay 地址。需要稳定地址时显式配置 `ipv4`，并由部署方保证同一产品内不冲突。

主要方法：

| 方法 | 语义 |
| --- | --- |
| `beginLogin(intent?)` | 生成 PKCE/state/nonce 和授权 URL；供宿主自管弹窗 |
| `completeLogin(callbackUri)` | 校验完整回调、交换 token、验签和派生；不暴露 token/seed |
| `login(options?)` | 打开弹窗并等待同源 callback 页面 `postMessage` |
| `startNetwork()` | 用已验证材料启动 EasyTier browser instance |
| `openPort(host, port, options?)` | 打开出站 overlay IPv4 TCP 流 |
| `connectTcp(host, port, options?)` | `openPort` 的同义入口 |
| `refresh()` | 真实走 Logto refresh、重新验签并比较派生材料 |
| `stopNetwork()` / `logout()` / `close()` | 关闭流和实例、清理内存授权/秘密 |
| `status()` | 返回 EasyTier 状态和连接数 |

`TcpConnection.write()` 可能部分写入；使用 `writeAll()` 或显式处理返回值。`read()` 返回 `{ data, eof }`，也可用 async iterator 读取到 EOF。

## 3. 登录回调

`login()` 在同步阶段先打开空白弹窗，避免 discovery 请求之后被弹窗拦截。授权完成后，Logto 重定向到已注册 callback 页面。callback 页面必须把完整 URL 发回 opener：

```html
<script>
  // 不同源 callback 页面必须改成主应用的精确 origin。
  const appOrigin = location.origin;
  window.opener?.postMessage({
    type: "cyberbus-web-auth-callback/v1",
    url: location.href,
  }, appOrigin);
  window.close();
</script>
```

SDK 只接受来自配置的 redirect origin 和本次弹窗的消息。callback 与主应用不同源时，`postMessage` 的 target origin 必须是主应用 origin。

不把 callback URL、code、token、PKCE verifier 写入日志、URL 查询参数以外的存储或遥测。浏览器 SDK 不把授权材料写入 Web Storage、IndexedDB 或 cookie；刷新页面后必须重新登录。

## 4. 凭证和网络材料

浏览器验证顺序与 Rust 侧一致：

1. 固定 issuer 的 discovery，要求 code + S256 + 允许的签名算法。
2. access token 的 `alg/kid`、JWKS 签名、`iss`、`aud`、`client_id`、`azp`、`scope=network:join`、grant kind、`iat/exp/nbf`。
3. ID token 的签名、issuer、audience、subject、nonce、auth_time 和可选 at_hash。
4. 完整 `https://cyberbus.x.aixgg.com/easytier/credentials/v1` claim，字段集合和值必须精确匹配。
5. `cyberbus/seed/v1` 长度前缀 scope → SHA-256 salt → HKDF-SHA256，得到 `network-name`、`network-secret`、app PSK 和 binding ID。

派生公式由 `packages/cyberbus-web/test/credentials.test.ts` 与 `crates/cyberbus-auth/tests/fixtures/derivation.json` 交叉验证。浏览器不把 seed、network secret、PSK 或 binding ID 暴露给应用 API。

运行中如果 refresh 成功但 epoch 或派生材料变化，SDK 停止旧网络并进入 `reauth-required`，要求重新登录后显式启动。它不会把新材料无感应用到旧连接。

## 5. Logto 配置

1. 创建 **SPA** application，登记精确 callback，例如 `http://127.0.0.1:5173/callback.html`。
2. 给 SPA 配置浏览器 origin 的 CORS；token 和 JWKS 端点必须允许该 origin。
3. 在 Custom JWT 的 `ET_PRODUCTS_JSON` 中，把 SPA client 放入对应产品的 `browserClientIds`：

```json
[
  {
    "productId": "cyberbus",
    "nativeClientIds": ["native-client-id"],
    "browserClientIds": ["spa-client-id"]
  }
]
```

4. 保持 `blockIssuanceOnError=true`，并实际验证 SPA 签发、刷新和拒绝路径。
5. 不要把 SPA client 加入 Native 列表。Hook 只接受 application type 与列表类型匹配的 client。

隔离测试部署已用独立的 SPA client 完成真实 PKCE 登录和 refresh，并确认 SPA 与 Native client 获得相同账号/产品 seed、refresh 后派生材料一致。具体 issuer、resource、client ID 和主机信息属于私有部署配置，不应提交到公开仓库；该结果也不证明真实 EasyTier relay 端口互通。

## 6. EasyTier relay 与构建

浏览器只能连接 `wss://` relay（本地开发可用 loopback `ws://`）。原生 SDK 示例中的 `tcp://relay.example.invalid:11010` 不能被浏览器使用；需要部署或提供浏览器兼容的 WSS relay。

`@easytier/browser` 目前不在公共 npm registry。集成方需要从 EasyTier 上游 `easytier-js` 工作区构建，或从私有 registry 安装。构建使用 `wasm32-wasip1`；浏览器必须支持 WebAssembly JSPI，上游发布的 bundle 还使用 `Uint8Array.fromBase64` 解码内嵌 WASM。Chrome 157 已完成真实页面验证。

```sh
cd packages/cyberbus-web
pnpm install
pnpm check
pnpm test
pnpm build
```

## 7. 示例

`examples/web-demo` 提供：

- Logto 弹窗登录和同源 callback 页面。
- 启动/停止 EasyTier 网络。
- 输入 overlay IPv4/port 并建立 TCP 流。
- 发送/读取文本。
- 只显示脱敏状态事件。

由于 `@easytier/browser` 尚未公开，demo 默认从 `/easytier-browser.js` 加载一个**自包含** ESM bundle；也可在页面中填写其他同源 ESM URL。上游包的 `dist/index.js` 将 `@easytier/runtime` 标为 external，因此不能只复制这个文件，必须把 browser 包和 runtime 一起打包并嵌入 WASM 产物。详见 [demo README](../examples/web-demo/README.md)。

## 8. 当前验收边界

已执行：

- TypeScript typecheck、构建和 27 个单元/集成测试。
- Rust/Python 派生 fixture 对照。
- ES256/ES384 签名验证。
- 隔离 Logto 部署的真实 SPA PKCE 登录、刷新、同产品 seed 一致性。
- token/JWKS CORS 预检。
- 离线 hook 178 项检查，含 Native/SPA 类型隔离和纯 Web 产品。
- 真实 Chrome 157 + 本地 OIDC fixture 登录 + `@easytier/browser` JSPI/WASM + 本地 Wrangler relay + overlay peer 的 TCP 请求/响应字节 smoke（收到 79 字节 marker）。
- Node 中真实 `@cyberbus/web` + 真实 `@easytier/browser` + 本地 relay 的双节点 TCP smoke。

未执行：

- 真实浏览器 + 生产 `wss://` relay + 远端端口的字节 smoke。本轮的浏览器验证使用 loopback `ws://` relay，未覆盖生产 WSS/TLS、域名、证书和边缘网络。
- 真实 Logto 登录与真实 relay 数据面的联合端到端；两项目前分别验证。
- 浏览器休眠/唤醒、网络切换、长时间 refresh 和 256 节点规模。
- 浏览器完整 Protobuf 设备/RPC 协议（当前不在本 SDK 范围）。
