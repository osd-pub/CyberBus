# OIDC/Logto 部署参考

`deploy/` 中的脚本是管理员在自己的 OIDC/Logto 环境中审阅后使用的参考材料，不是 CyberBus 运行时依赖，也不会替用户创建服务。公开仓库只提供占位配置；请在私有部署目录中填写 issuer、Native/SPA client、resource、scope、redirect URI 和服务器密钥。

客户端只需要标准 OIDC discovery、授权码、token 和 JWKS 端点，以及为该应用签发的受限 resource token。客户端不应持有 Management API、M2M、client secret、JWT 根密钥、账号 seed 或 refresh token。登录流程由 SDK 自己生成 PKCE verifier/state/nonce，并校验 issuer、audience/resource、client、redirect、nonce、时间和签名。

`deploy/logto-user-token.js` 是 token customizer 的参考实现。它使用稳定的 claim 字段名 `https://cyberbus.x.aixgg.com/easytier/credentials/v1`；这是协议 JSON claim 的命名空间，不代表仓库会访问这个域名。请在真实环境完成日志脱敏、scope 最小化和密钥轮换审计后再启用。

浏览器 SDK 需要独立的 Logto **SPA** application。在 `ET_PRODUCTS_JSON` 中，把 Native client 放入 `nativeClientIds`，把 SPA client 放入对应产品的 `browserClientIds`。Hook 要求 `context.application.type` 精确为 `Native` 或 `SPA`，并拒绝跨列表、重复或未知 client；不能把 SPA 加入 Native 列表来绕过。SPA 还需要允许应用 origin 的 CORS。

`check-claims.mjs` 与 `check-audit-redaction.mjs` 使用合成材料做本地检查，不连接任何服务器。不要把管理员配置、回调 URL、授权 code、token、原始审计记录或私有 fixture 放入 Git。

公共配置示例见 [test-client.json](test-client.json) 和 [test-web-client.json](test-web-client.json)。其中的 `example.com` 和 `.invalid` 地址不会提供可用登录或 relay；接入方必须替换为自己的部署值。
