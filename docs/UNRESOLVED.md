# 当前未解决事项

本文记录公开仓库的真实边界，避免把源码构建、离线单测或一次传输探针误读成完整产品验收。

## 仍需完成的验证

- macOS、Linux、Android 的 exact cohort 仍存在设备间握手超时方向；延长业务获取预算和 Cloudflare WSS 兜底已有独立 fixture，但尚未替代完整三端 ACK 验收。
- Wi-Fi/LTE 切换后的业务恢复、重复消息和 UNKNOWN_OUTCOME 处理需要在基础双向业务稳定后重新验证。
- 完整 256 节点目录、资源回收和分区边界尚未完成真实验收；局部 controller 测试不能替代全量有向业务。
- Windows、iOS 和所有平台消费者的完整登录、网络、打包运行尚未在本公开快照中声称通过。
- 平台安全存储集成仍需由应用提供正式 `SecureStore`；`DevelopmentFileStore` 是明文开发实现。
- 主动目标路由解析与复杂网络分区处理仍需设计、单测和真实 ACK 对照。

## 已完成的公开能力

Rust SDK、Protobuf schema、C/JNI 边界、Android sample、EasyTier 最小诊断探针和可选官方 `cloudflared` connector 已纳入源码。默认 Cloudflare 兜底关闭，且 Quick Tunnel 只适合作为临时开发中继；它不提供应用认证、不保证稳定域名或生产 SLA。

遇到连通性问题时按层定位：先用 `scripts/diagnose-easytier.py` 验证 TCP/WS 原始字节，再用 Noise 探针验证握手，最后运行 SDK 登录、目录、Data 和 ACK。每一层都必须使用新的公共测试 key/配置，避免把真实授权材料写入日志。

所有测试都应记录命令、目标平台、工具链和通过/失败/未执行状态。失败或未执行不应在 README 中写成通过。
