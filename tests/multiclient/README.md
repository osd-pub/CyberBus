# 多客户端离线 controller

本目录的 Python 测试只验证命令编排、事件 ledger、存储启动意图和失败收束；不会自动登录 OIDC，也不包含任何远程主机、账号或凭据。

```sh
python3 -m unittest discover -s tests/multiclient -p 'test_*.py' -v
```

需要连接真实 SDK 时，调用方必须自行提供二进制、公共配置、每个客户端独立的 state 目录和 callback-only 登录 driver。所有路径通过命令行传入，不使用仓库内默认主机或部署目录。首次安装显式使用 `provision`，已有安装使用 `open`；不要从 open 失败回退到 provision。

测试报告只保留 PASS/FAIL/SKIP、耗时和白名单错误码。授权 URL、callback、token、seed、主机名、绝对路径和原始网络日志不得进入报告。
