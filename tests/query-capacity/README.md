# 查询容量 controller

这里的 Python fixture 检查四个并发查询的 admission、唯一 terminal、超额拒绝、原始 deadline 和取消收束。它是离线 controller 测试，不能证明真实五客户端、认证或网络容量。

```sh
python3 -m unittest discover -s tests/query-capacity -p 'test_*.py' -v
```

真实运行时请从命令行传入 SDK runner、二进制、公共配置、private state 目录和 callback-only driver；所有账号和服务器材料必须在测试系统外部管理。报告应明确区分 fixture PASS、live PASS、FAIL 和 NOT_RUN。
