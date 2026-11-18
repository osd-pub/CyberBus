# SDK 打包

打包入口：

```sh
scripts/package-android-sdk.sh
scripts/build-apple.sh --release
python3 scripts/package-desktop-sdk.py --target x86_64-unknown-linux-gnu
python3 scripts/package-desktop-sdk.py --target x86_64-pc-windows-msvc
```

输出包含实际编译目标、Cargo.lock、schema、头文件、依赖许可、SBOM、校验和与重新链接说明。输出目录由 `CYBERBUS_PACKAGE_DIR` 指定，默认放在被忽略的 `target/` 下。每个包的 `MANIFEST.json` 才是架构和工具链的权威记录；arm64 AAR/XCFramework 不能宣称支持其他架构。

Android Maven 坐标是本地生成仓库中的 `io.cyberbus:cyberbus-sdk:0.1.0`，namespace 为 `io.cyberbus.sdk`，使用 protobuf-javalite；不要同时添加 full `protobuf-java`。C ABI 头文件是 `include/cyberbus.h`，Swift wrapper 使用本地 XCFramework。

包构建不等于真实登录、跨网络 ACK 或平台运行验收。请把对应平台的实际命令、结果和未执行范围记录在私有 CI/测试系统中；不要提交日志、授权材料、设备序列号或本机路径。许可和第三方声明见 [NOTICE.md](NOTICE.md) 与 [RELINK.md](RELINK.md)。

版本发布由 GitHub Actions 的 tag 流程统一生成。桌面包内含 `cyberbus-cli` 和 C sample，Apple 包内含 `sample.swift`，Android release 资产另带可安装的 debug sample APK。`scripts/package-release-assets.py` 会把各平台 CI artifact 规范化、生成 examples 包和 `SHA256SUMS`，然后由 workflow 创建 GitHub Release。
