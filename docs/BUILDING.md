# 构建与打包

推荐 Rust 1.97.1（`rust-toolchain.toml` 会约束项目版本）和 Cargo.lock。首次构建需要 Protobuf compiler；没有系统 `protoc` 时，脚本使用 `protoc-bin-vendored`。常用命令：

```sh
cargo check --workspace
cargo test --workspace --all-features -- --test-threads=1
./scripts/package-android-sdk.sh
./scripts/build-android.sh
./scripts/build-apple.sh --release
python3 scripts/package-desktop-sdk.py --target x86_64-unknown-linux-gnu
cd packages/cyberbus-web && pnpm install && pnpm check && pnpm test && pnpm build
```

构建输出统一放到被 `.gitignore` 忽略的 `target/`、`build/` 或显式 `CYBERBUS_PACKAGE_DIR`。不要把这些目录、授权 store、`local.properties`、签名文件或日志加入提交。

Android SDK 要求 JDK 17、Android SDK 35、NDK 27.2.12479018、Gradle 8.14 和 min SDK 26；默认只构建当前机器可用的 ABI。完整参数和 JNI 生命周期见 [Android sample](../examples/android-demo/README.md)。

Web SDK 需要 Node.js 22 和 pnpm。`@easytier/browser` 目前不在公共 npm registry；开发/集成时从 EasyTier 上游 `easytier-js` 工作区构建或使用私有 registry。浏览器运行时需要 WebAssembly JSPI。Web demo 的构建命令见 [demo README](../examples/web-demo/README.md)。

C ABI 和 desktop 包由 `crates/cyberbus-ffi`、`include/cyberbus.h` 与 `packaging/` 共同组成。Apple 包是本地 XCFramework，不代表已上传远程 Swift binary package。Windows/iOS 需要对应编译器和 SDK，本机没有这些工具时只能做源码检查。

离线 smoke：

```sh
cargo run -p cyberbus --example sdk_lifecycle
python3 -m unittest discover -s tests/multiclient -p 'test_*.py' -v
```

`easytier_probe` 需要用户提供 relay 和 peer 参数，输出 JSONL 的 IO/Noise 探针结果；它不读取账号配置、不启动 TUN、不声称业务可达。

发布前至少检查：`cargo fmt --all -- --check`、workspace tests、包内的 MANIFEST/SBOM、`python3 scripts/check-public-tree.py` 和 `git diff --check`。

## GitHub Release

`.github/workflows/sdk-packages.yml` 在推送 `v*` tag 时构建并发布 GitHub Release。tag 必须与 workspace 版本一致，例如 `v0.2.0` 对应 `0.2.0`。Release 包含：

- Linux x86_64、Windows x86_64、macOS arm64 原生库和 `cyberbus-cli`
- Android arm64 AAR、Maven repository 和 debug sample APK
- iOS device/simulator XCFramework、Swift package 和 `sample.swift`
- 桌面、Android、Apple sample 源码及接入文档
- `SHA256SUMS`、`release-manifest.json`、SBOM、许可证和源码材料

本地预演 release 资产汇总：

```sh
python3 scripts/package-release-assets.py \
  --tag v0.2.0 \
  --input release-artifacts \
  --output release-assets
```

正常发布通过 GitHub Actions 完成，不要手工上传替代平台构建结果。重复运行同一 tag 的 workflow 会更新已有 Release 的资产，并使用 `--clobber` 替换同名文件。
