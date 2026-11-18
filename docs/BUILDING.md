# 构建与打包

推荐 Rust 1.97.1（`rust-toolchain.toml` 会约束项目版本）和 Cargo.lock。首次构建需要 Protobuf compiler；没有系统 `protoc` 时，脚本使用 `protoc-bin-vendored`。常用命令：

```sh
cargo check --workspace
cargo test --workspace --all-features -- --test-threads=1
./scripts/package-android-sdk.sh
./scripts/build-android.sh
./scripts/build-apple.sh --release
python3 scripts/package-desktop-sdk.py --target x86_64-unknown-linux-gnu
```

构建输出统一放到被 `.gitignore` 忽略的 `target/`、`build/` 或显式 `CYBERBUS_PACKAGE_DIR`。不要把这些目录、授权 store、`local.properties`、签名文件或日志加入提交。

Android SDK 要求 JDK 17、Android SDK 35、NDK 27.2.12479018、Gradle 8.14 和 min SDK 26；默认只构建当前机器可用的 ABI。完整参数和 JNI 生命周期见 [Android sample](../examples/android-demo/README.md)。

C ABI 和 desktop 包由 `crates/cyberbus-ffi`、`include/cyberbus.h` 与 `packaging/` 共同组成。Apple 包是本地 XCFramework，不代表已上传远程 Swift binary package。Windows/iOS 需要对应编译器和 SDK，本机没有这些工具时只能做源码检查。

离线 smoke：

```sh
cargo run -p cyberbus --example sdk_lifecycle
python3 -m unittest discover -s tests/multiclient -p 'test_*.py' -v
```

`easytier_probe` 需要用户提供 relay 和 peer 参数，输出 JSONL 的 IO/Noise 探针结果；它不读取账号配置、不启动 TUN、不声称业务可达。

发布前至少检查：`cargo fmt --all -- --check`、workspace tests、包内的 MANIFEST/SBOM、`python3 scripts/check-public-tree.py` 和 `git diff --check`。
