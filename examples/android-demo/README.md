# CyberBus Android sample

这是共享 Rust SDK 的 Kotlin sample。登录、PKCE、token、租约、设备发现和传输全部由 Rust SDK 管理，Android 层只提供浏览器/UI、JNI bytes 和开发存储 callback。

## 构建

```sh
./scripts/build-android.sh
```

需要 JDK 17、Android SDK 35、NDK 27.2.12479018、Gradle 8.14，min SDK 26。可通过 `JAVA_HOME`、`ANDROID_HOME`、`ANDROID_NDK_HOME`、`GRADLE_BIN`、`CYBERBUS_CONFIG` 和 `CYBERBUS_JNI_DIR` 指定本机工具和输入。生成的 Java、APK、AAR、native library 和 `local.properties` 不提交。

`CYBERBUS_CONFIG` 必须是只含公共部署字段的 JSON；Android 使用 `cyberbus://auth/callback`。不要加入 token、client secret、seed、PSK 或管理凭据。

## JNI 生命周期

`NativeBridge` 提供 create、execute、poll、onResume、close；所有命令和事件都是 `SdkCommand`/`SdkResult`/`SdkEvent` bytes。事件 worker 在第一条命令前启动，UI 线程不阻塞网络。回到前台先调用 `nativeOnResume`，成功后再开放业务。

开发 `ProtectedStore` 使用 app-private 明文文件、安装 marker、原子替换和锁；它不是 Keystore，不适合生产。首次安装必须显式 provision，重新打开必须使用 installed-only 模式；缺失或损坏不能当成新设备。生产应用应替换为受保护的 `SecureStore`。

关闭顺序是 `SdkClose` → 消费关闭结果和 EOF → `nativeClose`。关闭不会自动 logout，也不会把 callback、token、handle 写入 Bundle、剪贴板或 logcat。更多接入语义见 [应用接入指南](../../docs/INTEGRATION.md)。
