# 原生绑定实现契约

绑定只封装 Rust Client。业务命令、结果和事件分别编码为 `SdkCommand`、`SdkResult`、`SdkEvent`；不跨 ABI 传内部网络流或 OAuth token。SDK 创建配置来自可信宿主的公共部署 JSON；这是本地启动配置，不是 peer 业务编码，也不允许包含 client secret、seed 或管理凭据。

## 句柄和调用

C ABI 使用不透明、非零 u64 句柄和明确 owned buffer；创建返回句柄或脱敏错误，Execute 返回一次结果 buffer，Poll 返回事件/超时/终态，Close 释放并关闭句柄。返回的 native buffer 只能由配套 free 释放，不能由调用者 allocator 释放；输入 bytes 在调用期间只借用。无效/已释放句柄返回明确错误，不能解引用悬空指针；所有 FFI panic 在边界隔离。

JNI 包装同一边界，Java/Kotlin `byte[]` 在边界复制，GlobalRef 由实例所有并在关闭后释放。UI 线程不等待网络命令；执行和事件消费在独立线程。每实例一个事件消费者，adapter 先启动消费，再提交命令。Poll 超时不创建空成功事件；Close 要先兑现关闭结果，再使事件通道读取完终态至 EOF。

## 当前基础联调存储

2026-11-17 用户明确要求“不需要 Keystore，避免复杂度，先把基础的流程跑通”。当前 sample 使用显式的开发文件存储：Android app 私有目录、桌面受限权限本地文件，原子替换保存安装身份和本地状态，OAuth 授权默认仅内存。此选择优先实现真实登录、客户端列表和双向数据；以下平台安全后端是后续目标，不作为当前基础链路的前置条件。不能将开发文件存储声称为 Keystore/keyring 保护。

## 后续安全存储目标

安全存储是一笔整体 load/atomic replace 操作，必须具备机密性、完整性和跨进程单所有者。默认不持久化 OAuth 授权；安装身份、本地 block、安全比较记录与声明 revision 仍需可靠存储。`CreateNew` 是可信首次安装决策，不能把读取失败、损坏或已安装后的文件丢失当成首次使用。

Android 由 Keystore AES-GCM 密钥保护 app 私有原子文件，JNI 的同步 store callback 只传给受信 Kotlin 存储适配器，不进入 UI/事件。宿主保存首次安装标记，并排除 Android 自动备份恢复半份密钥/密文。文件替换须 fsync；解密/写入/同步失败返回错误并保持远程关闭。app 不提供“存储失败忽略并连接”。

桌面使用平台 keyring/受保护存储及实例锁。测试专用 MemoryStore 必须显式选择且日志/文档标记为易失性测试，不计为持久策略验收。无平台安全后端时可由宿主实现同一 SecureStore，不能静默落到普通明文配置。

## 平台生命周期

Android onResume、网络恢复通知先进入 Client 的租约检查；在 gate 检查完成前不开始排队的旧 handler/data/window。Activity 可重建 UI adapter，安装身份由 store 恢复。是否使用 foreground service 由 sample 的明确用户操作和系统约束决定，不承诺后台永久在线。关闭和退出取消旧 generation，回调中的旧 runtime ID 不能更新新页面状态。
