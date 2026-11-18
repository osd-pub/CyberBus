package io.cyberbus.demo

import android.content.Context
import android.os.Handler
import android.os.Looper
import cyberbus.easytier.v1.Common.*
import cyberbus.easytier.v1.Sdk.*
import cyberbus.example.v1.EchoOuterClass as Echo
import com.google.protobuf.Any as ProtoAny
import com.google.protobuf.ByteString
import com.google.protobuf.Duration
import com.google.protobuf.FieldMask
import java.security.SecureRandom
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.ScheduledThreadPoolExecutor
import java.util.concurrent.TimeUnit

/** One serialized native owner; UI state is confined to the main thread. */
class DemoSession(context: Context) {
    private val app = context.applicationContext
    private val main = Handler(Looper.getMainLooper())
    private val worker = ScheduledThreadPoolExecutor(1)
    private val random = SecureRandom()
    private var handle = 0L // only touched on worker
    private var store: ProtectedStore? = null // lock lifetime exactly covers the native owner
    private var epoch = 0L
    private var eventSequence = 0L
    @Volatile private var accepting = true
    private val pendingQueries = mutableMapOf<ByteString, Long>()
    private var directoryRuntime = ByteString.EMPTY
    private var directoryRevision = 0L
    private val watchId = id()
    private val subscriptionId = id()
    private var authOperation = ByteString.EMPTY
    private var callbackSubmitted = false
    private var cancelRequested = false
    private var cancelSubmitted = false
    private var authGeneration = 0L
    private var cancelReportedGeneration = -1L
    enum class AuthContainer { BROWSER, WEBVIEW }
    var authContainer = AuthContainer.BROWSER; private set
    var authNavigation: AuthNavigation? = null; private set
    internal val presentationGeneration get() = authGeneration
    internal val presentationOperation get() = authOperation
    internal fun ownsPresentation(generation: Long, operation: ByteString, uri: String) =
        authGeneration == generation && !operation.isEmpty && authOperation == operation &&
            authBusy && !cancelRequested && !callbackSubmitted && browserUri == uri && authContainer == AuthContainer.WEBVIEW
    private var resumeGeneration = 0L
    private var foregroundActive = false
    private val deferredData = ArrayDeque<DataReceived>()
    private var deferredBytes = 0
    private var authRevision = 0L
    private var profileRevision = 0L
    private var profile = PublicProfile.getDefaultInstance()
    private val devices = linkedMapOf<ByteString, DeviceSnapshot>()
    val blocks = linkedMapOf<ByteString, DeviceBlockState>()
    val logs = ArrayDeque<String>()
    var changed: (() -> Unit)? = null
    var openBrowser: ((String) -> Unit)? = null
    var status = "正在创建 SDK…"; private set
    var auth = AuthEvent.getDefaultInstance(); private set
    var running = false; private set
    var reachable = false; private set
    var available = false; private set
    var busy = false; private set
    var authBusy = false; private set
    var refreshing = false; private set
    var foregroundReady = false; private set
    var selected: ByteString? = null; private set
    var browserUri: String? = null; private set
    @Volatile private var completionObserver: ((CompletionDiagnostic) -> Unit)? = null
    private var testEventObserver: ((ByteArray) -> Unit)? = null
    internal var testCloseResult: ByteArray? = null; private set
    val deviceList: List<DeviceSnapshot> get() = devices.values.toList()
    val canAuthenticate get() = available && !busy && !authBusy
    val authenticated get() = (auth.phase == AuthPhase.AUTHENTICATED || auth.phase == AuthPhase.DEGRADED) &&
        !auth.reauthRequired && !auth.securityStatePersistencePending
    val canStart get() = available && !busy && !authBusy && authenticated && foregroundReady && profileRevision > 0 && !running
    val canSend get() = available && !busy && !authBusy && authenticated && foregroundReady && running &&
        selected?.let { devices[it]?.presence == DevicePresence.ONLINE && blocks[it]?.blocked != true } == true

    init { create() }
    private fun id(): ByteString = ByteString.copyFrom(ByteArray(16).also(random::nextBytes))
    private fun notifyUi() { changed?.invoke() }
    fun log(text: String) {
        val clock = SimpleDateFormat("HH:mm:ss", Locale.ROOT).format(Date())
        logs.addLast("$clock · $text")
        while (logs.size > 200) logs.removeFirst()
        notifyUi()
    }
    private fun failure(error: ProtocolError) = "${error.code.name} · ${when (error.code) {
        ErrorCode.UNAUTHENTICATED -> "请通过系统浏览器登录"
        ErrorCode.UNSUPPORTED -> "核心尚不支持此操作"
        ErrorCode.UNKNOWN_OUTCOME -> "结果未知，请核对对端，勿自动重发"
        ErrorCode.LOGTO_CONFIGURATION, ErrorCode.INVALID_CLAIMS -> "请检查部署与认证配置"
        ErrorCode.CLOSED -> "SDK 已关闭，请重新创建"
        else -> "操作失败，请检查 SDK 状态"
    }}" // Never display arbitrary native errors, which may contain callback/token material.

    private fun create() {
        worker.execute {
            try {
                val config = app.assets.open("test-client.json").bufferedReader().use { it.readText() }
                val navigation = AuthNavigation(android.net.Uri.parse(org.json.JSONObject(config).getString("redirect_uri")))
                NativeBridge.load()
                val localStore = ProtectedStore(app)
                store = localStore
                val newHandle = NativeBridge.nativeCreate(config, localStore)
                check(newHandle != 0L)
                handle = newHandle
                main.post {
                    if (!accepting) return@post
                    available = true
                    authNavigation = navigation
                    status = "SDK 已创建 · 网络默认关闭"
                    log(status)
                    if (localStore.migratedLegacy) log("开发存储 · 已为旧记录持久建立首次标记并迁移完整性封装")
                    command("订阅设备", { setWatchDevices(WatchDevices.newBuilder().setWatchId(watchId)) })
                    command("订阅消息", { setSubscribeData(SubscribeData.newBuilder().setSubscriptionId(subscriptionId)
                        .addTypeUrls(ECHO_REQUEST).addTypeUrls(ECHO_REPLY)) })
                    queryDevices()
                    refreshForeground()
                }
            } catch (error: Exception) {
                releaseStore()
                main.post { status = "CONFIGURATION_ERROR · 公共配置或安全存储不可用 (${error.javaClass.simpleName})"; log(status) }
            }
            catch (error: LinkageError) {
                releaseStore()
                main.post { status = "UNAVAILABLE · 原生 SDK 未打包或 JNI 不匹配 (${error.javaClass.simpleName})"; log(status) }
            }
        }
        worker.scheduleWithFixedDelay({ poll() }, 0, 20, TimeUnit.MILLISECONDS)
    }

    private fun poll() {
        if (handle == 0L || !accepting) return
        try {
            val bytes = NativeBridge.nativePoll(handle, 100) ?: return
            check(bytes.isNotEmpty() && bytes.size <= 24 * 1024 * 1024)
            val event = SdkEvent.parseFrom(bytes)
            main.post {
                observeTestEvent(event, bytes)
                if (accepting) event(event) else settleTerminal(event)
            }
        } catch (error: Exception) { pollFailed(error.javaClass.simpleName) }
        catch (error: LinkageError) { pollFailed(error.javaClass.simpleName) }
    }
    private fun pollFailed(kind: String) {
        val old = handle
        handle = 0
        try { NativeBridge.nativeClose(old) } catch (_: Throwable) { }
        releaseStore()
        main.post { available = false; foregroundReady = false; running = false; status = "UNAVAILABLE · 事件通道关闭 ($kind)"; log(status) }
    }

    private fun releaseStore(): Boolean {
        val previous = store
        store = null
        return try { previous?.close(); true } catch (_: Exception) { false }
    }

    /** Instrumentation transport only. Reuses this owner's worker, handle and receiver. */
    internal fun observeTestEvents(observer: ((ByteArray) -> Unit)?) {
        check(BuildConfig.DEBUG)
        testEventObserver = observer
    }
    private fun observeTestEvent(event: SdkEvent, bytes: ByteArray) {
        if (!BuildConfig.DEBUG || event.bodyCase == SdkEvent.BodyCase.AUTH) return
        testEventObserver?.invoke(bytes) // Auth/authorization material never enters the bridge.
    }
    internal fun observeCompletions(observer: ((CompletionDiagnostic) -> Unit)?) {
        check(BuildConfig.DEBUG)
        completionObserver = observer
    }
    private fun diagnostic(row: CompletionDiagnostic) {
        if (!BuildConfig.DEBUG) return
        // A debug sink failure must never change application execution.
        try { completionObserver?.invoke(row) } catch (_: Exception) { }
    }
    private fun dataDiagnostic(kind: CompletionDiagnostic.Kind, received: DataReceived) {
        if (BuildConfig.DEBUG && completionObserver != null) diagnostic(CompletionDiagnostic(
            kind, received.peerDeviceId, received.message.messageId, foregroundReady = foregroundReady))
    }
    private fun completionDiagnostic(request: SdkCommand, kind: CompletionDiagnostic.Kind,
        result: SdkResult? = null, localFailure: CompletionDiagnostic.LocalFailure? = null) {
        if (!BuildConfig.DEBUG || completionObserver == null || !request.hasCompleteData()) return
        val data = request.completeData
        val completion = when {
            data.hasError() && data.error.code == ErrorCode.TYPE_MISMATCH -> CompletionDiagnostic.Completion.TYPE_MISMATCH
            data.hasError() && data.error.code == ErrorCode.RESOURCE_EXHAUSTED -> CompletionDiagnostic.Completion.RESOURCE_EXHAUSTED
            !data.hasError() && data.stage == AckStage.PROCESSED -> CompletionDiagnostic.Completion.PROCESSED
            else -> CompletionDiagnostic.Completion.OTHER
        }
        diagnostic(CompletionDiagnostic(kind, data.peerDeviceId, data.messageId, request.commandId,
            completion = completion, result = result?.let {
                when { it.hasOk() -> CompletionDiagnostic.Result.OK
                    it.hasError() -> CompletionDiagnostic.Result.ERROR
                    else -> CompletionDiagnostic.Result.UNEXPECTED_BODY }
            }, errorCode = result?.takeIf { it.hasError() }?.error?.code,
            correlated = result?.let { it.commandId == request.commandId }, localFailure = localFailure))
    }
    internal fun executeTestCommand(bytes: ByteArray, done: (ByteArray?, String?) -> Unit) {
        if (!BuildConfig.DEBUG || !accepting) { done(null, "bridge_closed"); return }
        val request = try { check(bytes.size in 1..1024 * 1024); SdkCommand.parseFrom(bytes) }
        catch (_: Exception) { done(null, "invalid_command"); return }
        if (request.commandId.size() != 16 || request.bodyCase !in setOf(
                SdkCommand.BodyCase.GET_DEVICES, SdkCommand.BodyCase.REFRESH_DEVICES,
                SdkCommand.BodyCase.NETWORK_START, SdkCommand.BodyCase.NETWORK_STOP,
                SdkCommand.BodyCase.SEND, SdkCommand.BodyCase.GET_AUTH_STATE)) {
            done(null, "command_not_allowed"); return
        }
        worker.execute {
            try {
                check(handle != 0L)
                val result = NativeBridge.nativeExecute(handle, bytes)
                check(result.size in 1..65536)
                val decoded = SdkResult.parseFrom(result)
                check(decoded.commandId == request.commandId && decoded.bodyCase != SdkResult.BodyCase.BODY_NOT_SET)
                main.post { done(result, null) }
            } catch (_: Exception) { main.post { done(null, "native_execute_failed") } }
            catch (_: LinkageError) { main.post { done(null, "native_abi_failed") } }
        }
    }

    private fun command(label: String, body: SdkCommand.Builder.() -> Unit, done: (SdkResult) -> Unit = {}) {
        if (!accepting) return
        val request = SdkCommand.newBuilder().setCommandId(id()).apply(body).build()
        completionDiagnostic(request, CompletionDiagnostic.Kind.COMPLETE_QUEUED)
        worker.execute {
            var returned = false
            try {
                check(handle != 0L)
                completionDiagnostic(request, CompletionDiagnostic.Kind.COMPLETE_ENTERED)
                val bytes = NativeBridge.nativeExecute(handle, request.toByteArray())
                returned = true
                check(bytes.isNotEmpty() && bytes.size <= 65536)
                val result = SdkResult.parseFrom(bytes)
                completionDiagnostic(request, CompletionDiagnostic.Kind.COMPLETE_RESULT, result)
                check(result.commandId == request.commandId && result.bodyCase != SdkResult.BodyCase.BODY_NOT_SET)
                main.post {
                    if (accepting) {
                        if (result.hasError()) log("$label · ${failure(result.error)}")
                        done(result)
                        notifyUi()
                    }
                }
            } catch (error: Exception) {
                completionDiagnostic(request, CompletionDiagnostic.Kind.COMPLETE_LOCAL_FAILURE,
                    localFailure = if (returned) CompletionDiagnostic.LocalFailure.INVALID_RESULT
                        else CompletionDiagnostic.LocalFailure.EXECUTION_EXCEPTION)
                main.post { if (accepting) {
                    busy = false; status = "UNAVAILABLE · $label (${error.javaClass.simpleName})"; log(status)
                    done(SdkResult.newBuilder().setCommandId(request.commandId).setError(ProtocolError.newBuilder().setCode(ErrorCode.UNAVAILABLE)).build())
                    notifyUi()
                } }
            }
            catch (error: LinkageError) {
                completionDiagnostic(request, CompletionDiagnostic.Kind.COMPLETE_LOCAL_FAILURE,
                    localFailure = CompletionDiagnostic.LocalFailure.ABI_ERROR)
                main.post { if (accepting) { busy = false; available = false; status = "UNAVAILABLE · JNI 接口不匹配"; log(status) } } }
        }
    }

    fun resume() {
        foregroundActive = true
        refreshForeground()
    }
    private fun refreshForeground() {
        if (!available || !foregroundActive) return
        val generation = ++resumeGeneration
        foregroundReady = false
        worker.execute {
            try {
                check(handle != 0L)
                val resumed = NativeBridge.nativeOnResume(handle)
                main.post {
                    if (!accepting || generation != resumeGeneration || !foregroundActive) return@post
                    if (!resumed) { log("UNAVAILABLE · 前台租约检查未通过，业务保持关闭"); return@post }
                    command("恢复状态", { setGetAuthState(GetAuthState.getDefaultInstance()) }) {
                        if (it.hasAuthState() && generation == resumeGeneration && foregroundActive) {
                            applyAuth(it.authState); foregroundReady = true
                            while (deferredData.isNotEmpty()) {
                                val received = deferredData.removeFirst()
                                dataDiagnostic(CompletionDiagnostic.Kind.DATA_RELEASED, received)
                                receive(received)
                            }
                            deferredBytes = 0
                        }
                    }
                }
            } catch (_: Exception) { main.post { if (accepting) log("UNAVAILABLE · 前台租约检查失败") } }
            catch (_: LinkageError) { main.post { if (accepting) log("UNSUPPORTED · JNI 缺少 nativeOnResume，业务保持关闭") } }
        }
    }
    fun background() { foregroundActive = false; resumeGeneration++; foregroundReady = false; notifyUi() }
    fun select(device: ByteString) {
        if (devices[device]?.isLocal != false || blocks[device]?.blocked == true) return
        selected = device; notifyUi()
    }
    fun login(register: Boolean, container: AuthContainer = AuthContainer.BROWSER) {
        if (!canAuthenticate) return
        val generation = ++authGeneration
        authContainer = container
        authBusy = true; callbackSubmitted = false; cancelRequested = false; cancelSubmitted = false; notifyUi()
        command(if (register) "注册" else "登录", {
            setAuthStart(AuthStart.newBuilder().setIntent(if (register) AuthIntent.REGISTER else AuthIntent.LOGIN))
        }) {
            if (generation != authGeneration) return@command
            if (it.hasAuthStarted()) {
                authOperation = it.authStarted.operationId
                browserUri = it.authStarted.authorizationUri
                if (cancelRequested) cancelAuth() else openPendingBrowser()
            } else { authBusy = false }
        }
    }
    fun openPendingBrowser() { browserUri?.let { openBrowser?.invoke(it) } }
    fun browserOpened() { if (authContainer == AuthContainer.BROWSER) browserUri = null }
    fun browserFailed() = presentationFailed("UNAVAILABLE · 无法打开系统浏览器")
    fun presentationFailed(message: String) { log(message); cancelAuth() }
    fun callback(uri: String) {
        if (authNavigation == null) {
            log("CONFLICT · SDK 尚未就绪或认证操作已丢失，请重新登录"); return
        }
        if (authNavigation?.isCallback(android.net.Uri.parse(uri)) != true) {
            log("INVALID_ARGUMENT · 未识别的认证回调"); return
        }
        if (authOperation.isEmpty || !authBusy) { log("CONFLICT · 没有可匹配的认证操作，请重新登录"); return }
        if (callbackSubmitted || cancelRequested) { log("CONFLICT · 认证回调已提交或操作已取消"); return }
        callbackSubmitted = true; browserUri = null; notifyUi()
        command("认证回调", { setAuthCallback(AuthCallback.newBuilder().setOperationId(authOperation).setCallbackUri(uri)) }) {
            if (it.hasError() && authBusy) cancelAuth()
        }
    }
    fun cancelAuth() {
        if (!authBusy || cancelSubmitted) return
        cancelRequested = true; browserUri = null; notifyUi()
        if (authOperation.isEmpty) return // AuthStart must settle before its real AuthCancel.
        cancelSubmitted = true
        val generation = authGeneration
        val operation = authOperation
        command("取消认证", { setAuthCancel(AuthCancel.newBuilder().setOperationId(authOperation)) }) {
            cancelSubmitted = false
            if (it.hasOk() && generation == authGeneration) {
                log("取消请求已受理 · 正在核对 SDK 终态")
                command("核对取消结果", { setGetAuthState(GetAuthState.getDefaultInstance()) }) { result ->
                    if (generation == authGeneration && result.hasAuthState()) {
                        val next = result.authState
                        applyAuth(next)
                        if (next.phase !in listOf(AuthPhase.AUTHORIZING, AuthPhase.RESTORING)) {
                            if (authOperation == operation) { authBusy = false; authOperation = ByteString.EMPTY; browserUri = null }
                            reportCancelOutcome(next)
                        }
                    }
                }
            }
        }
    }
    private fun reportCancelOutcome(next: AuthEvent) {
        if (!cancelRequested || cancelReportedGeneration == authGeneration) return
        cancelReportedGeneration = authGeneration
        log(when {
            next.hasError() && next.error.code == ErrorCode.CANCELLED || next.phase == AuthPhase.AUTH_CANCELLED -> "已取消认证 · SDK 已确认"
            next.phase == AuthPhase.AUTHENTICATED || next.phase == AuthPhase.DEGRADED -> "认证已完成 · 取消未撤回已完成登录，启动仍需手动操作"
            else -> "取消竞争已结算 · SDK 状态 ${next.phase.name}"
        })
    }
    fun restore() {
        if (!canAuthenticate) return
        authBusy = true; authOperation = id(); notifyUi()
        command("恢复授权", { setAuthRestore(AuthRestore.newBuilder().setOperationId(authOperation)) }) {
            if (it.hasError()) { authBusy = false; authOperation = ByteString.EMPTY }
        }
    }
    fun saveName(name: String) {
        if (!available || busy) return
        if (name.isBlank() || name.toByteArray().size > 128) { log("INVALID_ARGUMENT · 名称需为 1–128 字节"); return }
        busy = true; notifyUi()
        val publicConfig = Echo.PublicConfig.newBuilder().setApplicationVersion("0.1.0").build()
        val next = profile.toBuilder().setDeviceName(name.trim()).setConfigRevision(0)
            .setConfigSemanticVersion("1.0.0").setPublicConfig(ProtoAny.newBuilder()
                .setTypeUrl("type.googleapis.com/cyberbus.example.v1.PublicConfig").setValue(publicConfig.toByteString()))
        command("保存声明", { setUpdatePublicProfile(UpdatePublicProfile.newBuilder().setProfile(next)
            .setExpectedRevision(profileRevision).setUpdateMask(FieldMask.newBuilder()
                .addPaths("device_name").addPaths("public_config").addPaths("config_semantic_version"))) }) {
            busy = false
            if (it.hasPublicProfile()) { profile = it.publicProfile; profileRevision = profile.configRevision; log("已保存声明 · revision=$profileRevision") }
        }
    }
    fun start() {
        if (!canStart) return
        busy = true; notifyUi()
        command("启动网络", { setNetworkStart(NetworkStart.getDefaultInstance()) }) {
            busy = false
            if (it.hasOk()) log("启动已接纳 · 等待真实网络状态")
        }
    }
    fun stop() {
        if (!available || busy) return
        busy = true; foregroundReady = false; selected = null; notifyUi()
        command("停止网络", { setNetworkStop(NetworkStop.getDefaultInstance()) }) {
            busy = false
            if (it.hasOk()) { running = false; reachable = false; log("网络已停止"); queryDevices(); refreshForeground() }
        }
    }
    private fun query(label: String, body: SdkCommand.Builder.(ByteString) -> Unit) {
        if (pendingQueries.size >= 4) { log("RESOURCE_EXHAUSTED · 正在等待目录查询"); refreshing = false; return }
        val queryId = id()
        pendingQueries[queryId] = epoch
        command(label, { body(queryId) }) {
            if (it.hasError()) { pendingQueries.remove(queryId); refreshing = false }
        }
    }
    private fun queryDevices() = query("查询设备") { setGetDevices(GetDevices.newBuilder().setQueryId(it)) }
    fun refresh() {
        if (!available || refreshing || busy) return
        refreshing = true; notifyUi()
        query("刷新设备") { setRefreshDevices(RefreshDevices.newBuilder().setQueryId(it).setBudget(Duration.newBuilder().setSeconds(30))) }
    }
    private fun queryBlocks() = query("查询屏蔽") { setGetBlockedDevices(GetBlockedDevices.newBuilder().setQueryId(it)) }
    fun block(device: ByteString, blocked: Boolean) {
        if (!available || busy) return
        busy = true; if (selected == device) selected = null; notifyUi()
        command(if (blocked) "屏蔽" else "解除屏蔽", {
            if (blocked) setBlockDevice(BlockDevice.newBuilder().setPeerDeviceId(device))
            else setUnblockDevice(UnblockDevice.newBuilder().setPeerDeviceId(device))
        }) {
            busy = false
            if (it.hasDeviceBlock()) applyBlock(it.deviceBlock)
        }
    }
    fun send(text: String) {
        if (!canSend) return
        if (text.isBlank() || text.toByteArray().size > 8192) { log("INVALID_ARGUMENT · 消息需为 1–8192 字节"); return }
        val peer = selected ?: return
        val bytes = Echo.EchoRequest.newBuilder().setText(text).build().toByteString()
        val messageId = id()
        busy = true; notifyUi()
        command("发送", { setSend(Send.newBuilder().setPeerDeviceId(peer).setMessage(DataMessage.newBuilder()
            .setMessageId(messageId).setRequestedAck(AckStage.PROCESSED).setTimeout(Duration.newBuilder().setSeconds(30))
            .setFragment(PayloadFragment.newBuilder().setApplicationTypeUrl(ECHO_REQUEST).setEncoding(PayloadEncoding.PROTOBUF_MESSAGE)
                .setTotalSize(bytes.size()).setOffset(0).setProtobufBytes(bytes)))) }) {
            busy = false
            if (it.hasOk()) log("发送已接纳 · ${short(messageId)} → ${short(peer)} · 等待 ACK")
        }
    }
    fun logout() {
        if (!available || busy) return
        busy = true; foregroundReady = false; selected = null; notifyUi()
        command("退出", { setAuthLogout(AuthLogout.getDefaultInstance()) }) {
            busy = false
            if (it.hasAuthLogout()) {
                val result = it.authLogout
                log("退出 · 本机关闭=${result.localClosed} · 云端=${result.cloudStatus.name}")
                if (result.hasLocalError()) log(failure(result.localError))
                if (result.hasCloudError()) log(failure(result.cloudError))
                if (result.localClosed) {
                    epoch++; authGeneration++; authBusy = false; authOperation = ByteString.EMPTY; browserUri = null
                    running = false; reachable = false; blocks.clear(); clearRemote(); queryDevices(); refreshForeground()
                }
            }
        }
    }
    private fun clearRemote() { devices.entries.removeAll { !it.value.isLocal }; selected = null }
    private fun applyAuth(next: AuthEvent) {
        if (next.stateRevision < authRevision) return
        val accountChanged = auth.hasAccount() && next.hasAccount() && auth.account != next.account
        if (accountChanged) { epoch++; blocks.clear(); clearRemote() }
        val wasAuthenticated = authenticated
        auth = next; authRevision = next.stateRevision
        status = "${next.phase.name}" + if (next.reauthRequired) " · ${next.reason.name} · 请重新登录后手动启动" else ""
        if (next.phase !in listOf(AuthPhase.AUTHORIZING, AuthPhase.RESTORING)) {
            if (next.operationId == authOperation && !authOperation.isEmpty) {
                reportCancelOutcome(next)
                authBusy = false; authOperation = ByteString.EMPTY; browserUri = null; callbackSubmitted = false
            }
        }
        if (!authenticated) { running = false; reachable = false; clearRemote() }
        if (!wasAuthenticated && authenticated) { queryBlocks(); queryDevices() }
        if (next.hasError()) log(failure(next.error))
        notifyUi()
    }
    private fun snapshot(next: DevicesSnapshot) {
        if (next.runtimeId.size() != 16 || next.devicesList.count { it.isLocal } != 1 || next.devicesCount > 256) {
            log("PROTOCOL_ERROR · 无效设备快照"); return
        }
        if (directoryRuntime == next.runtimeId && next.revision < directoryRevision) return
        directoryRuntime = next.runtimeId; directoryRevision = next.revision
        devices.clear(); next.devicesList.forEach { devices[it.deviceId] = it }
        devices.values.firstOrNull { it.isLocal }?.let {
            profile = it.profile; profileRevision = if (it.hasProfile()) it.profile.configRevision else 0
        }
        if (selected !in devices.keys || selected?.let { blocks[it]?.blocked } == true) selected = null
        notifyUi()
    }
    private fun deviceEvent(next: DevicesEvent) {
        if (next.watchId != watchId) return
        if (next.hasSnapshot()) { snapshot(next.snapshot); return }
        if (next.hasReset()) { selected = null; snapshot(next.reset.snapshot); return }
        if (next.runtimeId != directoryRuntime || next.previousRevision != directoryRevision) {
            selected = null; log("目录版本不连续 · 重新查询快照"); queryDevices(); return
        }
        if (next.revision <= directoryRevision) return
        directoryRevision = next.revision
        when (next.bodyCase) {
            DevicesEvent.BodyCase.ADDED -> devices[next.added.device.deviceId] = next.added.device
            DevicesEvent.BodyCase.UPDATED -> devices[next.updated.device.deviceId] = next.updated.device
            DevicesEvent.BodyCase.OFFLINE -> devices[next.offline.device.deviceId] = next.offline.device
            DevicesEvent.BodyCase.REMOVED -> { devices.remove(next.removed.deviceId); if (selected == next.removed.deviceId) selected = null }
            else -> log("PROTOCOL_ERROR · 未知设备事件")
        }
        devices.values.firstOrNull { it.isLocal && it.hasProfile() }?.let { profile = it.profile; profileRevision = profile.configRevision }
        notifyUi()
    }
    private fun applyBlock(next: DeviceBlockResult) {
        if (!auth.hasAccount() || next.scope.issuer != auth.account.issuer || next.scope.subject != auth.account.subject ||
            next.scope.productId != auth.account.productId) return
        blocks[next.state.deviceId] = next.state
        if (next.state.blocked) { devices.remove(next.state.deviceId); if (selected == next.state.deviceId) selected = null }
        log("屏蔽 ${short(next.state.deviceId)} · 实际=${next.state.blocked} · 持久=${next.state.persistedBlocked} · 待保存=${next.state.persistencePending}")
    }
    private fun event(next: SdkEvent) {
        if (next.eventSequence <= eventSequence) { log("PROTOCOL_ERROR · 重复或逆序事件"); return }
        if (eventSequence != 0L && next.eventSequence != eventSequence + 1) {
            foregroundReady = false; selected = null; log("PROTOCOL_ERROR · 事件缺失，重新查询状态"); queryDevices(); refreshForeground()
        }
        eventSequence = next.eventSequence
        when (next.bodyCase) {
            SdkEvent.BodyCase.AUTH -> { applyAuth(next.auth); log(status) }
            SdkEvent.BodyCase.NETWORK -> {
                running = next.network.running; reachable = next.network.reachable
                if (next.network.hasError()) log(failure(next.network.error))
                else log("网络 · running=$running · reachable=$reachable")
            }
            SdkEvent.BodyCase.DEVICES -> deviceEvent(next.devices)
            SdkEvent.BodyCase.DEVICES_QUERY -> {
                val result = next.devicesQuery
                if (pendingQueries.remove(result.queryId) == epoch) {
                    if (result.hasSnapshot()) snapshot(result.snapshot)
                    if (result.hasError()) log(failure(result.error))
                }
            }
            SdkEvent.BodyCase.REFRESH_DEVICES -> {
                val result = next.refreshDevices
                if (pendingQueries.remove(result.queryId) == epoch) {
                    refreshing = false
                    log("刷新完成 · verified=${result.verified}/${result.attempted} · deferred=${result.deferred} · partial=${result.partial}")
                    if (result.hasError()) log(failure(result.error))
                    queryDevices()
                }
            }
            SdkEvent.BodyCase.DEVICE_BLOCK_CHANGED -> applyBlock(next.deviceBlockChanged)
            SdkEvent.BodyCase.BLOCKED_DEVICES -> {
                val result = next.blockedDevices
                if (pendingQueries.remove(result.queryId) == epoch) {
                    if (result.hasError()) log(failure(result.error))
                    if (result.hasSnapshot() && auth.hasAccount() && result.snapshot.scope.issuer == auth.account.issuer &&
                        result.snapshot.scope.subject == auth.account.subject && result.snapshot.scope.productId == auth.account.productId) {
                        blocks.clear(); result.snapshot.devicesList.forEach { blocks[it.deviceId] = it }
                    }
                }
            }
            SdkEvent.BodyCase.DATA_RECEIVED -> {
                val received = next.dataReceived
                val size = received.serializedSize
                if (foregroundReady) {
                    dataDiagnostic(CompletionDiagnostic.Kind.DATA_IMMEDIATE, received)
                    receive(received)
                }
                else if (deferredData.size < 64 && deferredBytes + size <= 4 * 1024 * 1024) {
                    deferredData.addLast(received); deferredBytes += size
                    dataDiagnostic(CompletionDiagnostic.Kind.DATA_DEFERRED, received)
                } else {
                    dataDiagnostic(CompletionDiagnostic.Kind.DATA_QUEUE_FULL, received)
                    log("RESOURCE_EXHAUSTED · 前台消息队列已满")
                    command("拒绝排队", { setCompleteData(CompleteData.newBuilder().setPeerDeviceId(received.peerDeviceId)
                        .setMessageId(received.message.messageId).setError(ProtocolError.newBuilder().setCode(ErrorCode.RESOURCE_EXHAUSTED))) })
                }
            }
            SdkEvent.BodyCase.DATA_STATUS -> {
                val result = next.dataStatus
                log("ACK ${short(result.messageId)} · ${if (result.hasError()) failure(result.error) else result.stage.name}")
            }
            SdkEvent.BodyCase.PEER_DATA_CANCEL -> log("对端取消 ${short(next.peerDataCancel.messageId)}")
            else -> log("UNSUPPORTED · 未处理事件 ${next.bodyCase.name}")
        }
        notifyUi()
    }
    private fun receive(received: DataReceived) {
        val message = received.message
        try {
            check(received.subscriptionId == subscriptionId && blocks[received.peerDeviceId]?.blocked != true)
            val fragment = message.fragment
            check(fragment.offset == 0 && fragment.totalSize == fragment.protobufBytes.size() && fragment.totalSize <= 65536)
            val bytes = when (fragment.encoding) {
                PayloadEncoding.PROTOBUF_MESSAGE -> fragment.protobufBytes
                PayloadEncoding.PROTOBUF_ANY -> ProtoAny.parseFrom(fragment.protobufBytes).also { check(it.typeUrl == fragment.applicationTypeUrl) }.value
                else -> error("Unsupported encoding")
            }
            val text = when (fragment.applicationTypeUrl) {
                ECHO_REQUEST -> Echo.EchoRequest.parseFrom(bytes).text
                ECHO_REPLY -> Echo.EchoReply.parseFrom(bytes).text
                else -> error("Unsupported type")
            }
            log("收到 ${short(received.peerDeviceId)} · ${text.take(8192)}")
            // log() updates the visible UI synchronously before reporting application completion.
            command("确认处理", { setCompleteData(CompleteData.newBuilder().setPeerDeviceId(received.peerDeviceId)
                .setMessageId(message.messageId).setStage(AckStage.PROCESSED)) }) {
                if (it.hasOk()) log("已报告 PROCESSED · ${short(message.messageId)}")
            }
        } catch (_: Exception) {
            log("TYPE_MISMATCH · 无法解析入站 sample Protobuf")
            command("拒绝消息", { setCompleteData(CompleteData.newBuilder().setPeerDeviceId(received.peerDeviceId)
                .setMessageId(message.messageId).setError(ProtocolError.newBuilder().setCode(ErrorCode.TYPE_MISMATCH))) })
        }
    }
    /** Final close events settle existing work only; never deliver/ACK new business data here. */
    private fun settleTerminal(next: SdkEvent) {
        when (next.bodyCase) {
            SdkEvent.BodyCase.DATA_STATUS -> {
                val result = next.dataStatus
                log("关闭结算 ACK ${short(result.messageId)} · ${if (result.hasError()) failure(result.error) else result.stage.name}")
            }
            SdkEvent.BodyCase.PEER_DATA_CANCEL -> log("关闭结算 · 对端取消 ${short(next.peerDataCancel.messageId)}")
            else -> Unit
        }
    }
    fun close(done: (() -> Unit)? = null) {
        if (!accepting) { done?.invoke(); return }
        accepting = false; available = false; foregroundReady = false; running = false; selected = null
        authGeneration++; authBusy = false; browserUri = null; authOperation = ByteString.EMPTY
        deferredData.forEach { dataDiagnostic(CompletionDiagnostic.Kind.DATA_CLEARED, it) }
        deferredData.clear(); deferredBytes = 0; notifyUi()
        worker.execute {
            var description = "SDK 已关闭"
            if (handle != 0L) {
                try {
                    val request = SdkCommand.newBuilder().setCommandId(id()).setSdkClose(SdkClose.getDefaultInstance()).build()
                    val closeBytes = NativeBridge.nativeExecute(handle, request.toByteArray())
                    val result = SdkResult.parseFrom(closeBytes)
                    if (BuildConfig.DEBUG) testCloseResult = closeBytes
                    description = if (result.commandId == request.commandId && result.hasSdkClosed() && result.sdkClosed.closed)
                        if (result.sdkClosed.hasCleanupError()) "CLOSED · ${failure(result.sdkClosed.cleanupError)}" else "SDK 已关闭"
                        else "CLOSED · SDK 清理结果未确认"
                    val closeResult = description
                    main.post { log(closeResult) }
                    // Execute SdkClose keeps the handle alive. Drain its final events before native
                    // release; post settlement to main without making either thread wait for UI.
                    val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2)
                    var eof = false
                    while (System.nanoTime() < deadline) {
                        val bytes = try { NativeBridge.nativePoll(handle, 25) }
                        catch (error: IllegalStateException) {
                            if (error.message == "native event channel closed") { eof = true; break }
                            throw error
                        }
                        if (bytes != null) {
                            check(bytes.isNotEmpty() && bytes.size <= 24 * 1024 * 1024)
                            val terminal = SdkEvent.parseFrom(bytes)
                            main.post { observeTestEvent(terminal, bytes); settleTerminal(terminal) }
                        }
                    }
                    if (!eof) description = "CLOSED · 终态事件排空超时，未确认工作结果"
                } catch (_: Throwable) { description = "CLOSED · SDK 清理返回错误" }
                finally {
                    try { NativeBridge.nativeClose(handle) } catch (_: Throwable) { description = "CLOSED · 原生释放失败" }
                    handle = 0
                }
            }
            if (!releaseStore()) description = "CLOSED · 存储锁释放未确认"
            main.post { status = description; log(description); done?.invoke() }
            worker.shutdown()
        }
    }
    companion object {
        const val ECHO_REQUEST = "type.googleapis.com/cyberbus.example.v1.EchoRequest"
        const val ECHO_REPLY = "type.googleapis.com/cyberbus.example.v1.EchoReply"
        fun short(value: ByteString): String = value.toByteArray().take(6).joinToString("") { "%02x".format(it.toInt() and 255) }
    }
}
