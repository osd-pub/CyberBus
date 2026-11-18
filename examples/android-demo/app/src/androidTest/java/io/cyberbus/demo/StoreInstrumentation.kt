package io.cyberbus.demo

import android.app.Activity
import android.app.Instrumentation
import android.content.Intent
import android.os.Bundle
import android.os.SystemClock
import android.widget.EditText
import java.io.File
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.UUID

/** Real-device smoke check; touches only its unique disposable development-store key. */
class StoreInstrumentation : Instrumentation() {
    private var hostedFlow = false
    private var sendText: String? = null
    private var authBoundary = false
    private var nativeReopen = false
    private var container = DemoSession.AuthContainer.BROWSER
    private var register = false
    private var invalidArguments = false
    private var timeoutSeconds = 600L
    private var raceCancel = false
    private var machineParticipant = false
    override fun onCreate(arguments: Bundle?) {
        hostedFlow = arguments?.getString("hostedFlow") == "true"
        sendText = arguments?.getString("sendText")
        authBoundary = arguments?.getString("authBoundary") == "true"
        nativeReopen = arguments?.getString("nativeReopen") == "true"
        container = if (arguments?.getString("container") == "webview") DemoSession.AuthContainer.WEBVIEW else DemoSession.AuthContainer.BROWSER
        register = arguments?.getString("intent") == "register"
        raceCancel = arguments?.getString("raceCancel") == "true"
        machineParticipant = arguments?.getString("machineParticipant") == "true"
        timeoutSeconds = arguments?.getString("hostedTimeoutSeconds")?.toLongOrNull() ?: 600L
        invalidArguments = arguments?.getString("container")?.let { it !in listOf("browser", "webview") } == true ||
            arguments?.getString("intent")?.let { it !in listOf("login", "register") } == true ||
            timeoutSeconds !in 1..600 || listOf(hostedFlow, authBoundary, nativeReopen).count { it } > 1 ||
            machineParticipant && (raceCancel || sendText != null) ||
            listOf("hostedFlow", "authBoundary", "nativeReopen", "raceCancel", "machineParticipant").any { key ->
                arguments?.getString(key)?.let { it !in listOf("true", "false") } == true
            } || arguments?.getString("hostedTimeoutSeconds")?.let { it.toLongOrNull() == null } == true ||
            !hostedFlow && listOf("container", "intent", "raceCancel", "sendText", "hostedTimeoutSeconds", "machineParticipant").any { arguments?.containsKey(it) == true }
        super.onCreate(arguments); start()
    }
    override fun onStart() {
        if (invalidArguments) {
            finish(Activity.RESULT_CANCELED, Bundle().apply { putString("stream", "FAIL: invalid auth scenario arguments\n") }); return
        }
        if (authBoundary) { checkAuthBoundary(); return }
        if (nativeReopen) { checkNativeReopen(); return }
        if (hostedFlow) { captureHostedFlow(); return }
        checkStoreBoundary()
    }

    private fun checkStoreBoundary() {
        val results = Bundle()
        val prefix = "instrumentation-${UUID.randomUUID()}"
        val scopes = mutableListOf<String>()
        var success = false
        val key = "disposable-state"
        val hash = java.security.MessageDigest.getInstance("SHA-256").digest(key.toByteArray())
            .joinToString("") { "%02x".format(it.toInt() and 255) }
        var stage = "initial"
        fun scope(label: String) = "$prefix-$label".also { scopes.add(it) }
        fun directory(scope: String) = File(targetContext.noBackupFilesDir, "cyberbus-development-store-tests/$scope")
        fun markers(scope: String) = File(targetContext.noBackupFilesDir, "cyberbus-development-store-tests/$scope-markers")
        fun missingFails(scope: String) {
            ProtectedStore.forTest(targetContext, scope).use { store ->
                var rejected = false
                try { store.load(key) } catch (_: java.io.IOException) { rejected = true }
                check(rejected)
                check(!store.save(key, byteArrayOf(1, 2, 3)))
            }
        }
        try {
            val first = byteArrayOf(0, 1, 2, 127, -128, -1)
            val persisted = scope("persisted")
            ProtectedStore.forTest(targetContext, persisted).use { store ->
                check(store.load(key) == null && store.load(key) == null) // FFI and Client initial loads
                check(File(markers(persisted), "$hash.created").isFile)
                check(!File(directory(persisted), hash).exists()) // durable marker precedes first state
                check(store.save(key, first))
                check(store.load(key)!!.contentEquals(first))
                stage = "same-process-exclusion"
                var denied = false
                try { ProtectedStore.forTest(targetContext, persisted).close() } catch (_: java.io.IOException) { denied = true }
                check(denied)
                stage = "cross-process-exclusion"
                check(!probeOtherProcess(persisted))
            }
            stage = "release-reopen"
            check(probeOtherProcess(persisted))
            ProtectedStore.forTest(targetContext, persisted).use { store ->
                check(store.load(key)!!.contentEquals(first))
                val next = ByteArray(8193) { (it % 251).toByte() }
                check(store.save(key, next) && store.load(key)!!.contentEquals(next))
            }
            stage = "missing-record"
            check(File(directory(persisted), hash).delete())
            missingFails(persisted)
            stage = "missing-vault-directory"
            val lostVault = scope("lostvault")
            ProtectedStore.forTest(targetContext, lostVault).use { check(it.save(key, first)) }
            check(directory(lostVault).deleteRecursively())
            check(File(markers(lostVault), "$hash.created").isFile)
            missingFails(lostVault)
            stage = "corrupt-record"
            val corrupt = scope("corrupt")
            ProtectedStore.forTest(targetContext, corrupt).use { check(it.save(key, first)) }
            java.io.RandomAccessFile(File(directory(corrupt), hash), "rw").use {
                val last = it.length() - 1; it.seek(last); val value = it.read(); it.seek(last); it.write(value xor 1); it.fd.sync()
            }
            missingFails(corrupt)
            stage = "interrupted-first-commit"
            val pending = scope("pending")
            ProtectedStore.forTest(targetContext, pending).use { check(it.load(key) == null) }
            missingFails(pending)
            stage = "first-save-failure"
            val failed = scope("failed")
            ProtectedStore.forTest(targetContext, failed).use { store ->
                check(store.load(key) == null)
                android.system.Os.chmod(directory(failed).path, 320) // 0500
                try { check(!store.save(key, first)) } finally { android.system.Os.chmod(directory(failed).path, 448) }
                var denied = false
                try { store.load(key) } catch (_: java.io.IOException) { denied = true }
                check(denied)
            }
            missingFails(failed)
            stage = "marker-write-failure"
            val markerFailure = scope("markerfailure")
            ProtectedStore.forTest(targetContext, markerFailure).use { store ->
                android.system.Os.chmod(markers(markerFailure).path, 320)
                var denied = false
                try { store.load(key) } catch (_: java.io.IOException) { denied = true }
                finally { android.system.Os.chmod(markers(markerFailure).path, 448) }
                check(denied)
                denied = false
                try { store.load(key) } catch (_: java.io.IOException) { denied = true }
                check(denied)
            }
            missingFails(markerFailure)
            stage = "legacy-migration"
            val legacy = scope("legacy")
            check(directory(legacy).mkdir())
            File(directory(legacy), hash).outputStream().use { it.write(first); it.fd.sync() }
            ProtectedStore.forTest(targetContext, legacy).use { store ->
                check(store.load(key)!!.contentEquals(first) && store.migratedLegacy)
                check(File(markers(legacy), "$hash.created").isFile)
            }
            ProtectedStore.forTest(targetContext, legacy).use { check(it.load(key)!!.contentEquals(first)) }
            stage = "isolated-delete"
            val deleted = scope("deleted")
            ProtectedStore.forTest(targetContext, deleted).use { store ->
                check(store.save(key, first)); check(store.delete(key)); check(store.load(key) == null)
            }
            results.putString("stream", "PASS: isolated store first marker/commit/reopen/replace; missing/corrupt/interrupted/failed writes closed; legacy migration; same-process and second-process exclusion/release; disposable delete. Production state untouched.\n")
            success = true
        } catch (error: Throwable) {
            results.putString("stream", "FAIL: store $stage ${error.javaClass.simpleName}\n")
        } finally {
            scopes.forEach { directory(it).deleteRecursively(); markers(it).deleteRecursively() } // only test factory UUID scopes
        }
        finish(if (success) Activity.RESULT_OK else Activity.RESULT_CANCELED, results)
    }
    private fun probeOtherProcess(scope: String): Boolean {
        val latch = CountDownLatch(1)
        var acquired = false
        val receiver = object : android.os.ResultReceiver(android.os.Handler(android.os.Looper.getMainLooper())) {
            override fun onReceiveResult(resultCode: Int, resultData: Bundle?) { acquired = resultCode == 1; latch.countDown() }
        }
        val connection = object : android.content.ServiceConnection {
            override fun onServiceConnected(name: android.content.ComponentName, service: android.os.IBinder) {}
            override fun onServiceDisconnected(name: android.content.ComponentName) {}
        }
        // Send the framework ResultReceiver parcel, not the test APK's anonymous
        // subclass: the second app process does not load instrumentation classes.
        val parcel = android.os.Parcel.obtain()
        val remoteReceiver = try {
            receiver.writeToParcel(parcel, 0); parcel.setDataPosition(0)
            android.os.ResultReceiver.CREATOR.createFromParcel(parcel)
        } finally { parcel.recycle() }
        val intent = Intent().setClassName(targetContext, "io.cyberbus.demo.StoreLockProbeService")
            .putExtra("scope", scope).putExtra("result", remoteReceiver)
        check(targetContext.bindService(intent, connection, android.content.Context.BIND_AUTO_CREATE))
        try { check(latch.await(15, TimeUnit.SECONDS)); return acquired }
        finally { targetContext.unbindService(connection) }
    }

    /** Opt-in real-device test: capture only the SDK authorization request, never a token/code.
     * Keeps the actual Activity/SDK alive for callback delivery and manual two-endpoint checks.
     * Read with run-as into a private runner, then use 外部 callback-only driver. */
    private fun captureHostedFlow() {
        val request = File(targetContext.noBackupFilesDir, "test-hosted-authorize.txt")
        val results = Bundle()
        var capturedSession: DemoSession? = null
        var capturedActivity: MainActivity? = null
        var participant: MachineParticipant? = null
        var finishCode = Activity.RESULT_CANCELED
        val artifacts = listOf("test-hosted-authorize.txt", "test-hosted-fields.json", "test-hosted-snapshot",
            "test-hosted-ui.json", "test-hosted-close").map { File(targetContext.noBackupFilesDir, it) }
        try {
            artifacts.forEach { it.delete() }
            if (machineParticipant) File(targetContext.noBackupFilesDir, "multiclient/ready.json").delete()
            val activity = startActivitySync(Intent(targetContext, MainActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)) as MainActivity
            capturedActivity = activity
            if (machineParticipant) runOnMainSync {
                activity.window.addFlags(android.view.WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
            }
            val field = MainActivity::class.java.getDeclaredField("session").apply { isAccessible = true }
            lateinit var session: DemoSession
            runOnMainSync { session = field.get(activity) as DemoSession; capturedSession = session }
            val readyDeadline = SystemClock.elapsedRealtime() + 15_000
            var ready = false
            while (!ready && SystemClock.elapsedRealtime() < readyDeadline) {
                runOnMainSync { ready = session.canAuthenticate }
                if (!ready) SystemClock.sleep(100)
            }
            check(ready)
            val captured = CountDownLatch(1)
            runOnMainSync {
                val browser = session.openBrowser
                if (raceCancel) {
                    val changed = session.changed
                    val submitted = DemoSession::class.java.getDeclaredField("callbackSubmitted").apply { isAccessible = true }
                    var scheduled = false
                    session.changed = {
                        changed?.invoke()
                        if (!scheduled && submitted.getBoolean(session)) {
                            scheduled = true
                            // callback() queues real exchange before this main-loop task queues
                            // AuthCancel on the same native owner. Never start a second owner.
                            android.os.Handler(android.os.Looper.getMainLooper()).post { session.cancelAuth(); session.cancelAuth() }
                        }
                    }
                }
                session.openBrowser = { uri ->
                    request.outputStream().use { it.write(uri.toByteArray()); it.fd.sync() }
                    request.setReadable(false, false); request.setWritable(false, false)
                    check(request.setReadable(true, true) && request.setWritable(true, true))
                    captured.countDown()
                    browser?.invoke(uri)
                }
                session.login(register, container)
            }
            check(captured.await(45, TimeUnit.SECONDS))
            sendStatus(0, Bundle().apply { putString("stream", "SDK authorization request captured privately; Activity remains live for hosted callback/data checks.\n") })
            val deadline = SystemClock.elapsedRealtime() + timeoutSeconds * 1000
            var closed = false
            var started = false
            var sent = false
            var authenticated = false
            var profileSaved = false
            while (!closed && SystemClock.elapsedRealtime() < deadline) {
                fillHostedFieldsIfRequested()
                participant?.pump()
                var machineReady = false
                runOnMainSync {
                    if (File(targetContext.noBackupFilesDir, "test-hosted-close").delete()) session.close()
                    closed = session.status == "SDK 已关闭" || session.status.startsWith("CLOSED")
                    if (!authenticated && session.authenticated) {
                        authenticated = true
                        sendStatus(0, Bundle().apply { putString("stream", "SDK_AUTHENTICATED; network running=${session.running}; container=${container.name}; intent=${if (register) "register" else "login"}\n") })
                    }
                    if (machineParticipant && session.authenticated && session.foregroundReady && !profileSaved && !session.busy) {
                        profileSaved = true; session.saveName("Android")
                    }
                    machineReady = machineParticipant && profileSaved && session.canStart
                    // Explicit test-only sendText requests the real Start/select/send path. No
                    // identity/auth state is supplied: wait for actual auth and an ONLINE peer.
                    if (sendText != null && !started && session.canStart) {
                        started = true
                        session.start()
                    }
                    if (sendText != null && !sent && session.running) {
                        val peer = session.deviceList.firstOrNull { !it.isLocal && it.presence.name == "ONLINE" }
                        if (peer != null) {
                            session.select(peer.deviceId)
                            if (session.canSend) {
                                val input = MainActivity::class.java.getDeclaredField("message").apply { isAccessible = true }
                                (input.get(activity) as EditText).setText(sendText)
                                session.send(sendText!!)
                                sent = true
                                sendStatus(0, Bundle().apply { putString("stream", "Submitted real app EchoRequest to SDK-discovered ONLINE peer.\n") })
                            }
                        }
                    }
                }
                if (machineReady && participant == null) {
                    participant = MachineParticipant(this, session)
                    sendStatus(0, Bundle().apply { putString("stream", "MACHINE_PARTICIPANT_READY; same App DemoSession; private raw protobuf bridge.\n") })
                }
                if (!closed) SystemClock.sleep(250)
            }
            var passed = false
            runOnMainSync { passed = authenticated && (!raceCancel || session.logs.any { it.contains("取消未撤回已完成登录") }) &&
                (!machineParticipant || participant?.closed == true) }
            results.putString("stream", "${if (passed) "PASS" else "FAIL"}: hosted ${container.name}/${if (register) "register" else "login"}; SDK acceptance=$authenticated; cancel race=$raceCancel${if (!closed) "; deadline reached" else ""}.\n")
            finishCode = if (passed) Activity.RESULT_OK else Activity.RESULT_CANCELED
        } catch (error: Throwable) {
            results.putString("stream", "Hosted-flow capture failed: ${error.javaClass.simpleName}\n")
        } finally {
            val settled = CountDownLatch(1)
            runOnMainSync { capturedSession?.close { settled.countDown() } ?: settled.countDown() }
            if (!settled.await(8, TimeUnit.SECONDS)) {
                finishCode = Activity.RESULT_CANCELED
                results.putString("stream", "FAIL: hosted SDK cleanup timeout\n")
            }
            participant?.detach()
            if (machineParticipant) runOnMainSync {
                capturedActivity?.window?.clearFlags(android.view.WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
            }
            artifacts.forEach { it.delete() }
        }
        finish(finishCode, results)
    }

    /** Opt-in test runner only: system accessibility enters credentials in the real hosted
     * form. No JavaScript injection, app credential form, or SDK identity/token fixture. */
    private fun fillHostedFieldsIfRequested() {
        val input = File(targetContext.noBackupFilesDir, "test-hosted-fields.json")
        val snapshot = File(targetContext.noBackupFilesDir, "test-hosted-snapshot")
        if (!input.exists() && !snapshot.exists()) return
        var stage = "read"
        try {
            val nodes = mutableListOf<android.view.accessibility.AccessibilityNodeInfo>()
            val rows = org.json.JSONArray()
            fun visit(node: android.view.accessibility.AccessibilityNodeInfo, webContent: Boolean = false) {
                val inWebContent = webContent || node.className?.toString()?.contains("WebView") == true
                if (inWebContent && node.isEditable && node.packageName?.toString() in listOf("io.cyberbus.demo", "com.android.chrome")) nodes.add(node)
                if (node.packageName?.toString() in listOf("io.cyberbus.demo", "com.android.chrome", "android")) {
                    val bounds = android.graphics.Rect().also { node.getBoundsInScreen(it) }
                    rows.put(org.json.JSONObject().put("class", node.className?.toString()).put("text", node.text?.toString())
                        .put("description", node.contentDescription?.toString()).put("editable", node.isEditable)
                        .put("bounds", "[${bounds.left},${bounds.top}][${bounds.right},${bounds.bottom}]"))
                }
                for (i in 0 until node.childCount) node.getChild(i)?.let { visit(it, inWebContent) }
            }
            stage = "accessibility"
            uiAutomation.rootInActiveWindow?.let { visit(it) }
            if (snapshot.delete()) {
                File(targetContext.noBackupFilesDir, "test-hosted-ui.json").apply {
                    writeText(rows.toString()); setReadable(false, false); setReadable(true, true)
                }
            }
            if (!input.exists()) return
            val fields = org.json.JSONArray(input.readText())
            stage = "field-count-${nodes.size}-expected-${fields.length()}"
            check(nodes.size == fields.length())
            stage = "set-text"
            fields.let { for (i in 0 until it.length()) check(nodes[i].performAction(
                android.view.accessibility.AccessibilityNodeInfo.ACTION_SET_TEXT, Bundle().apply {
                    putCharSequence(android.view.accessibility.AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE, it.getString(i))
                })) }
            sendStatus(0, Bundle().apply { putString("stream", "Hosted form filled via system accessibility.\n") })
        } catch (error: Throwable) {
            sendStatus(0, Bundle().apply { putString("stream", "FAIL: hosted form $stage ${error.javaClass.simpleName}\n") })
        } finally { input.delete() }
    }

    private fun awaitUi(timeout: Long = 15_000, condition: () -> Boolean) {
        val deadline = SystemClock.elapsedRealtime() + timeout
        while (SystemClock.elapsedRealtime() < deadline) {
            var ready = false
            runOnMainSync { ready = condition() }
            if (ready) return
            SystemClock.sleep(100)
        }
        error("Timed out")
    }
    /** Focused native-build check: uses the real Activity/session without starting OAuth. */
    private fun checkNativeReopen() {
        val results = Bundle()
        var session: DemoSession? = null
        var stage = "sdk-ready"
        var passed = false
        fun assertClosed(owner: DemoSession) {
            awaitUi { owner.status == "SDK 已关闭" || owner.status.startsWith("CLOSED") }
            runOnMainSync {
                check(owner.status == "SDK 已关闭") // Also requires event EOF and store-lock release.
                val result = cyberbus.easytier.v1.Sdk.SdkResult.parseFrom(checkNotNull(owner.testCloseResult))
                check(!result.hasError() && result.hasSdkClosed() && result.sdkClosed.closed &&
                    !result.sdkClosed.hasCleanupError())
            }
        }
        try {
            val activity = startActivitySync(Intent(targetContext, MainActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)) as MainActivity
            val field = MainActivity::class.java.getDeclaredField("session").apply { isAccessible = true }
            runOnMainSync { session = field.get(activity) as DemoSession }
            val original = session!!
            awaitUi { original.canAuthenticate && original.foregroundReady && original.deviceList.any { it.isLocal } }
            var identity = com.google.protobuf.ByteString.EMPTY
            runOnMainSync {
                identity = original.deviceList.single { it.isLocal }.deviceId
                check(identity.size() == 32 && !original.authenticated && !original.authBusy && !original.running)
            }
            stage = "first-close"
            runOnMainSync { original.close() }
            assertClosed(original)
            stage = "native-reopen"
            runOnMainSync {
                MainActivity::class.java.getDeclaredMethod("recreateSession").apply { isAccessible = true }.invoke(activity)
                session = field.get(activity) as DemoSession
                check(session !== original)
            }
            val reopened = session!!
            awaitUi { reopened.canAuthenticate && reopened.foregroundReady && reopened.deviceList.any { it.isLocal } }
            runOnMainSync {
                check(reopened.deviceList.single { it.isLocal }.deviceId == identity)
                check(!reopened.authenticated && !reopened.authBusy && !reopened.running)
            }
            stage = "second-close"
            runOnMainSync { reopened.close() }
            assertClosed(reopened)
            results.putString("stream", "PASS: native Activity/session create-close-reopen-close; correlated SdkClosed without cleanup error, event EOF/store release; stable identity=${DemoSession.short(identity)}; no auth or network start.\n")
            passed = true
        } catch (error: Throwable) {
            results.putString("stream", "FAIL: native reopen $stage ${error.javaClass.simpleName}\n")
        } finally {
            val settled = CountDownLatch(1)
            runOnMainSync { session?.close { settled.countDown() } ?: settled.countDown() }
            if (!settled.await(8, TimeUnit.SECONDS)) {
                passed = false
                results.putString("stream", "FAIL: native reopen cleanup timeout\n")
            }
        }
        finish(if (passed) Activity.RESULT_OK else Activity.RESULT_CANCELED, results)
    }
    private fun checkAuthBoundary() {
        val results = Bundle()
        var session: DemoSession? = null
        var stage = "platform-error-capture"
        try {
            // WebResourceError has no accessible constructor. Capture a real platform
            // error from an unused loopback port, then replay that queued error object.
            lateinit var observedError: android.webkit.WebResourceError
            lateinit var errorProbe: android.webkit.WebView
            val errorReady = CountDownLatch(1)
            runOnMainSync {
                errorProbe = android.webkit.WebView(targetContext)
                errorProbe.webViewClient = object : android.webkit.WebViewClient() {
                    override fun onReceivedError(view: android.webkit.WebView, request: android.webkit.WebResourceRequest,
                        error: android.webkit.WebResourceError) {
                        if (request.isForMainFrame) { observedError = error; errorReady.countDown() }
                    }
                }
                errorProbe.loadUrl("https://127.0.0.1:1/")
            }
            val capturedError = errorReady.await(15, TimeUnit.SECONDS)
            runOnMainSync { errorProbe.destroy() }
            check(capturedError)
            stage = "sdk-ready"
            var activity = startActivitySync(Intent(targetContext, MainActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)) as MainActivity
            val field = MainActivity::class.java.getDeclaredField("session").apply { isAccessible = true }
            runOnMainSync { session = field.get(activity) as DemoSession }
            val owner = session!!
            awaitUi { owner.canAuthenticate && owner.foregroundReady }
            stage = "local-identity"
            awaitUi { owner.deviceList.any { it.isLocal } }
            var originalIdentity = com.google.protobuf.ByteString.EMPTY
            runOnMainSync { originalIdentity = owner.deviceList.single { it.isLocal }.deviceId }
            val policy = AuthNavigation(android.net.Uri.parse("cyberbus://auth/callback"))
            check(policy.isCallback(android.net.Uri.parse("cyberbus://auth/callback?error=access_denied")))
            listOf("cyberbus://auth/callback/", "cyberbus://auth:99/callback", "cyberbus://user@auth/callback",
                "cyberbus://auth/call%62ack", "cyberbus://other/callback", "cyberbus://auth/callback#fragment",
                "https://auth/callback").forEach { check(!policy.isCallback(android.net.Uri.parse(it))) }
            // Cancel even before AuthStart returns its SDK-owned operation ID.
            stage = "pending-cancel"
            runOnMainSync { owner.login(false); owner.cancelAuth(); owner.cancelAuth() }
            awaitUi { !owner.authBusy && owner.canAuthenticate }
            check(owner.logs.any { it.contains("已取消认证") })
            for (intent in listOf(false, true)) {
                stage = "webview-${if (intent) "register" else "login"}"
                runOnMainSync { owner.login(intent, DemoSession.AuthContainer.WEBVIEW) }
                awaitUi { owner.browserUri != null }
                var authorization = ""
                var page: Any? = null
                var oldClient: android.webkit.WebViewClient? = null
                var oldGeneration = 0L
                var oldOperation = com.google.protobuf.ByteString.EMPTY
                val pageField = MainActivity::class.java.getDeclaredField("authPage").apply { isAccessible = true }
                awaitUi { pageField.get(activity) != null }
                runOnMainSync {
                    authorization = owner.browserUri!!; page = pageField.get(activity)
                    oldClient = (page as HostedAuthPage).webView.webViewClient
                    oldGeneration = owner.presentationGeneration; oldOperation = owner.presentationOperation
                }
                val monitor = addMonitor(MainActivity::class.java.name, null, false)
                runOnMainSync { activity.recreate() }
                activity = waitForMonitorWithTimeout(monitor, 15_000) as MainActivity
                removeMonitor(monitor)
                awaitUi { owner.foregroundReady }
                runOnMainSync {
                    check(field.get(activity) === owner)
                    check(pageField.get(activity) === page)
                    check(owner.browserUri == authorization)
                    owner.callback("cyberbus://auth/callback/extra?error=access_denied")
                    check(owner.authBusy && owner.browserUri == authorization)
                    val web = (page as HostedAuthPage).webView
                    check(!web.settings.allowFileAccess && !web.settings.allowContentAccess)
                    check(web.settings.mixedContentMode == android.webkit.WebSettings.MIXED_CONTENT_NEVER_ALLOW)
                    activity.onBackPressed()
                }
                awaitUi { !owner.authBusy && pageField.get(activity) == null }
                // Deliver callbacks already queued by the destroyed container after a new
                // real SDK operation owns the same session. Use the NEW valid state, so an
                // accidental callback submission cannot hide behind stale-state rejection.
                runOnMainSync { owner.login(intent, DemoSession.AuthContainer.WEBVIEW) }
                awaitUi { owner.browserUri != null && pageField.get(activity) != null }
                runOnMainSync {
                    val currentUri = owner.browserUri!!
                    val currentOperation = owner.presentationOperation
                    check(currentOperation != oldOperation)
                    check(!owner.ownsPresentation(oldGeneration, oldOperation, authorization))
                    check(!owner.ownsPresentation(owner.presentationGeneration, currentOperation, authorization))
                    check(owner.ownsPresentation(owner.presentationGeneration, currentOperation, currentUri))
                    val logs = owner.logs.toList()
                    val staleWeb = (page as HostedAuthPage).webView
                    val client = oldClient!!
                    val callback = android.net.Uri.Builder().scheme("cyberbus").authority("auth").path("/callback")
                        .appendQueryParameter("error", "access_denied")
                        .appendQueryParameter("state", android.net.Uri.parse(currentUri).getQueryParameter("state"))
                        .build()
                    val request = object : android.webkit.WebResourceRequest {
                        override fun getUrl() = callback
                        override fun isForMainFrame() = true
                        override fun isRedirect() = false
                        override fun hasGesture() = false
                        override fun getMethod() = "GET"
                        override fun getRequestHeaders() = emptyMap<String, String>()
                    }
                    client.onReceivedError(staleWeb, request, observedError)
                    client.onReceivedHttpError(staleWeb, request,
                        android.webkit.WebResourceResponse("text/plain", "UTF-8", 503, "Unavailable", emptyMap(), null))
                    client.onPageStarted(staleWeb, "http://invalid.example/late", null)
                    client.onPageFinished(staleWeb, "https://invalid.example/late")
                    check(client.shouldOverrideUrlLoading(staleWeb, request))
                    check(owner.authBusy && owner.browserUri == currentUri && owner.presentationOperation == currentOperation)
                    check(owner.logs.toList() == logs)
                }
                // Let native results/events run before asserting the new owner survived.
                SystemClock.sleep(500)
                runOnMainSync {
                    check(owner.authBusy && owner.browserUri != null && owner.presentationOperation != oldOperation)
                    activity.onBackPressed()
                }
                awaitUi { !owner.authBusy && pageField.get(activity) == null }
            }
            // Shared one-shot path: a provider-shaped denial with genuine SDK state. This is
            // an error-boundary test, never evidence of a successful hosted authorization.
            var request: String? = null
            stage = "provider-denial"
            runOnMainSync { owner.openBrowser = { request = it }; owner.login(false) }
            awaitUi { request != null }
            runOnMainSync {
                val state = android.net.Uri.parse(request).getQueryParameter("state")!!
                val denial = android.net.Uri.Builder().scheme("cyberbus").authority("auth").path("/callback")
                    .appendQueryParameter("error", "access_denied").appendQueryParameter("state", state).build().toString()
                owner.callback(denial); owner.callback(denial)
                check(owner.logs.any { it.contains("回调已提交") })
            }
            awaitUi { !owner.authBusy }
            check(!owner.authenticated && !owner.running)
            runOnMainSync { owner.callback("cyberbus://auth/callback?error=access_denied") }
            check(owner.logs.any { it.contains("没有可匹配") })
            stage = "native-close"
            runOnMainSync { owner.close() }
            awaitUi { owner.status.startsWith("SDK 已关闭") || owner.status.startsWith("CLOSED") }
            stage = "native-reopen"
            runOnMainSync {
                MainActivity::class.java.getDeclaredMethod("recreateSession").apply { isAccessible = true }.invoke(activity)
                session = field.get(activity) as DemoSession
            }
            val reopened = session!!
            awaitUi { reopened.canAuthenticate && reopened.foregroundReady && reopened.deviceList.any { it.isLocal } }
            runOnMainSync {
                check(reopened.deviceList.single { it.isLocal }.deviceId == originalIdentity)
                check(!reopened.authenticated && !reopened.running)
                reopened.close()
            }
            awaitUi { reopened.status.startsWith("SDK 已关闭") || reopened.status.startsWith("CLOSED") }
            results.putString("stream", "PASS: exact callback policy; pending AuthCancel; WebView login/register recreation retains page/operation; back cancels; disposed-page late error/HTTP/navigation/callback leaves newer operation pending; generation/operation/URI ownership; duplicate/late/error callbacks; native close/reopen identity=${DemoSession.short(originalIdentity)}; no automatic network start. No successful OAuth claimed.\n")
            finish(Activity.RESULT_OK, results)
        } catch (error: Throwable) {
            runOnMainSync { session?.close() }
            results.putString("stream", "FAIL: auth boundary $stage ${error.javaClass.simpleName}; status=${session?.status}\n")
            finish(Activity.RESULT_CANCELED, results)
        }
    }
}
