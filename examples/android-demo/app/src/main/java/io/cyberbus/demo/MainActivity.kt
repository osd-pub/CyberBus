package io.cyberbus.demo

import android.app.Activity
import android.content.Intent
import android.graphics.Color
import android.net.Uri
import android.os.Bundle
import android.text.InputFilter
import android.view.View
import android.view.ViewGroup
import android.widget.*
import cyberbus.easytier.v1.Common.DevicePresence

class MainActivity : Activity() {
    private lateinit var session: DemoSession
    private data class Retained(val session: DemoSession, val page: HostedAuthPage?, val container: DemoSession.AuthContainer)
    private lateinit var root: FrameLayout
    private lateinit var sample: ScrollView
    private lateinit var browserChoice: RadioButton
    private lateinit var webViewChoice: RadioButton
    private var authPage: HostedAuthPage? = null
    private var selectedContainer = DemoSession.AuthContainer.BROWSER
    private lateinit var status: TextView
    private lateinit var network: TextView
    private lateinit var authDetail: TextView
    private lateinit var clients: LinearLayout
    private lateinit var blocked: LinearLayout
    private lateinit var logs: TextView
    private lateinit var target: TextView
    private lateinit var name: EditText
    private lateinit var message: EditText
    private lateinit var login: Button
    private lateinit var register: Button
    private lateinit var cancel: Button
    private lateinit var restore: Button
    private lateinit var logout: Button
    private lateinit var save: Button
    private lateinit var start: Button
    private lateinit var stop: Button
    private lateinit var refresh: Button
    private lateinit var send: Button
    private lateinit var close: Button
    private lateinit var reopen: Button
    private var resumed = false
    private var closing = false
    private var deviceSignature = ""
    private val preferences by lazy { getSharedPreferences("sample-ui", MODE_PRIVATE) }
    private fun dp(value: Int) = (resources.displayMetrics.density * value).toInt()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val retained = lastNonConfigurationInstance as? Retained
        session = retained?.session ?: DemoSession(applicationContext)
        authPage = retained?.page
        selectedContainer = retained?.container ?: DemoSession.AuthContainer.BROWSER
        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL; setPadding(dp(16), dp(18), dp(16), dp(24))
            setBackgroundColor(Color.rgb(246, 245, 240))
        }
        sample = ScrollView(this).apply { isFillViewport = true; addView(content) }
        root = FrameLayout(this).apply { addView(sample) }
        setContentView(root)
        fun label(text: String, size: Float = 14f) = TextView(this).apply {
            this.text = text; textSize = size; setTextColor(Color.rgb(26, 48, 43)); setPadding(0, dp(5), 0, dp(5)); content.addView(this)
        }
        fun section(text: String) { label(text, 20f).setPadding(0, dp(20), 0, dp(6)) }
        fun row(): LinearLayout = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; content.addView(this) }
        fun button(row: LinearLayout, text: String, action: () -> Unit): Button = Button(this).apply {
            this.text = text; isAllCaps = false; textSize = 13f; minimumWidth = 0; minWidth = 0
            row.addView(this, LinearLayout.LayoutParams(0, dp(48), 1f)); setOnClickListener { action() }
        }
        label("CYBERBUS / ANDROID SAMPLE", 12f)
        label("设备间的消息实验室", 25f)
        status = label("创建 SDK…", 16f)
        network = label("网络默认关闭")
        authDetail = label("")
        label("开发模式 · 本地状态为 app 私有文件，未加密；登录授权仅内存。", 12f)
        label("授权方式")
        RadioGroup(this).apply {
            orientation = RadioGroup.HORIZONTAL
            browserChoice = RadioButton(this@MainActivity).apply { id = View.generateViewId(); text = "系统浏览器" }
            webViewChoice = RadioButton(this@MainActivity).apply { id = View.generateViewId(); text = "WebView" }
            addView(browserChoice); addView(webViewChoice); content.addView(this)
            check(if (selectedContainer == DemoSession.AuthContainer.BROWSER) browserChoice.id else webViewChoice.id)
            setOnCheckedChangeListener { _, checked -> selectedContainer = if (checked == webViewChoice.id)
                DemoSession.AuthContainer.WEBVIEW else DemoSession.AuthContainer.BROWSER }
        }
        row().let { login = button(it, "登录") { session.login(false, selectedContainer) }; register = button(it, "注册") { session.login(true, selectedContainer) }; logout = button(it, "退出") { session.logout() } }
        row().let { cancel = button(it, "取消认证") { session.cancelAuth() }; restore = button(it, "恢复授权") { session.restore() } }
        section("本机声明")
        name = EditText(this).apply {
            hint = "本机名称"; setSingleLine(); filters = arrayOf(InputFilter.LengthFilter(64))
            setTextColor(Color.rgb(26, 48, 43)); setHintTextColor(Color.DKGRAY)
            setText(preferences.getString("local-name", "Android")); content.addView(this)
        }
        row().let {
            save = button(it, "保存声明") {
                preferences.edit().putString("local-name", name.text.toString()).apply()
                session.saveName(name.text.toString())
            }
            start = button(it, "启动") { session.start() }
            stop = button(it, "停止") { session.stop() }
            refresh = button(it, "刷新") { session.refresh() }
        }
        section("客户端")
        clients = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; content.addView(this) }
        blocked = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; content.addView(this) }
        section("发送消息")
        target = label("目标：请选择在线远端")
        message = EditText(this).apply {
            hint = "输入消息（EchoRequest Protobuf）"; minLines = 2; maxLines = 5
            setTextColor(Color.rgb(26, 48, 43)); setHintTextColor(Color.DKGRAY)
            filters = arrayOf(InputFilter.LengthFilter(4096)); content.addView(this)
        }
        row().let { send = button(it, "发送 · 请求 PROCESSED ACK") { session.send(message.text.toString()) } }
        label("SDK 接纳与 RECEIVED / ACCEPTED / PROCESSED 分别显示。", 12f)
        section("接收与操作日志")
        logs = label("").apply { typeface = android.graphics.Typeface.MONOSPACE; textSize = 12f; setTextIsSelectable(true) }
        row().let { close = button(it, "关闭 SDK") {
            closing = true; render(); session.close { closing = false; render() }
        }; reopen = button(it, "重新创建") { recreateSession() } }
        attach()
        consumeCallback(intent)
    }
    private fun attach() {
        session.changed = { if (!isDestroyed) render() }
        session.openBrowser = { url -> if (resumed) {
            if (session.authContainer == DemoSession.AuthContainer.WEBVIEW) showHostedPage(url) else launchBrowser(url)
        } }
        render()
    }
    private fun launchBrowser(url: String) {
        try {
            val uri = Uri.parse(url)
            if (!AuthNavigation.isHttps(uri)) {
                session.browserFailed(); return
            }
            // ACTION_VIEW leaves auth entirely in the user's external browser.
            startActivity(Intent(Intent.ACTION_VIEW, uri).addCategory(Intent.CATEGORY_BROWSABLE))
            session.browserOpened()
        } catch (_: Exception) { session.browserFailed() }
    }
    private fun consumeCallback(incoming: Intent?) {
        val uri = incoming?.data ?: return
        incoming.data = null // Do not retain authorization codes in the Activity's current Intent.
        session.callback(uri.toString())
    }
    override fun onNewIntent(intent: Intent) { super.onNewIntent(intent); setIntent(intent); consumeCallback(intent) }
    override fun onResume() { super.onResume(); resumed = true; session.resume(); session.openPendingBrowser() }
    override fun onPause() { resumed = false; session.background(); super.onPause() }
    override fun onRetainNonConfigurationInstance(): Any = Retained(session, authPage, selectedContainer)
    override fun onDestroy() {
        session.changed = null; session.openBrowser = null
        (authPage?.parent as? ViewGroup)?.removeView(authPage)
        if (!isChangingConfigurations) { authPage?.dispose(); authPage = null }
        if (!isChangingConfigurations) session.close()
        super.onDestroy()
    }
    override fun onSaveInstanceState(outState: Bundle) {
        // Do not serialize SDK handles, auth operations, authorization URLs, or callbacks.
        super.onSaveInstanceState(outState)
    }
    @Deprecated("Uses Activity back for API 28 sample")
    override fun onBackPressed() {
        if (authPage != null) session.cancelAuth() else super.onBackPressed()
    }
    private fun showHostedPage(url: String) {
        if (!AuthNavigation.isHttps(Uri.parse(url))) { session.browserFailed(); return }
        val page = authPage ?: HostedAuthPage(applicationContext, session, url).also { authPage = it }
        if (page.parent !== root) {
            (page.parent as? ViewGroup)?.removeView(page)
            root.addView(page, FrameLayout.LayoutParams(-1, -1))
        }
        sample.visibility = View.GONE
    }
    private fun dismissHostedPage() {
        authPage?.let { (it.parent as? ViewGroup)?.removeView(it); it.dispose() }
        authPage = null
        sample.visibility = View.VISIBLE
    }
    private fun recreateSession() {
        if (closing) return
        closing = true; render()
        val old = session
        dismissHostedPage()
        old.close {
            old.changed = null; old.openBrowser = null
            session = DemoSession(applicationContext); deviceSignature = ""; closing = false; attach()
            if (resumed) session.resume()
        }
    }
    private fun render() {
        status.text = session.status
        network.text = "网络：${if (session.running) "运行中" else "已停止"} · ${if (session.reachable) "可达" else "未确认可达"}"
        authDetail.text = buildString {
            if (session.authBusy) append("等待${if (session.authContainer == DemoSession.AuthContainer.WEBVIEW) "WebView" else "系统浏览器"}认证，可取消后重试。\n")
            if (session.auth.interactionRecommended) append("建议重新交互登录。\n")
            if (session.auth.refreshGrantFrozen) append("刷新结果未知，授权已冻结。\n")
            if (session.auth.securityStatePersistencePending) append("本地状态待保存，网络保持关闭。\n")
            if (session.authenticated && !session.auth.refreshSupported) append("当前核心不支持后台真实刷新，租约结束前需重新登录。")
        }
        login.isEnabled = session.canAuthenticate && !closing
        register.isEnabled = login.isEnabled
        browserChoice.isEnabled = login.isEnabled
        webViewChoice.isEnabled = login.isEnabled
        restore.isEnabled = login.isEnabled
        cancel.isEnabled = session.available && session.authBusy && !closing
        logout.isEnabled = session.available && !session.busy && !session.authBusy && !closing
        save.isEnabled = session.available && !session.busy && !closing
        start.isEnabled = session.canStart && !closing
        stop.isEnabled = session.available && !session.busy && !closing
        refresh.isEnabled = session.available && !session.busy && !session.refreshing && !closing
        refresh.text = if (session.refreshing) "刷新中…" else "刷新"
        send.isEnabled = session.canSend && !closing
        close.isEnabled = session.available && !closing
        reopen.isEnabled = !closing && !session.available
        target.text = session.selected?.let { "目标：${DemoSession.short(it)}" } ?: "目标：请选择在线远端"
        logs.text = session.logs.joinToString("\n")
        if (!session.authBusy || session.browserUri == null) dismissHostedPage()
        else if (authPage != null && session.authContainer == DemoSession.AuthContainer.WEBVIEW && resumed) showHostedPage(session.browserUri!!)
        val signature = "${session.deviceList.hashCode()}/${session.blocks.hashCode()}/${session.selected}/${session.busy}/${session.available}"
        if (signature == deviceSignature) return
        deviceSignature = signature
        clients.removeAllViews(); blocked.removeAllViews()
        if (session.deviceList.isEmpty()) clients.addView(TextView(this).apply { text = "等待 SDK 本机快照；尚未发现远端。" })
        session.deviceList.forEach { device ->
            val row = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; setPadding(0, dp(4), 0, dp(4)) }
            val title = if (device.hasProfile()) device.profile.deviceName.ifBlank { "未命名" } else "未声明"
            val description = "$title${if (device.isLocal) " · 本机" else ""} · ${device.presence.name}\n${DemoSession.short(device.deviceId)}"
            val choice = RadioButton(this).apply {
                text = description; textSize = 13f; isChecked = session.selected == device.deviceId
                isEnabled = !device.isLocal && device.presence == DevicePresence.ONLINE
                setOnClickListener { session.select(device.deviceId) }
            }
            row.addView(choice, LinearLayout.LayoutParams(0, -2, 1f))
            if (!device.isLocal) row.addView(Button(this).apply {
                text = "屏蔽"; isAllCaps = false; isEnabled = !session.busy && session.available
                setOnClickListener { session.block(device.deviceId, true) }
            })
            clients.addView(row)
        }
        if (session.deviceList.isNotEmpty() && session.deviceList.none { !it.isLocal }) {
            clients.addView(TextView(this).apply { text = "尚未连接或发现远端。登录、保存声明并点击启动后刷新。"; textSize = 12f })
        }
        session.blocks.values.filter { it.blocked || it.persistencePending }.forEach { state ->
            blocked.addView(Button(this).apply {
                text = "解除屏蔽 ${DemoSession.short(state.deviceId)}${if (state.persistencePending) " · 待保存" else ""}"
                isAllCaps = false; isEnabled = session.available && !session.busy
                setOnClickListener { session.block(state.deviceId, false) }
            })
        }
    }
}
