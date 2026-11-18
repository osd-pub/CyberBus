package io.cyberbus.demo

import android.annotation.SuppressLint
import android.content.Context
import android.graphics.Color
import android.net.http.SslError
import android.webkit.*
import android.widget.*

/** Retained with the SDK session using application context; never serializes web history. */
@SuppressLint("SetJavaScriptEnabled", "ViewConstructor")
class HostedAuthPage(context: Context, private val session: DemoSession, private val uri: String) : LinearLayout(context) {
    private val generation = session.presentationGeneration
    private val operation = session.presentationOperation
    private var disposed = false
    private fun active() = !disposed && session.ownsPresentation(generation, operation, uri)
    val webView = WebView(context)
    private val source = TextView(context)
    init {
        orientation = VERTICAL
        setBackgroundColor(Color.WHITE)
        source.setTextColor(Color.BLACK)
        source.textSize = 16f
        addView(source)
        addView(Button(context).apply {
            text = "关闭认证"; setOnClickListener { if (active()) session.cancelAuth() }
        })
        addView(webView, LayoutParams(-1, 0, 1f))
        webView.isSaveEnabled = false
        webView.settings.apply {
            javaScriptEnabled = true // Required by the hosted Logto UI; no JavaScript bridge.
            domStorageEnabled = true
            allowFileAccess = false
            allowContentAccess = false
            @Suppress("DEPRECATION")
            allowFileAccessFromFileURLs = false
            @Suppress("DEPRECATION")
            allowUniversalAccessFromFileURLs = false
            mixedContentMode = WebSettings.MIXED_CONTENT_NEVER_ALLOW
            setSupportMultipleWindows(false)
            javaScriptCanOpenWindowsAutomatically = false
            cacheMode = WebSettings.LOAD_NO_CACHE
            saveFormData = false
        }
        CookieManager.getInstance().setAcceptThirdPartyCookies(webView, false)
        webView.webViewClient = object : WebViewClient() {
            override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean {
                if (!active()) return true
                if (request.isForMainFrame && session.authNavigation?.isCallback(request.url) == true) {
                    session.callback(request.url.toString()); return true
                }
                if (!AuthNavigation.isHttps(request.url)) {
                    if (request.isForMainFrame) session.presentationFailed("INVALID_ARGUMENT · 托管页面导航被拒绝")
                    return true
                }
                return false
            }
            override fun onPageStarted(view: WebView, url: String, favicon: android.graphics.Bitmap?) {
                if (!active()) return
                val parsed = android.net.Uri.parse(url)
                if (!AuthNavigation.isHttps(parsed)) {
                    view.stopLoading(); session.presentationFailed("INVALID_ARGUMENT · 非 HTTPS 托管页面"); return
                }
                source.text = "托管认证 · ${AuthNavigation.origin(parsed)}\n加载中…"
            }
            override fun onPageFinished(view: WebView, url: String) {
                if (!active()) return
                val parsed = android.net.Uri.parse(url)
                if (AuthNavigation.isHttps(parsed)) source.text = "托管认证 · ${AuthNavigation.origin(parsed)}"
            }
            override fun onReceivedSslError(view: WebView, handler: SslErrorHandler, error: SslError) {
                handler.cancel()
                if (active()) session.presentationFailed("UNAVAILABLE · 托管站点证书验证失败")
            }
            override fun onReceivedError(view: WebView, request: WebResourceRequest, error: WebResourceError) {
                if (active() && request.isForMainFrame) session.presentationFailed("UNAVAILABLE · 托管页面加载失败")
            }
            override fun onReceivedHttpError(view: WebView, request: WebResourceRequest, response: WebResourceResponse) {
                if (active() && request.isForMainFrame) session.presentationFailed("UNAVAILABLE · 托管站点 HTTP 错误")
            }
        }
        webView.loadUrl(uri)
    }
    fun dispose() {
        if (disposed) return
        disposed = true // stopLoading itself may synchronously deliver an old error callback.
        webView.stopLoading()
        webView.webViewClient = WebViewClient()
        removeView(webView)
        webView.destroy()
    }
}
