package io.cyberbus.demo

import android.app.Service
import android.content.Intent
import android.os.Binder
import android.os.IBinder
import android.os.ResultReceiver

/** Debug-only second process. Can open only a disposable instrumentation namespace. */
class StoreLockProbeService : Service() {
    override fun onBind(intent: Intent): IBinder {
        val scope = intent.getStringExtra("scope") ?: return Binder()
        @Suppress("DEPRECATION")
        val receiver = intent.getParcelableExtra<ResultReceiver>("result") ?: return Binder()
        val acquired = try { ProtectedStore.forTest(this, scope).use { true } } catch (_: Exception) { false }
        receiver.send(if (acquired) 1 else 0, null)
        return Binder()
    }
}
