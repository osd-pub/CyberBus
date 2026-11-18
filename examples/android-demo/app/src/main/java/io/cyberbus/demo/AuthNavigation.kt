package io.cyberbus.demo

import android.net.Uri

/** Container policy only. State/nonce/PKCE and OAuth errors are checked by Rust. */
class AuthNavigation(private val redirect: Uri) {
    fun isCallback(uri: Uri): Boolean = uri.isHierarchical &&
        uri.scheme == redirect.scheme && uri.encodedAuthority == redirect.encodedAuthority &&
        uri.encodedPath == redirect.encodedPath && uri.userInfo == null && uri.fragment == null

    companion object {
        fun isHttps(uri: Uri) = uri.isHierarchical && uri.scheme == "https" &&
            !uri.host.isNullOrBlank() && uri.userInfo == null
        fun origin(uri: Uri): String = "https://${uri.host}${if (uri.port == -1 || uri.port == 443) "" else ":${uri.port}"}"
    }
}
