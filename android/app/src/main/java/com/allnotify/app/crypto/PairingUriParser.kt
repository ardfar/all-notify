package com.allnotify.app.crypto

import java.net.URI
import java.net.URLDecoder
import java.net.URLEncoder
import java.util.Base64

data class PairingConfig(
    val version: Int = 1,
    val serverUrl: String,
    val wsUrl: String,
    val token: String,
    val keyBase64Url: String,
    val keyBytes: ByteArray,
    val deviceId: String,
    val deviceName: String
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is PairingConfig) return false
        return version == other.version &&
            serverUrl == other.serverUrl &&
            wsUrl == other.wsUrl &&
            token == other.token &&
            keyBase64Url == other.keyBase64Url &&
            keyBytes.contentEquals(other.keyBytes) &&
            deviceId == other.deviceId &&
            deviceName == other.deviceName
    }

    override fun hashCode(): Int {
        var result = version
        result = 31 * result + serverUrl.hashCode()
        result = 31 * result + wsUrl.hashCode()
        result = 31 * result + token.hashCode()
        result = 31 * result + keyBase64Url.hashCode()
        result = 31 * result + keyBytes.contentHashCode()
        result = 31 * result + deviceId.hashCode()
        result = 31 * result + deviceName.hashCode()
        return result
    }

    // Never leak secrets via toString() in logs or crash reports.
    override fun toString(): String =
        "PairingConfig(v=$version, serverUrl=$serverUrl, deviceId=$deviceId, deviceName=$deviceName)"
}

sealed class PairingLink {
    abstract val version: Int
    abstract val serverUrl: String
    abstract val wsUrl: String
    abstract val keyBase64Url: String
    abstract val keyBytes: ByteArray
    abstract val deviceName: String

    data class V1(val config: PairingConfig) : PairingLink() {
        override val version: Int get() = config.version
        override val serverUrl: String get() = config.serverUrl
        override val wsUrl: String get() = config.wsUrl
        override val keyBase64Url: String get() = config.keyBase64Url
        override val keyBytes: ByteArray get() = config.keyBytes
        override val deviceName: String get() = config.deviceName

        override fun toString(): String = "PairingLink.V1($config)"
    }

    data class V2(
        override val serverUrl: String,
        override val wsUrl: String,
        val code: String,
        override val keyBase64Url: String,
        override val keyBytes: ByteArray,
        override val deviceName: String
    ) : PairingLink() {
        override val version: Int = 2

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is V2) return false
            return serverUrl == other.serverUrl &&
                wsUrl == other.wsUrl &&
                code == other.code &&
                keyBase64Url == other.keyBase64Url &&
                keyBytes.contentEquals(other.keyBytes) &&
                deviceName == other.deviceName
        }

        override fun hashCode(): Int {
            var result = serverUrl.hashCode()
            result = 31 * result + wsUrl.hashCode()
            result = 31 * result + code.hashCode()
            result = 31 * result + keyBase64Url.hashCode()
            result = 31 * result + keyBytes.contentHashCode()
            result = 31 * result + deviceName.hashCode()
            return result
        }

        // Never leak secrets (pairing code or K_master) via toString().
        override fun toString(): String =
            "PairingLink.V2(serverUrl=$serverUrl, deviceName=$deviceName)"
    }
}

object PairingUriParser {
    private val UNPADDED_B64URL = Regex("^[A-Za-z0-9_-]+$")
    private val PAIRING_CODE_REGEX = Regex("^pc_[A-Za-z0-9_-]{22}$")

    fun parseLink(raw: String): Result<PairingLink> = runCatching {
        val trimmed = raw.trim()
        val uri = URI(trimmed)
        require(uri.scheme == "allnotify") { "scheme must be allnotify" }
        require(uri.host == "pair") { "host must be pair" }
        require(uri.userInfo == null) { "pairing uri must not contain userinfo" }
        require(uri.fragment == null) { "pairing uri must not contain fragment" }
        val path = uri.rawPath.orEmpty()
        require(path.isEmpty() || path == "/") { "pairing uri must not include a non-empty path" }

        val query = parseQuery(uri.rawQuery.orEmpty())
        val vStr = query["v"] ?: error("v parameter is required")
        val vInt = vStr.toIntOrNull() ?: error("invalid v parameter")
        require(vInt == 1 || vInt == 2) { "only protocol versions 1 and 2 are supported" }

        val serverUrlRaw = query["url"]?.takeIf { it.isNotEmpty() } ?: error("url parameter is required")
        val serverUri = URI(serverUrlRaw)
        require(serverUri.scheme == "https") { "server url must use https" }
        require(!serverUri.host.isNullOrEmpty()) { "server url must have a host" }
        require(serverUri.rawUserInfo == null) { "server url must not contain userinfo" }
        require(serverUri.rawQuery == null) { "server url must not contain query parameters" }
        require(serverUri.rawFragment == null) { "server url must not contain a fragment" }

        val cleanUrl = serverUri.toASCIIString().trimEnd('/')
        val wsUrl = "wss://" + cleanUrl.removePrefix("https://") + "/v1/ws"

        val deviceName = query["name"]?.takeIf { it.isNotEmpty() } ?: error("name parameter is required")

        val keyB64 = query["key"]?.takeIf { it.isNotEmpty() } ?: error("key parameter is required")
        require(!keyB64.contains('=')) { "key must be unpadded base64url" }
        require(UNPADDED_B64URL.matches(keyB64)) { "key must use base64url alphabet (- and _)" }
        val keyBytes = Base64.getUrlDecoder().decode(keyB64)
        require(keyBytes.size == 32) { "decoded key must be exactly 32 bytes" }
        val canonical = Base64.getUrlEncoder().withoutPadding().encodeToString(keyBytes)
        require(canonical == keyB64) { "key is not canonical unpadded base64url" }

        if (vInt == 1) {
            val token = query["token"]?.takeIf { it.isNotEmpty() } ?: error("token parameter is required")
            val deviceId = query["device_id"]?.takeIf { it.isNotEmpty() } ?: error("device_id parameter is required")
            PairingLink.V1(
                PairingConfig(
                    version = 1,
                    serverUrl = cleanUrl,
                    wsUrl = wsUrl,
                    token = token,
                    keyBase64Url = keyB64,
                    keyBytes = keyBytes,
                    deviceId = deviceId,
                    deviceName = deviceName
                )
            )
        } else {
            require(!query.containsKey("token")) { "v2 pairing uri must not contain token" }
            require(!query.containsKey("device_id")) { "v2 pairing uri must not contain device_id" }
            val code = query["code"]?.takeIf { it.isNotEmpty() } ?: error("code parameter is required")
            require(PAIRING_CODE_REGEX.matches(code)) { "invalid pairing code format" }
            PairingLink.V2(
                serverUrl = cleanUrl,
                wsUrl = wsUrl,
                code = code,
                keyBase64Url = keyB64,
                keyBytes = keyBytes,
                deviceName = deviceName
            )
        }
    }

    /** Convenience parser for v1 links returning a ready-to-connect PairingConfig. */
    fun parse(raw: String): Result<PairingConfig> = parseLink(raw).mapCatching { link ->
        when (link) {
            is PairingLink.V1 -> link.config
            is PairingLink.V2 -> error("v2 pairing link must be claimed via POST /v1/pair/claim")
        }
    }

    fun encode(config: PairingConfig): String {
        fun enc(s: String) = URLEncoder.encode(s, "UTF-8").replace("+", "%20")
        return "allnotify://pair?v=1" +
            "&url=${enc(config.serverUrl)}" +
            "&token=${enc(config.token)}" +
            "&key=${enc(config.keyBase64Url)}" +
            "&device_id=${enc(config.deviceId)}" +
            "&name=${enc(config.deviceName)}"
    }

    fun encodeV2(serverUrl: String, code: String, keyBase64Url: String, deviceName: String): String {
        fun enc(s: String) = URLEncoder.encode(s, "UTF-8").replace("+", "%20")
        return "allnotify://pair?v=2" +
            "&url=${enc(serverUrl.trimEnd('/'))}" +
            "&code=${enc(code)}" +
            "&key=${enc(keyBase64Url)}" +
            "&name=${enc(deviceName)}"
    }

    private fun parseQuery(rawQuery: String): Map<String, String> {
        if (rawQuery.isEmpty()) return emptyMap()
        val result = LinkedHashMap<String, String>()
        for (pair in rawQuery.split('&')) {
            if (pair.isEmpty()) continue
            val idx = pair.indexOf('=')
            val rawKey = if (idx >= 0) pair.substring(0, idx) else pair
            val rawVal = if (idx >= 0) pair.substring(idx + 1) else ""
            val key = URLDecoder.decode(rawKey, "UTF-8")
            val value = URLDecoder.decode(rawVal, "UTF-8")
            result.putIfAbsent(key, value)
        }
        return result
    }
}
