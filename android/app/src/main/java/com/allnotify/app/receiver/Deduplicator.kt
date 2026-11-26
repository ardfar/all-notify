package com.allnotify.app.receiver

import com.allnotify.app.net.BlobApiClient
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

object Deduplicator {
    const val DEDUP_WINDOW_MS = 5_000L

    private val listJson = Json { ignoreUnknownKeys = true }

    fun normalize(text: String): String =
        text.replace("\r\n", "\n").trim()

    fun fingerprint(packageName: String, title: String, body: String): String {
        val raw = "$packageName\u0000${normalize(title)}\u0000${normalize(body)}"
        return BlobApiClient.sha256Hex(raw.toByteArray(Charsets.UTF_8))
    }

    fun decodeStringList(json: String): List<String> =
        runCatching { listJson.decodeFromString<List<String>>(json) }.getOrDefault(emptyList())

    fun encodeStringList(items: List<String>): String =
        listJson.encodeToString(items)

    fun jsonQuoted(value: String): String =
        listJson.encodeToString(value)
}
