package com.allnotify.app.net

import com.allnotify.app.crypto.CryptoEngine
import com.allnotify.app.crypto.PairingConfig
import com.allnotify.app.data.BlobCacheManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.IOException
import java.security.MessageDigest

class BlobApiClient(private val httpClient: OkHttpClient) {

    suspend fun headBlob(serverUrl: String, token: String, blobId: String): Boolean =
        withContext(Dispatchers.IO) {
            require(BlobCacheManager.BLOB_ID_REGEX.matches(blobId)) { "invalid blob_id" }
            val req = Request.Builder()
                .url("${serverUrl.trimEnd('/')}/v1/blobs/$blobId")
                .header("Authorization", "Bearer $token")
                .head()
                .build()
            httpClient.newCall(req).execute().use { resp ->
                when (resp.code) {
                    200 -> true
                    404 -> false
                    else -> throw IOException("HEAD blob failed: HTTP ${resp.code}")
                }
            }
        }

    suspend fun putEncryptedBlob(
        serverUrl: String,
        token: String,
        blobId: String,
        encryptedBytes: ByteArray
    ): Boolean = withContext(Dispatchers.IO) {
        require(BlobCacheManager.BLOB_ID_REGEX.matches(blobId)) { "invalid blob_id" }
        if (encryptedBytes.isEmpty() || encryptedBytes.size > MAX_ENCRYPTED_BLOB_BYTES) {
            return@withContext false
        }
        val req = Request.Builder()
            .url("${serverUrl.trimEnd('/')}/v1/blobs/$blobId")
            .header("Authorization", "Bearer $token")
            .put(encryptedBytes.toRequestBody(OCTET_STREAM))
            .build()
        httpClient.newCall(req).execute().use { resp ->
            resp.isSuccessful
        }
    }

    suspend fun getEncryptedBlob(serverUrl: String, token: String, blobId: String): ByteArray? =
        withContext(Dispatchers.IO) {
            require(BlobCacheManager.BLOB_ID_REGEX.matches(blobId)) { "invalid blob_id" }
            val req = Request.Builder()
                .url("${serverUrl.trimEnd('/')}/v1/blobs/$blobId")
                .header("Authorization", "Bearer $token")
                .get()
                .build()
            httpClient.newCall(req).execute().use { resp ->
                if (resp.code == 404) return@withContext null
                if (!resp.isSuccessful) throw IOException("GET blob failed: HTTP ${resp.code}")
                val body = resp.body ?: return@withContext null
                val stream = body.byteStream()
                val out = ByteArrayOutputStream()
                val buf = ByteArray(8192)
                var total = 0
                while (true) {
                    val n = stream.read(buf)
                    if (n < 0) break
                    total += n
                    if (total > MAX_ENCRYPTED_BLOB_BYTES) {
                        throw IOException("blob exceeds max encrypted limit")
                    }
                    out.write(buf, 0, n)
                }
                out.toByteArray()
            }
        }

    /**
     * Ensures an app icon exists encrypted on the VPS.
     * Skips network I/O when recently verified, otherwise HEADs before encrypting & PUTting.
     */
    suspend fun ensureIconUploaded(
        config: PairingConfig,
        crypto: CryptoEngine,
        blobCache: BlobCacheManager,
        sha256: String,
        webpBytes: ByteArray
    ): String? {
        if (!BlobCacheManager.SHA256_REGEX.matches(sha256)) return null
        val blobId = "icon_${sha256.take(16)}"
        if (blobCache.isIconRecentlyUploaded(sha256)) {
            return blobId
        }
        return runCatching {
            val exists = headBlob(config.serverUrl, config.token, blobId)
            if (exists) {
                blobCache.markIconUploaded(sha256)
                blobId
            } else {
                val encrypted = crypto.encryptBlob(blobId, webpBytes)
                if (putEncryptedBlob(config.serverUrl, config.token, blobId, encrypted)) {
                    blobCache.markIconUploaded(sha256)
                    blobId
                } else {
                    null
                }
            }
        }.getOrNull()
    }

    suspend fun uploadImageAttachment(
        config: PairingConfig,
        crypto: CryptoEngine,
        blobId: String,
        imageBytes: ByteArray
    ): Boolean = runCatching {
        val encrypted = crypto.encryptBlob(blobId, imageBytes)
        putEncryptedBlob(config.serverUrl, config.token, blobId, encrypted)
    }.getOrDefault(false)

    suspend fun downloadAndCacheIcon(
        config: PairingConfig,
        crypto: CryptoEngine,
        blobCache: BlobCacheManager,
        sha256: String,
        blobId: String
    ): File? {
        if (!BlobCacheManager.SHA256_REGEX.matches(sha256)) return null
        if (!BlobCacheManager.BLOB_ID_REGEX.matches(blobId)) return null
        blobCache.getIconFile(sha256)?.let { return it }

        return runCatching {
            val ct = getEncryptedBlob(config.serverUrl, config.token, blobId) ?: return@runCatching null
            val pt = crypto.decryptBlob(blobId, ct)
            if (sha256Hex(pt) != sha256) return@runCatching null
            blobCache.putIcon(sha256, pt)
        }.getOrNull()
    }

    suspend fun downloadAndCacheAttachment(
        config: PairingConfig,
        crypto: CryptoEngine,
        blobCache: BlobCacheManager,
        blobId: String,
        expectedSha256: String
    ): File? {
        if (!BlobCacheManager.BLOB_ID_REGEX.matches(blobId)) return null
        if (!BlobCacheManager.SHA256_REGEX.matches(expectedSha256)) return null
        blobCache.getAttachmentFile(blobId)?.let { return it }

        return runCatching {
            val ct = getEncryptedBlob(config.serverUrl, config.token, blobId) ?: return@runCatching null
            val pt = crypto.decryptBlob(blobId, ct)
            if (sha256Hex(pt) != expectedSha256) return@runCatching null
            blobCache.putAttachment(blobId, pt)
        }.getOrNull()
    }

    companion object {
        const val MAX_ENCRYPTED_BLOB_BYTES = 563_200 // 550 KB
        private val OCTET_STREAM = "application/octet-stream".toMediaType()

        fun sha256Hex(bytes: ByteArray): String {
            val digest = MessageDigest.getInstance("SHA-256").digest(bytes)
            val sb = StringBuilder(64)
            for (b in digest) {
                val v = b.toInt() and 0xff
                sb.append("0123456789abcdef"[v ushr 4])
                sb.append("0123456789abcdef"[v and 0x0f])
            }
            return sb.toString()
        }
    }
}
