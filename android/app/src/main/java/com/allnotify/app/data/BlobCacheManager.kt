package com.allnotify.app.data

import java.io.File
import java.util.concurrent.ConcurrentHashMap

/**
 * Local disk cache for decrypted 64x64 WebP app icons (LRU 200) and decrypted image attachments.
 * Validates all IDs strictly to prevent path traversal.
 */
class BlobCacheManager(
    cacheRoot: File,
    private val maxIcons: Int = MAX_ICONS,
    private val nowMs: () -> Long = { System.currentTimeMillis() }
) {
    val iconsDir = File(cacheRoot, "icons").apply { mkdirs() }
    val attachmentsDir = File(cacheRoot, "attachments").apply { mkdirs() }
    private val uploadedIconsFile = File(cacheRoot, "uploaded_icons.tsv")

    private val iconLock = Any()
    private val uploadedLock = Any()

    // Map sha256 -> last verified upload timestamp (ms) on VPS (re-verify after 12h due to 24h VPS TTL)
    private val uploadedIconTimestamps = ConcurrentHashMap<String, Long>()

    init {
        loadUploadedIcons()
    }

    fun getIconFile(sha256: String): File? {
        if (!SHA256_REGEX.matches(sha256)) return null
        synchronized(iconLock) {
            val file = File(iconsDir, "$sha256.webp")
            if (!file.exists()) return null
            file.setLastModified(nowMs())
            return file
        }
    }

    fun putIcon(sha256: String, webpBytes: ByteArray): File {
        require(SHA256_REGEX.matches(sha256)) { "invalid icon sha256" }
        synchronized(iconLock) {
            iconsDir.mkdirs()
            val target = File(iconsDir, "$sha256.webp")
            writeAtomic(iconsDir, "$sha256.", target, webpBytes)
            target.setLastModified(nowMs())
            evictIconsIfNeeded()
            return target
        }
    }

    fun getAttachmentFile(blobId: String): File? {
        if (!BLOB_ID_REGEX.matches(blobId)) return null
        val file = File(attachmentsDir, "$blobId.webp")
        return if (file.exists()) file else null
    }

    fun putAttachment(blobId: String, bytes: ByteArray): File {
        require(BLOB_ID_REGEX.matches(blobId)) { "invalid blob_id" }
        attachmentsDir.mkdirs()
        val target = File(attachmentsDir, "$blobId.webp")
        writeAtomic(attachmentsDir, "$blobId.", target, bytes)
        return target
    }

    fun isIconRecentlyUploaded(sha256: String): Boolean {
        val ts = uploadedIconTimestamps[sha256] ?: return false
        return (nowMs() - ts) < ICON_REVERIFY_MS
    }

    fun markIconUploaded(sha256: String) {
        if (!SHA256_REGEX.matches(sha256)) return
        uploadedIconTimestamps[sha256] = nowMs()
        persistUploadedIcons()
    }

    fun clearUploadedIconCache() {
        synchronized(uploadedLock) {
            uploadedIconTimestamps.clear()
            uploadedIconsFile.delete()
        }
    }

    fun pruneOrphanAttachments(referencedPaths: Set<String>): Int {
        val files = attachmentsDir.listFiles() ?: return 0
        var deleted = 0
        for (f in files) {
            if (f.isFile && !f.name.endsWith(".tmp") && f.absolutePath !in referencedPaths) {
                if (f.delete()) deleted++
            }
        }
        return deleted
    }

    fun clearAttachments() {
        attachmentsDir.listFiles()?.forEach { it.delete() }
    }

    private fun writeAtomic(dir: File, prefix: String, target: File, bytes: ByteArray) {
        val tmp = File.createTempFile(prefix, ".tmp", dir)
        try {
            tmp.writeBytes(bytes)
            if (!tmp.renameTo(target)) {
                target.writeBytes(bytes)
            }
        } finally {
            if (tmp.exists()) {
                tmp.delete()
            }
        }
    }

    private fun evictIconsIfNeeded() {
        val files = iconsDir.listFiles { f -> f.isFile && f.name.endsWith(".webp") } ?: return
        if (files.size <= maxIcons) return
        files.sortBy { it.lastModified() }
        val toRemove = files.size - maxIcons
        for (i in 0 until toRemove) {
            files[i].delete()
        }
    }

    private fun loadUploadedIcons() {
        synchronized(uploadedLock) {
            if (!uploadedIconsFile.exists()) return
            runCatching {
                val cutoff = nowMs() - ICON_REVERIFY_MS
                uploadedIconsFile.readLines().forEach { line ->
                    val parts = line.split('\t')
                    if (parts.size == 2) {
                        val hash = parts[0]
                        val ts = parts[1].toLongOrNull() ?: return@forEach
                        if (SHA256_REGEX.matches(hash) && ts >= cutoff) {
                            uploadedIconTimestamps[hash] = ts
                        }
                    }
                }
            }
        }
    }

    private fun persistUploadedIcons() {
        synchronized(uploadedLock) {
            runCatching {
                val parent = uploadedIconsFile.parentFile ?: return
                parent.mkdirs()
                val text = uploadedIconTimestamps.entries.joinToString("\n") { "${it.key}\t${it.value}" }
                writeAtomic(parent, "uploaded_icons.", uploadedIconsFile, text.toByteArray(Charsets.UTF_8))
            }
        }
    }

    companion object {
        const val MAX_ICONS = 200
        const val ICON_REVERIFY_MS = 12L * 60 * 60 * 1000
        val SHA256_REGEX = Regex("^[0-9a-f]{64}$")
        val BLOB_ID_REGEX = Regex("^[a-zA-Z0-9_-]{8,64}$")
    }
}
