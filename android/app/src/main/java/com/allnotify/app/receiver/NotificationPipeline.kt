package com.allnotify.app.receiver

import com.allnotify.app.crypto.CryptoEngine
import com.allnotify.app.crypto.PairingConfig
import com.allnotify.app.data.AllNotifyDatabase
import com.allnotify.app.data.BlobCacheManager
import com.allnotify.app.data.NotificationEntity
import com.allnotify.app.net.RelayFrameHandler
import com.allnotify.app.protocol.EventFrame
import com.allnotify.app.protocol.InnerPayload
import com.allnotify.app.protocol.NotificationDismissedPayload
import com.allnotify.app.protocol.NotificationPostedPayload
import com.allnotify.app.protocol.ReplayCompleteFrame
import com.allnotify.app.protocol.parseInnerPayload
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.io.File

interface MirroredDisplayPort {
    fun showNotification(
        entity: NotificationEntity,
        iconFile: File?,
        attachmentFile: File?,
        silentUpdate: Boolean
    )

    fun showReplaySummary(activeEntities: List<NotificationEntity>)
    fun cancelMirrored(notificationRowId: Long)
    fun isOsDndBlocking(): Boolean
}

interface RemoteCancelPort {
    fun cancelLocalBySbnKey(sbnKey: String)
}

interface BlobFetcher {
    suspend fun fetchIcon(sha256: String, blobId: String): File?
    suspend fun fetchAttachment(blobId: String, sha256: String): File?
}

/**
 * Receiver pipeline handling E2EE decryption, 5-second cross-device deduplication,
 * anti-popup-storm offline replay buffering, DND/Pause respect, and remote dismissal dispatch.
 */
class NotificationPipeline(
    private val configProvider: () -> PairingConfig?,
    private val cryptoProvider: () -> CryptoEngine?,
    private val database: AllNotifyDatabase,
    private val blobCache: BlobCacheManager,
    private val blobFetcher: BlobFetcher,
    private val displayPort: MirroredDisplayPort,
    private val remoteCancelPort: RemoteCancelPort,
    private val sendAck: suspend (Long) -> Unit,
    private val nowMs: () -> Long = { System.currentTimeMillis() }
) : RelayFrameHandler {

    private val mutex = Mutex()
    private var replaying = false
    private var replayHighestSeq = 0L
    private val replayActiveRowIds = LinkedHashSet<Long>()

    override suspend fun onReplayStart() = mutex.withLock {
        replaying = true
        replayHighestSeq = 0L
        replayActiveRowIds.clear()
    }

    override suspend fun onEvent(frame: EventFrame) = mutex.withLock {
        val config = configProvider() ?: return@withLock
        val crypto = cryptoProvider() ?: return@withLock

        if (replaying && frame.seq > replayHighestSeq) {
            replayHighestSeq = frame.seq
        }

        // Defense-in-depth against server echo.
        if (frame.senderDeviceId != config.deviceId) {
            val plaintext = runCatching {
                crypto.decryptEvent(frame.eventId, frame.senderDeviceId, frame.ciphertext)
            }.getOrNull()

            if (plaintext != null) {
                when (val inner = runCatching { parseInnerPayload(plaintext) }.getOrNull()) {
                    is InnerPayload.Posted -> handlePosted(frame.senderDeviceId, inner.payload)
                    is InnerPayload.Dismissed -> handleDismissed(inner.payload)
                    null -> Unit
                }
            }
        }

        if (!replaying) {
            database.setLastAckedSeq(frame.seq)
            sendAck(frame.seq)
        }
    }

    override suspend fun onReplayComplete(frame: ReplayCompleteFrame) = mutex.withLock {
        replaying = false
        val pendingIds = replayActiveRowIds.toList()
        replayActiveRowIds.clear()

        if (pendingIds.isNotEmpty() && !database.isPaused(nowMs()) && !displayPort.isOsDndBlocking()) {
            val stillActive = pendingIds.mapNotNull { id ->
                database.notificationDao().getById(id)?.takeIf { it.dismissedAt == null }
            }
            if (stillActive.size > SUMMARY_THRESHOLD) {
                displayPort.showReplaySummary(stillActive)
            } else {
                for (entity in stillActive) {
                    val iconFile = entity.iconSha256?.let { blobCache.getIconFile(it) }
                    val attachmentFile = entity.attachmentPath?.let { File(it).takeIf(File::exists) }
                    displayPort.showNotification(entity, iconFile, attachmentFile, silentUpdate = false)
                }
            }
        }

        val ackSeq = maxOf(replayHighestSeq, frame.latestSeq)
        if (ackSeq > 0L) {
            database.setLastAckedSeq(ackSeq)
            sendAck(ackSeq)
        }
    }

    private suspend fun handlePosted(senderDeviceId: String, payload: NotificationPostedPayload) {
        val dao = database.notificationDao()

        // Idempotency: ignore if this exact notification_uid was already ingested.
        // If an earlier replay was interrupted before replay_complete, ensure a still-active
        // mirrored row is re-queued for the current replay batch so it isn't silently lost.
        val existingByUid = dao.findByUidPattern(Deduplicator.jsonQuoted(payload.notificationUid))
            .firstOrNull { payload.notificationUid in Deduplicator.decodeStringList(it.notificationUidsJson) }
        if (existingByUid != null) {
            if (replaying && existingByUid.isMirrored && existingByUid.dismissedAt == null) {
                replayActiveRowIds.add(existingByUid.id)
            }
            return
        }

        val iconFile = if (payload.app.iconSha256 != null && payload.app.iconBlobId != null) {
            blobFetcher.fetchIcon(payload.app.iconSha256, payload.app.iconBlobId)
        } else {
            payload.app.iconSha256?.let { blobCache.getIconFile(it) }
        }

        val firstImage = payload.attachments?.firstOrNull { it.kind == "image" }
        val attachmentFile = if (firstImage != null) {
            blobFetcher.fetchAttachment(firstImage.blobId, firstImage.sha256)
        } else {
            null
        }

        val dedupHash = Deduplicator.fingerprint(
            payload.app.packageName,
            payload.content.title,
            payload.content.body
        )

        val duplicate = dao.findRecentActiveDuplicates(
            dedupHash = dedupHash,
            postedAt = payload.postedAt,
            windowMs = Deduplicator.DEDUP_WINDOW_MS
        ).firstOrNull { candidate ->
            senderDeviceId !in Deduplicator.decodeStringList(candidate.senderDeviceIdsJson)
        }

        if (duplicate != null) {
            val existingSenderIds = Deduplicator.decodeStringList(duplicate.senderDeviceIdsJson)
            val mergedUids = (Deduplicator.decodeStringList(duplicate.notificationUidsJson) + payload.notificationUid).distinct()
            val mergedNames = (Deduplicator.decodeStringList(duplicate.senderDevicesJson) + payload.senderDeviceName).distinct()
            val mergedSenderIds = (existingSenderIds + senderDeviceId).distinct()

            val updated = duplicate.copy(
                notificationUidsJson = Deduplicator.encodeStringList(mergedUids),
                senderDevicesJson = Deduplicator.encodeStringList(mergedNames),
                senderDeviceIdsJson = Deduplicator.encodeStringList(mergedSenderIds),
                iconSha256 = duplicate.iconSha256 ?: payload.app.iconSha256,
                attachmentPath = duplicate.attachmentPath ?: attachmentFile?.absolutePath
            )
            dao.update(updated)

            // Only update the mirrored OS notification if this row is actually mirrored.
            // If isMirrored == false, this phone already has the native app notification locally.
            if (updated.isMirrored && !replaying && !database.isPaused(nowMs()) && !displayPort.isOsDndBlocking()) {
                val resolvedIcon = iconFile ?: updated.iconSha256?.let { blobCache.getIconFile(it) }
                val resolvedAttachment = attachmentFile ?: updated.attachmentPath?.let { File(it).takeIf(File::exists) }
                displayPort.showNotification(updated, resolvedIcon, resolvedAttachment, silentUpdate = true)
            }
            return
        }

        val entity = NotificationEntity(
            notificationUidsJson = Deduplicator.encodeStringList(listOf(payload.notificationUid)),
            senderDevicesJson = Deduplicator.encodeStringList(listOf(payload.senderDeviceName)),
            senderDeviceIdsJson = Deduplicator.encodeStringList(listOf(senderDeviceId)),
            packageName = payload.app.packageName,
            appName = payload.app.name,
            iconSha256 = payload.app.iconSha256,
            title = payload.content.title,
            body = payload.content.body,
            attachmentPath = attachmentFile?.absolutePath,
            dedupHash = dedupHash,
            postedAt = payload.postedAt,
            dismissedAt = null,
            isMirrored = true
        )
        val rowId = dao.insert(entity)
        val saved = entity.copy(id = rowId)

        if (replaying) {
            replayActiveRowIds.add(rowId)
        } else if (!database.isPaused(nowMs()) && !displayPort.isOsDndBlocking()) {
            displayPort.showNotification(saved, iconFile, attachmentFile, silentUpdate = false)
        }
    }

    private suspend fun handleDismissed(payload: NotificationDismissedPayload) {
        val notifDao = database.notificationDao()
        val keyMapDao = database.activeKeyMapDao()

        for (uid in payload.notificationUids) {
            // 1. Mark mirrored/sent history rows dismissed & clear mirrored OS notification.
            val candidates = notifDao.findByUidPattern(Deduplicator.jsonQuoted(uid))
            for (row in candidates) {
                val uids = Deduplicator.decodeStringList(row.notificationUidsJson)
                if (uid in uids) {
                    notifDao.markDismissedById(row.id, payload.dismissedAt)
                    replayActiveRowIds.remove(row.id)
                    if (row.isMirrored) {
                        displayPort.cancelMirrored(row.id)
                    }
                }
            }

            // 2. If this phone originated the notification, cancel it via NotificationListenerService.
            val mapping = keyMapDao.findByUid(uid)
            if (mapping != null) {
                remoteCancelPort.cancelLocalBySbnKey(mapping.sbnKey)
                keyMapDao.deleteBySbnKey(mapping.sbnKey)
            }
        }
    }

    companion object {
        const val SUMMARY_THRESHOLD = 5
    }
}
