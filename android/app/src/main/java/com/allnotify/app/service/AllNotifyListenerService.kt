package com.allnotify.app.service

import android.app.Notification
import android.app.NotificationManager
import android.content.Context
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.os.Bundle
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import com.allnotify.app.AllNotifyApp
import com.allnotify.app.BuildConfig
import com.allnotify.app.crypto.CryptoEngine
import com.allnotify.app.crypto.PairingConfig
import com.allnotify.app.crypto.Ulid
import com.allnotify.app.data.ActiveKeyMapEntity
import com.allnotify.app.data.AllNotifyDatabase
import com.allnotify.app.data.BlobCacheManager
import com.allnotify.app.data.NotificationEntity
import com.allnotify.app.net.BlobApiClient
import com.allnotify.app.protocol.AppInfoPayload
import com.allnotify.app.protocol.AttachmentPayload
import com.allnotify.app.protocol.ContentPayload
import com.allnotify.app.protocol.NotificationPostedPayload
import com.allnotify.app.protocol.encodePostedPayload
import com.allnotify.app.receiver.Deduplicator
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.io.File
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

/**
 * Coordinates concurrent onNotificationPosted (which performs async icon/image uploads)
 * and onNotificationRemoved callbacks for the same sbn.key so a notification swiped away
 * before its upload finishes is aborted cleanly rather than sent as a ghost notification.
 */
internal class SbnLifecycleCoordinator {
    private val seqGen = AtomicLong(0L)
    private val removedSeqByKey = ConcurrentHashMap<String, Long>()
    private val inFlightByKey = ConcurrentHashMap<String, Int>()
    private val commitMutex = Mutex()

    fun onPostStarted(sbnKey: String): Long {
        inFlightByKey.compute(sbnKey) { _, prev -> (prev ?: 0) + 1 }
        return seqGen.incrementAndGet()
    }

    fun onPostFinished(sbnKey: String) {
        inFlightByKey.compute(sbnKey) { _, prev ->
            val next = (prev ?: 1) - 1
            if (next <= 0) null else next
        }
    }

    fun onRemoved(sbnKey: String): Long {
        val seq = seqGen.incrementAndGet()
        removedSeqByKey[sbnKey] = seq
        pruneIfNeeded()
        return seq
    }

    fun wasRemovedAfter(sbnKey: String, postSeq: Long): Boolean =
        (removedSeqByKey[sbnKey] ?: 0L) >= postSeq

    suspend fun <T> withCommitLock(sbnKey: String, postSeq: Long, block: suspend () -> T): T? {
        return commitMutex.withLock {
            if (wasRemovedAfter(sbnKey, postSeq)) {
                null
            } else {
                block()
            }
        }
    }

    suspend fun <T> withRemoveLock(block: suspend () -> T): T =
        commitMutex.withLock { block() }

    private fun pruneIfNeeded() {
        if (removedSeqByKey.size <= MAX_TRACKED_KEYS) return
        val it = removedSeqByKey.entries.iterator()
        while (it.hasNext() && removedSeqByKey.size > MAX_TRACKED_KEYS / 2) {
            val entry = it.next()
            if (!inFlightByKey.containsKey(entry.key)) {
                it.remove()
            }
        }
    }

    companion object {
        private const val MAX_TRACKED_KEYS = 512
    }
}

class AllNotifyListenerService : NotificationListenerService() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val filter = NotificationFilter(BuildConfig.APPLICATION_ID)
    private val lifecycle = SbnLifecycleCoordinator()

    override fun onListenerConnected() {
        super.onListenerConnected()
        activeInstance.set(this)
        (applicationContext as? AllNotifyApp)?.ensureRelayRunning()
    }

    override fun onListenerDisconnected() {
        activeInstance.compareAndSet(this, null)
        super.onListenerDisconnected()
    }

    override fun onDestroy() {
        activeInstance.compareAndSet(this, null)
        scope.cancel()
        super.onDestroy()
    }

    override fun onNotificationPosted(sbn: StatusBarNotification?) {
        val status = sbn ?: return
        // Unconditional fast-path loop guard.
        if (status.packageName == BuildConfig.APPLICATION_ID) return

        val app = applicationContext as? AllNotifyApp ?: return
        val config = app.currentConfig() ?: return
        val crypto = app.currentCrypto() ?: return

        val notification = status.notification ?: return
        val extras = notification.extras ?: return

        val title = extras.getCharSequence(Notification.EXTRA_TITLE)?.toString().orEmpty()
        val body = extractBody(extras).take(MAX_BODY_CHARS)
        val subText = extras.getCharSequence(Notification.EXTRA_SUB_TEXT)
            ?.toString()
            ?.takeIf { it.isNotBlank() }
            ?.take(MAX_SUBTEXT_CHARS)

        val flags = notification.flags
        val template = extras.getString(Notification.EXTRA_TEMPLATE).orEmpty()
        val isMediaStyle = template.contains("MediaStyle", ignoreCase = true) ||
            extras.containsKey(Notification.EXTRA_MEDIA_SESSION)

        val ranking = Ranking()
        val importance = if (currentRanking?.getRanking(status.key, ranking) == true &&
            ranking.importance != NotificationManager.IMPORTANCE_UNSPECIFIED
        ) {
            ranking.importance
        } else {
            NotificationManager.IMPORTANCE_DEFAULT
        }

        val filterInput = NotificationFilterInput(
            packageName = status.packageName,
            isOngoing = status.isOngoing || (flags and Notification.FLAG_ONGOING_EVENT) != 0,
            isForegroundService = (flags and Notification.FLAG_FOREGROUND_SERVICE) != 0,
            isGroupSummary = (flags and Notification.FLAG_GROUP_SUMMARY) != 0,
            category = notification.category,
            isMediaStyle = isMediaStyle,
            importance = importance,
            title = title,
            body = body
        )

        val extrasSnapshot = Bundle(extras)
        val sbnKey = status.key
        val pkgName = status.packageName.take(MAX_PKG_CHARS)
        val postedAt = status.postTime.takeIf { it > 0L } ?: System.currentTimeMillis()
        val groupKey = status.groupKey?.takeIf { it.isNotBlank() }?.take(MAX_GROUP_KEY_CHARS)
        val category = notification.category?.takeIf { it.isNotBlank() }?.take(MAX_CATEGORY_CHARS)

        processPostedNotification(
            context = this,
            config = config,
            crypto = crypto,
            database = app.database,
            blobCache = app.blobCache,
            blobApiClient = app.blobApiClient,
            enqueueAndSend = { eventId, ciphertext -> app.relayClient.enqueueAndSend(eventId, ciphertext) },
            filterInput = filterInput,
            extrasSnapshot = extrasSnapshot,
            sbnKey = sbnKey,
            pkgName = pkgName,
            title = title,
            body = body,
            subText = subText,
            postedAt = postedAt,
            groupKey = groupKey,
            category = category,
            appNameResolver = { resolveAppName(it) },
            iconEncoder = { pkg ->
                runCatching {
                    val drawable = packageManager.getApplicationIcon(pkg)
                    MediaProcessor.encodeAppIcon(drawable)
                }.getOrNull()
            },
            attachmentExtractor = MediaProcessor::extractAttachmentBitmap
        )
    }

    internal fun processPostedNotification(
        context: Context,
        config: PairingConfig,
        crypto: CryptoEngine,
        database: AllNotifyDatabase,
        blobCache: BlobCacheManager,
        blobApiClient: BlobApiClient,
        enqueueAndSend: suspend (String, String) -> Boolean,
        filterInput: NotificationFilterInput,
        extrasSnapshot: Bundle,
        sbnKey: String,
        pkgName: String,
        title: String,
        body: String,
        subText: String?,
        postedAt: Long,
        groupKey: String?,
        category: String?,
        appNameResolver: (String) -> String,
        iconEncoder: (String) -> EncodedIcon?,
        attachmentExtractor: (Context, Bundle) -> Bitmap?
    ): Job {
        val postSeq = lifecycle.onPostStarted(sbnKey)

        return scope.launch {
            try {
                if (database.isPaused()) return@launch
                val filterMode = database.getFilterMode()
                val appFilter = database.appFilterDao().get(pkgName)
                if (!filter.shouldCapture(filterInput, appFilter, filterMode)) return@launch

                val appName = appNameResolver(pkgName).ifBlank { pkgName }.take(MAX_APP_NAME_CHARS)

                // App icon pipeline (64x64 WebP, SHA-256 cached, HEAD before PUT).
                var iconSha256: String? = null
                var iconBlobId: String? = null
                val encodedIcon = iconEncoder(pkgName)
                if (encodedIcon != null) {
                    iconSha256 = encodedIcon.sha256
                    blobCache.putIcon(encodedIcon.sha256, encodedIcon.bytes)
                    iconBlobId = blobApiClient.ensureIconUploaded(
                        config = config,
                        crypto = crypto,
                        blobCache = blobCache,
                        sha256 = encodedIcon.sha256,
                        webpBytes = encodedIcon.bytes
                    )
                }

                // Abort early before decoding/uploading a large image if notification was already dismissed.
                if (lifecycle.wasRemovedAfter(sbnKey, postSeq)) return@launch

                // Image attachment pipeline (extract/decode on IO thread after filtering, <=800px, <=512KB).
                var attachments: List<AttachmentPayload>? = null
                var localAttachmentPath: String? = null
                val rawAttachmentBitmap = attachmentExtractor(context, extrasSnapshot)
                if (rawAttachmentBitmap != null) {
                    val encodedImg = runCatching {
                        MediaProcessor.compressImageAttachment(rawAttachmentBitmap)
                    }.getOrNull()
                    if (encodedImg != null) {
                        val imgBlobId = "img_${Ulid.generate(postedAt)}"
                        val uploaded = blobApiClient.uploadImageAttachment(
                            config = config,
                            crypto = crypto,
                            blobId = imgBlobId,
                            imageBytes = encodedImg.bytes
                        )
                        if (uploaded) {
                            localAttachmentPath = blobCache.putAttachment(imgBlobId, encodedImg.bytes).absolutePath
                            attachments = listOf(
                                AttachmentPayload(
                                    kind = "image",
                                    blobId = imgBlobId,
                                    mime = encodedImg.mime,
                                    width = encodedImg.width,
                                    height = encodedImg.height,
                                    sizeBytes = encodedImg.bytes.size,
                                    sha256 = encodedImg.sha256
                                )
                            )
                        }
                    }
                }

                val eventId = Ulid.generate(postedAt)
                val notificationUid = "${config.deviceId}:$postedAt:${eventId.takeLast(6).lowercase()}"

                val payload = NotificationPostedPayload(
                    notificationUid = notificationUid,
                    senderDeviceName = config.deviceName.take(MAX_DEVICE_NAME_CHARS),
                    postedAt = postedAt,
                    app = AppInfoPayload(
                        packageName = pkgName,
                        name = appName,
                        iconSha256 = iconSha256,
                        iconBlobId = iconBlobId
                    ),
                    content = ContentPayload(
                        title = title.take(MAX_TITLE_CHARS),
                        body = body,
                        subText = subText,
                        category = category,
                        groupKey = groupKey
                    ),
                    attachments = attachments
                )

                // Atomically verify the notification was not removed during async uploads
                // before recording active_key_map, local history, and broadcasting.
                val committed = lifecycle.withCommitLock(sbnKey, postSeq) {
                    database.activeKeyMapDao().upsert(
                        ActiveKeyMapEntity(
                            notificationUid = notificationUid,
                            sbnKey = sbnKey,
                            createdAt = postedAt
                        )
                    )

                    database.notificationDao().insert(
                        NotificationEntity(
                            notificationUidsJson = Deduplicator.encodeStringList(listOf(notificationUid)),
                            senderDevicesJson = Deduplicator.encodeStringList(listOf(config.deviceName)),
                            senderDeviceIdsJson = Deduplicator.encodeStringList(listOf(config.deviceId)),
                            packageName = pkgName,
                            appName = appName,
                            iconSha256 = iconSha256,
                            title = payload.content.title,
                            body = payload.content.body,
                            attachmentPath = localAttachmentPath,
                            dedupHash = Deduplicator.fingerprint(pkgName, payload.content.title, payload.content.body),
                            postedAt = postedAt,
                            dismissedAt = null,
                            isMirrored = false
                        )
                    )

                    val ciphertext = crypto.encryptEvent(
                        eventId = eventId,
                        senderDeviceId = config.deviceId,
                        plaintextUtf8 = encodePostedPayload(payload)
                    )
                    enqueueAndSend(eventId, ciphertext)
                }
                if (committed == null && localAttachmentPath != null) {
                    runCatching { File(localAttachmentPath).delete() }
                }
            } finally {
                lifecycle.onPostFinished(sbnKey)
            }
        }
    }

    internal fun markRemovedForTest(sbnKey: String) {
        lifecycle.onRemoved(sbnKey)
    }

    override fun onNotificationRemoved(
        sbn: StatusBarNotification?,
        rankingMap: RankingMap?,
        reason: Int
    ) {
        val status = sbn ?: return
        if (status.packageName == BuildConfig.APPLICATION_ID) return
        val app = applicationContext as? AllNotifyApp ?: return

        val sbnKey = status.key
        lifecycle.onRemoved(sbnKey)

        // Suppress echo if this removal was triggered by a remote notification.dismissed event.
        if (app.remoteCancelGuard.consumeIfRemotelyCancelled(sbnKey)) {
            return
        }

        scope.launch {
            lifecycle.withRemoveLock {
                val mappings = app.database.activeKeyMapDao().findBySbnKey(sbnKey)
                if (mappings.isEmpty()) return@withRemoveLock

                app.database.activeKeyMapDao().deleteBySbnKey(sbnKey)
                val mappedUids = mappings.map { it.notificationUid }.distinct()
                val allUidsToDismiss = LinkedHashSet<String>(mappedUids)
                val now = System.currentTimeMillis()
                for (uid in mappedUids) {
                    val rows = app.database.notificationDao().findByUidPattern(Deduplicator.jsonQuoted(uid))
                    for (row in rows) {
                        val rowUids = Deduplicator.decodeStringList(row.notificationUidsJson)
                        if (uid in rowUids) {
                            app.database.notificationDao().markDismissedById(row.id, now)
                            allUidsToDismiss.addAll(rowUids)
                        }
                    }
                }
                app.emitDismissal(allUidsToDismiss.toList())
            }
        }
    }

    @Suppress("DEPRECATION")
    private fun extractBody(extras: Bundle): String {
        val bigText = extras.getCharSequence(Notification.EXTRA_BIG_TEXT)?.toString()
        if (!bigText.isNullOrBlank()) return bigText

        val plainText = extras.getCharSequence(Notification.EXTRA_TEXT)?.toString()
        if (!plainText.isNullOrBlank()) return plainText

        // Fallback for MessagingStyle notifications that omit EXTRA_TEXT.
        val messages = extras.getParcelableArray(Notification.EXTRA_MESSAGES)
        if (messages != null) {
            for (i in messages.lastIndex downTo 0) {
                val msgText = (messages[i] as? Bundle)?.getCharSequence("text")?.toString()
                if (!msgText.isNullOrBlank()) return msgText
            }
        }

        // Fallback for InboxStyle notifications that populate EXTRA_TEXT_LINES only.
        val lines = extras.getCharSequenceArray(Notification.EXTRA_TEXT_LINES)
        if (!lines.isNullOrEmpty()) {
            val joined = lines.mapNotNull { it?.toString()?.takeIf(String::isNotBlank) }.joinToString("\n")
            if (joined.isNotBlank()) return joined
        }
        return ""
    }

    private fun resolveAppName(packageName: String): String = runCatching {
        val appInfo = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU) {
            packageManager.getApplicationInfo(packageName, PackageManager.ApplicationInfoFlags.of(0))
        } else {
            @Suppress("DEPRECATION")
            packageManager.getApplicationInfo(packageName, 0)
        }
        packageManager.getApplicationLabel(appInfo).toString()
    }.getOrDefault(packageName)

    companion object {
        private const val MAX_TITLE_CHARS = 512
        private const val MAX_BODY_CHARS = 8_192
        private const val MAX_SUBTEXT_CHARS = 512
        private const val MAX_GROUP_KEY_CHARS = 256
        private const val MAX_CATEGORY_CHARS = 64
        private const val MAX_PKG_CHARS = 256
        private const val MAX_APP_NAME_CHARS = 256
        private const val MAX_DEVICE_NAME_CHARS = 128

        private val activeInstance = AtomicReference<AllNotifyListenerService?>(null)

        fun isConnected(): Boolean = activeInstance.get() != null

        fun cancelRemote(sbnKey: String, guard: RemoteCancelGuard) {
            val svc = activeInstance.get() ?: return
            guard.markRemotelyCancelled(sbnKey)
            runCatching { svc.cancelNotification(sbnKey) }
        }
    }
}
