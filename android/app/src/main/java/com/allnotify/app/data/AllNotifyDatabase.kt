package com.allnotify.app.data

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase

@Database(
    entities = [
        NotificationEntity::class,
        ActiveKeyMapEntity::class,
        AppFilterEntity::class,
        OutboxEntity::class,
        KvStateEntity::class
    ],
    version = 1,
    exportSchema = false
)
abstract class AllNotifyDatabase : RoomDatabase() {
    abstract fun notificationDao(): NotificationDao
    abstract fun activeKeyMapDao(): ActiveKeyMapDao
    abstract fun appFilterDao(): AppFilterDao
    abstract fun outboxDao(): OutboxDao
    abstract fun kvStateDao(): KvStateDao

    suspend fun getLastAckedSeq(): Long =
        kvStateDao().get(KvKeys.LAST_ACKED_SEQ)?.toLongOrNull() ?: 0L

    suspend fun setLastAckedSeq(seq: Long) {
        val current = getLastAckedSeq()
        if (seq > current) {
            kvStateDao().put(KvStateEntity(KvKeys.LAST_ACKED_SEQ, seq.toString()))
        }
    }

    suspend fun resetSyncState() {
        kvStateDao().delete(KvKeys.LAST_ACKED_SEQ)
        outboxDao().deleteAll()
    }

    suspend fun isPaused(nowMs: Long = System.currentTimeMillis()): Boolean {
        val pausedUntil = kvStateDao().get(KvKeys.PAUSED_UNTIL)?.toLongOrNull() ?: 0L
        return pausedUntil == Long.MAX_VALUE || pausedUntil > nowMs
    }

    suspend fun setPaused(paused: Boolean) {
        val value = if (paused) Long.MAX_VALUE.toString() else "0"
        kvStateDao().put(KvStateEntity(KvKeys.PAUSED_UNTIL, value))
    }

    suspend fun getFilterMode(): String =
        kvStateDao().get(KvKeys.FILTER_MODE) ?: KvKeys.FILTER_MODE_DENYLIST

    suspend fun setFilterMode(mode: String) {
        kvStateDao().put(KvStateEntity(KvKeys.FILTER_MODE, mode))
    }

    suspend fun getCanAddDevices(): Boolean =
        kvStateDao().get(KvKeys.CAN_ADD_DEVICES) == "true"

    suspend fun setCanAddDevices(trusted: Boolean) {
        kvStateDao().put(KvStateEntity(KvKeys.CAN_ADD_DEVICES, trusted.toString()))
    }

    /** Enforces 30-day / 5,000-row retention and removes expired outbox & orphaned attachment files. */
    suspend fun pruneRetention(
        blobCache: BlobCacheManager,
        nowMs: Long = System.currentTimeMillis()
    ): PruneStats {
        val deletedByAge = notificationDao().deleteOlderThan(nowMs - RETENTION_MS)
        val deletedByCap = notificationDao().trimToMaxRows(MAX_HISTORY_ROWS)
        val deletedOutbox = outboxDao().deleteOlderThan(nowMs - OUTBOX_TTL_MS)
        activeKeyMapDao().deleteOlderThan(nowMs - ACTIVE_KEY_TTL_MS)

        val referenced = notificationDao().listReferencedAttachmentPaths().toSet()
        val deletedOrphans = blobCache.pruneOrphanAttachments(referenced)
        return PruneStats(
            deletedNotifications = deletedByAge + deletedByCap,
            deletedOutbox = deletedOutbox,
            deletedOrphanAttachments = deletedOrphans
        )
    }

    data class PruneStats(
        val deletedNotifications: Int,
        val deletedOutbox: Int,
        val deletedOrphanAttachments: Int
    )

    companion object {
        const val MAX_HISTORY_ROWS = 5_000
        const val RETENTION_MS = 30L * 24 * 60 * 60 * 1000
        const val OUTBOX_TTL_MS = 24L * 60 * 60 * 1000
        const val ACTIVE_KEY_TTL_MS = 7L * 24 * 60 * 60 * 1000

        fun build(context: Context): AllNotifyDatabase =
            Room.databaseBuilder(
                context.applicationContext,
                AllNotifyDatabase::class.java,
                "all_notify.db"
            ).build()
    }
}
