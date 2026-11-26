package com.allnotify.app.data

import androidx.room.ColumnInfo
import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

@Entity(
    tableName = "notifications",
    indices = [
        Index(value = ["posted_at"]),
        Index(value = ["dedup_hash", "posted_at"])
    ]
)
data class NotificationEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    @ColumnInfo(name = "notification_uids_json") val notificationUidsJson: String,
    @ColumnInfo(name = "sender_devices_json") val senderDevicesJson: String,
    @ColumnInfo(name = "sender_device_ids_json") val senderDeviceIdsJson: String = "[]",
    @ColumnInfo(name = "package_name") val packageName: String,
    @ColumnInfo(name = "app_name") val appName: String,
    @ColumnInfo(name = "icon_sha256") val iconSha256: String? = null,
    val title: String,
    val body: String,
    @ColumnInfo(name = "attachment_path") val attachmentPath: String? = null,
    @ColumnInfo(name = "dedup_hash") val dedupHash: String,
    @ColumnInfo(name = "posted_at") val postedAt: Long,
    @ColumnInfo(name = "dismissed_at") val dismissedAt: Long? = null,
    @ColumnInfo(name = "is_mirrored") val isMirrored: Boolean
)

@Entity(
    tableName = "active_key_map",
    indices = [Index(value = ["sbn_key"])]
)
data class ActiveKeyMapEntity(
    @PrimaryKey @ColumnInfo(name = "notification_uid") val notificationUid: String,
    @ColumnInfo(name = "sbn_key") val sbnKey: String,
    @ColumnInfo(name = "created_at") val createdAt: Long
)

@Entity(tableName = "app_filters")
data class AppFilterEntity(
    @PrimaryKey @ColumnInfo(name = "package_name") val packageName: String,
    @ColumnInfo(name = "app_name") val appName: String,
    val enabled: Boolean = true,
    @ColumnInfo(name = "allow_ongoing") val allowOngoing: Boolean = false
)

@Entity(
    tableName = "outbox",
    indices = [Index(value = ["created_at"])]
)
data class OutboxEntity(
    @PrimaryKey @ColumnInfo(name = "event_id") val eventId: String,
    val ciphertext: String,
    @ColumnInfo(name = "created_at") val createdAt: Long
)

@Entity(tableName = "kv_state")
data class KvStateEntity(
    @PrimaryKey val key: String,
    val value: String
)

object KvKeys {
    const val LAST_ACKED_SEQ = "last_acked_seq"
    const val PAUSED_UNTIL = "paused_until"
    const val FILTER_MODE = "filter_mode"

    const val FILTER_MODE_DENYLIST = "denylist"
    const val FILTER_MODE_ALLOWLIST = "allowlist"
}
