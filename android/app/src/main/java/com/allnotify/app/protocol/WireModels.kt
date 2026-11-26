package com.allnotify.app.protocol

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonPrimitive

val ProtocolJson = Json {
    ignoreUnknownKeys = false
    encodeDefaults = true
    explicitNulls = false
}

// --- Outer WS frames (visible to zero-knowledge VPS) ---

@Serializable
data class RelayFrame(
    val op: String = "relay",
    @SerialName("event_id") val eventId: String,
    val target: String = "broadcast",
    val ciphertext: String
)

@Serializable
data class EventFrame(
    val op: String = "event",
    val seq: Long,
    @SerialName("event_id") val eventId: String,
    @SerialName("sender_device_id") val senderDeviceId: String,
    @SerialName("server_ts") val serverTs: Long,
    val ciphertext: String
)

@Serializable
data class ReplayCompleteFrame(
    val op: String = "replay_complete",
    @SerialName("latest_seq") val latestSeq: Long
)

@Serializable
data class AckFrame(
    val op: String = "ack",
    val seq: Long
)

@Serializable
data class ErrorFrame(
    val op: String = "error",
    val code: String,
    val message: String
)

sealed interface IncomingWsFrame {
    data class Event(val frame: EventFrame) : IncomingWsFrame
    data class ReplayComplete(val frame: ReplayCompleteFrame) : IncomingWsFrame
    data class Error(val frame: ErrorFrame) : IncomingWsFrame
}

fun parseIncomingWsFrame(raw: String): IncomingWsFrame? {
    val obj = ProtocolJson.decodeFromString<JsonObject>(raw)
    return when (obj["op"]?.jsonPrimitive?.content) {
        "event" -> IncomingWsFrame.Event(ProtocolJson.decodeFromString<EventFrame>(raw))
        "replay_complete" -> IncomingWsFrame.ReplayComplete(ProtocolJson.decodeFromString<ReplayCompleteFrame>(raw))
        "error" -> IncomingWsFrame.Error(ProtocolJson.decodeFromString<ErrorFrame>(raw))
        else -> null
    }
}

// --- Inner decrypted payloads (never visible to VPS) ---

@Serializable
data class AppInfoPayload(
    @SerialName("package") val packageName: String,
    val name: String,
    @SerialName("icon_sha256") val iconSha256: String? = null,
    @SerialName("icon_blob_id") val iconBlobId: String? = null
)

@Serializable
data class ContentPayload(
    val title: String,
    val body: String,
    @SerialName("sub_text") val subText: String? = null,
    val category: String? = null,
    @SerialName("group_key") val groupKey: String? = null
)

@Serializable
data class AttachmentPayload(
    val kind: String = "image",
    @SerialName("blob_id") val blobId: String,
    val mime: String,
    val width: Int,
    val height: Int,
    @SerialName("size_bytes") val sizeBytes: Int,
    val sha256: String
)

@Serializable
data class NotificationPostedPayload(
    val type: String = TYPE,
    @SerialName("notification_uid") val notificationUid: String,
    @SerialName("sender_device_name") val senderDeviceName: String,
    @SerialName("posted_at") val postedAt: Long,
    val app: AppInfoPayload,
    val content: ContentPayload,
    val attachments: List<AttachmentPayload>? = null
) {
    companion object {
        const val TYPE = "notification.posted"
    }
}

@Serializable
data class NotificationDismissedPayload(
    val type: String = TYPE,
    @SerialName("notification_uids") val notificationUids: List<String>,
    @SerialName("dismissed_at") val dismissedAt: Long,
    @SerialName("dismissed_by_device_name") val dismissedByDeviceName: String
) {
    companion object {
        const val TYPE = "notification.dismissed"
    }
}

sealed interface InnerPayload {
    data class Posted(val payload: NotificationPostedPayload) : InnerPayload
    data class Dismissed(val payload: NotificationDismissedPayload) : InnerPayload
}

fun parseInnerPayload(raw: String): InnerPayload? {
    val obj = ProtocolJson.decodeFromString<JsonObject>(raw)
    return when (obj["type"]?.jsonPrimitive?.content) {
        NotificationPostedPayload.TYPE ->
            InnerPayload.Posted(ProtocolJson.decodeFromString<NotificationPostedPayload>(raw))
        NotificationDismissedPayload.TYPE ->
            InnerPayload.Dismissed(ProtocolJson.decodeFromString<NotificationDismissedPayload>(raw))
        else -> null
    }
}

fun encodePostedPayload(payload: NotificationPostedPayload): String =
    ProtocolJson.encodeToString(payload)

fun encodeDismissedPayload(payload: NotificationDismissedPayload): String =
    ProtocolJson.encodeToString(payload)
