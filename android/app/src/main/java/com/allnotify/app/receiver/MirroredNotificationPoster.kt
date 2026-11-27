package com.allnotify.app.receiver

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.BitmapFactory
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import com.allnotify.app.MainActivity
import com.allnotify.app.R
import com.allnotify.app.data.NotificationEntity
import java.io.File

class MirroredNotificationPoster(private val context: Context) : MirroredDisplayPort {

    private val notificationManager =
        context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

    fun ensureChannels() {
        val mirrored = NotificationChannel(
            CHANNEL_MIRRORED,
            "Mirrored Notifications",
            NotificationManager.IMPORTANCE_DEFAULT
        ).apply {
            description = "Notifications mirrored from your other Android devices"
        }
        notificationManager.createNotificationChannel(mirrored)
    }

    override fun isOsDndBlocking(): Boolean {
        val filter = notificationManager.currentInterruptionFilter
        return filter != NotificationManager.INTERRUPTION_FILTER_ALL &&
            filter != NotificationManager.INTERRUPTION_FILTER_UNKNOWN
    }

    override fun showNotification(
        entity: NotificationEntity,
        iconFile: File?,
        attachmentFile: File?,
        silentUpdate: Boolean
    ) {
        if (!canPostNotifications()) return
        ensureChannels()

        val senders = Deduplicator.decodeStringList(entity.senderDevicesJson).joinToString(", ")
        val uids = Deduplicator.decodeStringList(entity.notificationUidsJson)
        val notifId = notificationIdFor(entity.id)

        val contentIntent = PendingIntent.getActivity(
            context,
            notifId,
            Intent(context, MainActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
            },
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val deleteIntent = PendingIntent.getBroadcast(
            context,
            notifId,
            Intent(context, DismissBroadcastReceiver::class.java).apply {
                action = DismissBroadcastReceiver.ACTION_DISMISS_MIRRORED
                putExtra(DismissBroadcastReceiver.EXTRA_ROW_ID, entity.id)
                putStringArrayListExtra(DismissBroadcastReceiver.EXTRA_UIDS, ArrayList(uids))
            },
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val silent = silentUpdate || isOsDndBlocking()
        val subText = if (senders.isNotEmpty()) "${entity.appName} • $senders" else entity.appName
        val builder = NotificationCompat.Builder(context, CHANNEL_MIRRORED)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(entity.title.ifBlank { entity.appName })
            .setContentText(entity.body)
            .setSubText(subText)
            .setWhen(entity.postedAt)
            .setShowWhen(true)
            .setAutoCancel(true)
            .setOnlyAlertOnce(silent)
            .setSilent(silent)
            .setContentIntent(contentIntent)
            .setDeleteIntent(deleteIntent)

        val iconBitmap = iconFile?.takeIf(File::exists)?.let {
            runCatching { BitmapFactory.decodeFile(it.absolutePath) }.getOrNull()
        }
        if (iconBitmap != null) {
            builder.setLargeIcon(iconBitmap)
        }

        val pictureBitmap = attachmentFile?.takeIf(File::exists)?.let {
            runCatching { BitmapFactory.decodeFile(it.absolutePath) }.getOrNull()
        }
        if (pictureBitmap != null) {
            builder.setStyle(
                NotificationCompat.BigPictureStyle()
                    .bigPicture(pictureBitmap)
                    .setSummaryText(entity.body)
            )
        } else if (entity.body.length > 48) {
            builder.setStyle(NotificationCompat.BigTextStyle().bigText(entity.body))
        }

        notificationManager.notify(notifId, builder.build())
    }

    override fun showReplaySummary(activeEntities: List<NotificationEntity>) {
        if (!canPostNotifications() || activeEntities.isEmpty()) return
        ensureChannels()

        val contentIntent = PendingIntent.getActivity(
            context,
            SUMMARY_NOTIFICATION_ID,
            Intent(context, MainActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
            },
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val inbox = NotificationCompat.InboxStyle()
            .setBigContentTitle("${activeEntities.size} new notifications")
        activeEntities.take(5).forEach { e ->
            val preview = listOf(e.title, e.body).filter { it.isNotBlank() }.joinToString(": ")
            inbox.addLine("${e.appName} — $preview")
        }
        if (activeEntities.size > 5) {
            inbox.setSummaryText("+${activeEntities.size - 5} more in All-Notify")
        }

        val silent = isOsDndBlocking()
        val notif = NotificationCompat.Builder(context, CHANNEL_MIRRORED)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle("${activeEntities.size} mirrored notifications")
            .setContentText("Tap to view in All-Notify")
            .setStyle(inbox)
            .setAutoCancel(true)
            .setOnlyAlertOnce(silent)
            .setSilent(silent)
            .setContentIntent(contentIntent)
            .build()

        notificationManager.notify(SUMMARY_NOTIFICATION_ID, notif)
    }

    override fun cancelMirrored(notificationRowId: Long) {
        notificationManager.cancel(notificationIdFor(notificationRowId))
    }

    private fun canPostNotifications(): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return true
        return ContextCompat.checkSelfPermission(
            context,
            Manifest.permission.POST_NOTIFICATIONS
        ) == PackageManager.PERMISSION_GRANTED
    }

    companion object {
        const val CHANNEL_MIRRORED = "mirrored_notifications"
        private const val MIRROR_ID_BASE = 10_000
        private const val SUMMARY_NOTIFICATION_ID = 9_999

        fun notificationIdFor(rowId: Long): Int =
            MIRROR_ID_BASE + (rowId % 1_000_000L).toInt()
    }
}
