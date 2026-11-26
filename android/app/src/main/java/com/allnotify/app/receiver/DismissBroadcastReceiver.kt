package com.allnotify.app.receiver

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import com.allnotify.app.AllNotifyApp
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

/** Triggered when a user swipes away a mirrored notification on this Android device. */
class DismissBroadcastReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent?) {
        if (intent?.action != ACTION_DISMISS_MIRRORED) return
        val app = context.applicationContext as? AllNotifyApp ?: return
        val rowId = intent.getLongExtra(EXTRA_ROW_ID, -1L)
        val fallbackUids = intent.getStringArrayListExtra(EXTRA_UIDS).orEmpty()

        val pendingResult = goAsync()
        CoroutineScope(Dispatchers.IO).launch {
            try {
                // Prefer DB row's UIDs so merged 5s-dedup UIDs added after initial post are all dismissed.
                val uids = if (rowId > 0L) {
                    val row = app.database.notificationDao().getById(rowId)
                    if (row != null) {
                        if (row.dismissedAt != null) return@launch
                        app.database.notificationDao().markDismissedById(rowId, System.currentTimeMillis())
                        Deduplicator.decodeStringList(row.notificationUidsJson).ifEmpty { fallbackUids }
                    } else {
                        fallbackUids
                    }
                } else {
                    fallbackUids
                }

                if (uids.isNotEmpty()) {
                    app.emitDismissal(uids)
                }
            } finally {
                pendingResult.finish()
            }
        }
    }

    companion object {
        const val ACTION_DISMISS_MIRRORED = "com.allnotify.app.ACTION_DISMISS_MIRRORED"
        const val EXTRA_ROW_ID = "row_id"
        const val EXTRA_UIDS = "uids"
    }
}
