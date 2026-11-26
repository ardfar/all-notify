package com.allnotify.app.service

import android.app.Notification
import android.app.NotificationManager
import com.allnotify.app.data.AppFilterEntity
import com.allnotify.app.data.KvKeys

data class NotificationFilterInput(
    val packageName: String,
    val isOngoing: Boolean,
    val isForegroundService: Boolean,
    val isGroupSummary: Boolean,
    val category: String?,
    val isMediaStyle: Boolean,
    val importance: Int,
    val title: String,
    val body: String
)

/**
 * Pure filtering logic for Android notification capture.
 * Enforces the non-negotiable own-package loop guard and default noise filters.
 */
class NotificationFilter(private val ownPackageName: String) {

    fun shouldCapture(
        input: NotificationFilterInput,
        appFilter: AppFilterEntity?,
        filterMode: String
    ): Boolean {
        // 1. Unconditional loop guard: never capture our own notifications.
        if (input.packageName == ownPackageName) return false

        // 2. Drop empty shell notifications with no displayable text.
        if (input.title.isBlank() && input.body.isBlank()) return false

        // 3. Per-app filter (denylist by default; toggleable to allowlist).
        val appEnabled = when (filterMode) {
            KvKeys.FILTER_MODE_ALLOWLIST -> appFilter?.enabled == true
            else -> appFilter?.enabled ?: true
        }
        if (!appEnabled) return false

        // 4. Ongoing / foreground service notifications (overridable per app).
        val allowOngoing = appFilter?.allowOngoing == true
        if ((input.isOngoing || input.isForegroundService) && !allowOngoing) return false

        // 5. Group summary shells (individual child notifications are mirrored instead).
        if (input.isGroupSummary) return false

        // 6. Media transport controls.
        if (input.category == Notification.CATEGORY_TRANSPORT || input.isMediaStyle) return false

        // 7. Low/min importance notifications (ignore IMPORTANCE_UNSPECIFIED = -1000).
        if (input.importance != NotificationManager.IMPORTANCE_UNSPECIFIED &&
            input.importance <= NotificationManager.IMPORTANCE_MIN
        ) return false

        return true
    }
}
