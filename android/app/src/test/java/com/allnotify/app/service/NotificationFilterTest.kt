package com.allnotify.app.service

import android.app.Notification
import android.app.NotificationManager
import com.allnotify.app.data.AppFilterEntity
import com.allnotify.app.data.KvKeys
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class NotificationFilterTest {

    private val filter = NotificationFilter("com.allnotify.app")

    private fun sample(
        packageName: String = "com.whatsapp",
        isOngoing: Boolean = false,
        isForegroundService: Boolean = false,
        isGroupSummary: Boolean = false,
        category: String? = Notification.CATEGORY_MESSAGE,
        isMediaStyle: Boolean = false,
        importance: Int = NotificationManager.IMPORTANCE_DEFAULT,
        title: String = "Alice",
        body: String = "Hello"
    ) = NotificationFilterInput(
        packageName = packageName,
        isOngoing = isOngoing,
        isForegroundService = isForegroundService,
        isGroupSummary = isGroupSummary,
        category = category,
        isMediaStyle = isMediaStyle,
        importance = importance,
        title = title,
        body = body
    )

    @Test
    fun ownPackageIsAlwaysDroppedEvenWithAllowlistOverride() {
        val override = AppFilterEntity("com.allnotify.app", "All-Notify", enabled = true, allowOngoing = true)
        assertFalse(filter.shouldCapture(sample(packageName = "com.allnotify.app"), override, KvKeys.FILTER_MODE_DENYLIST))
        assertFalse(filter.shouldCapture(sample(packageName = "com.allnotify.app"), override, KvKeys.FILTER_MODE_ALLOWLIST))
    }

    @Test
    fun defaultNoiseFiltersWorkAndAllowOngoingOverrideApplies() {
        assertTrue(filter.shouldCapture(sample(), null, KvKeys.FILTER_MODE_DENYLIST))
        assertFalse(filter.shouldCapture(sample(isOngoing = true), null, KvKeys.FILTER_MODE_DENYLIST))
        assertFalse(filter.shouldCapture(sample(isForegroundService = true), null, KvKeys.FILTER_MODE_DENYLIST))
        assertFalse(filter.shouldCapture(sample(isGroupSummary = true), null, KvKeys.FILTER_MODE_DENYLIST))
        assertFalse(filter.shouldCapture(sample(category = Notification.CATEGORY_TRANSPORT), null, KvKeys.FILTER_MODE_DENYLIST))
        assertFalse(filter.shouldCapture(sample(isMediaStyle = true), null, KvKeys.FILTER_MODE_DENYLIST))
        assertFalse(filter.shouldCapture(sample(importance = NotificationManager.IMPORTANCE_MIN), null, KvKeys.FILTER_MODE_DENYLIST))
        assertTrue(
            "IMPORTANCE_UNSPECIFIED (-1000) must not be falsely dropped as IMPORTANCE_MIN",
            filter.shouldCapture(sample(importance = NotificationManager.IMPORTANCE_UNSPECIFIED), null, KvKeys.FILTER_MODE_DENYLIST)
        )
        assertFalse(filter.shouldCapture(sample(title = " ", body = ""), null, KvKeys.FILTER_MODE_DENYLIST))

        val allowOngoing = AppFilterEntity("com.whatsapp", "WhatsApp", enabled = true, allowOngoing = true)
        assertTrue(filter.shouldCapture(sample(isOngoing = true), allowOngoing, KvKeys.FILTER_MODE_DENYLIST))
        assertTrue(filter.shouldCapture(sample(isForegroundService = true), allowOngoing, KvKeys.FILTER_MODE_DENYLIST))
    }

    @Test
    fun denylistAndAllowlistModesBehaveCorrectly() {
        val disabled = AppFilterEntity("com.spam", "Spam", enabled = false)
        val enabled = AppFilterEntity("com.whatsapp", "WhatsApp", enabled = true)

        assertFalse(filter.shouldCapture(sample(packageName = "com.spam"), disabled, KvKeys.FILTER_MODE_DENYLIST))
        assertTrue(filter.shouldCapture(sample(packageName = "com.unknown"), null, KvKeys.FILTER_MODE_DENYLIST))

        assertFalse(filter.shouldCapture(sample(packageName = "com.unknown"), null, KvKeys.FILTER_MODE_ALLOWLIST))
        assertFalse(filter.shouldCapture(sample(packageName = "com.spam"), disabled, KvKeys.FILTER_MODE_ALLOWLIST))
        assertTrue(filter.shouldCapture(sample(packageName = "com.whatsapp"), enabled, KvKeys.FILTER_MODE_ALLOWLIST))
    }
}
