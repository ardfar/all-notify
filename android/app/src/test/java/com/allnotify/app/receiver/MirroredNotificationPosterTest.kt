package com.allnotify.app.receiver

import android.Manifest
import android.app.Application
import android.app.Notification
import android.app.NotificationManager
import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.allnotify.app.data.NotificationEntity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = Application::class)
class MirroredNotificationPosterTest {

    @Test
    fun postsMirroredNotificationWithDeleteIntentCancelsAndChecksDnd() {
        val app = ApplicationProvider.getApplicationContext<Application>()
        shadowOf(app).grantPermissions(Manifest.permission.POST_NOTIFICATIONS)
        val nm = app.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        val shadowNm = shadowOf(nm)

        val poster = MirroredNotificationPoster(app)

        // DND check
        shadowNm.setNotificationPolicyAccessGranted(true)
        nm.setInterruptionFilter(NotificationManager.INTERRUPTION_FILTER_ALL)
        assertFalse(poster.isOsDndBlocking())
        nm.setInterruptionFilter(NotificationManager.INTERRUPTION_FILTER_PRIORITY)
        assertTrue(poster.isOsDndBlocking())
        nm.setInterruptionFilter(NotificationManager.INTERRUPTION_FILTER_ALL)

        val entity = NotificationEntity(
            id = 42L,
            notificationUidsJson = """["uid_1","uid_2"]""",
            senderDevicesJson = """["Phone A","Phone B"]""",
            packageName = "com.whatsapp",
            appName = "WhatsApp",
            title = "Alice",
            body = "Dinner at 7?",
            dedupHash = "abc",
            postedAt = 1_764_060_000_000L,
            isMirrored = true
        )

        poster.showNotification(entity, iconFile = null, attachmentFile = null, silentUpdate = false)

        val active = shadowNm.allNotifications
        assertEquals(1, active.size)
        val posted = active[0]
        assertEquals("Alice", posted.extras.getCharSequence(Notification.EXTRA_TITLE)?.toString())
        assertEquals("Dinner at 7?", posted.extras.getCharSequence(Notification.EXTRA_TEXT)?.toString())
        assertEquals("WhatsApp • Phone A, Phone B", posted.extras.getCharSequence(Notification.EXTRA_SUB_TEXT)?.toString())
        assertNotNull("DeleteIntent must be wired for swipe dismissal sync", posted.deleteIntent)
        val deleteIntent = shadowOf(posted.deleteIntent).savedIntent
        assertEquals(DismissBroadcastReceiver.ACTION_DISMISS_MIRRORED, deleteIntent.action)
        assertEquals(42L, deleteIntent.getLongExtra(DismissBroadcastReceiver.EXTRA_ROW_ID, -1L))
        assertEquals(arrayListOf("uid_1", "uid_2"), deleteIntent.getStringArrayListExtra(DismissBroadcastReceiver.EXTRA_UIDS))

        poster.cancelMirrored(42L)
        assertEquals(0, shadowNm.allNotifications.size)

        // Summary collapse
        val batch = (1..7).map { i -> entity.copy(id = i.toLong(), title = "Msg $i") }
        poster.showReplaySummary(batch)
        assertEquals(1, shadowNm.allNotifications.size)
        assertEquals(
            "7 mirrored notifications",
            shadowNm.allNotifications[0].extras.getCharSequence(Notification.EXTRA_TITLE)?.toString()
        )
    }
}
