package com.allnotify.app.service

import android.app.Application
import android.app.Notification
import android.app.NotificationManager
import android.content.Context
import android.graphics.Bitmap
import android.net.Uri
import android.os.Bundle
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import com.allnotify.app.crypto.CryptoEngine
import com.allnotify.app.crypto.PairingConfig
import com.allnotify.app.data.AllNotifyDatabase
import com.allnotify.app.data.AppFilterEntity
import com.allnotify.app.data.BlobCacheManager
import com.allnotify.app.net.BlobApiClient
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.File
import java.io.FileOutputStream
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = Application::class)
class AllNotifyListenerServiceTest {

    @get:Rule
    val tempFolder = TemporaryFolder()

    private lateinit var context: Context
    private lateinit var db: AllNotifyDatabase
    private lateinit var blobCache: BlobCacheManager
    private lateinit var server: MockWebServer
    private lateinit var blobApiClient: BlobApiClient
    private lateinit var config: PairingConfig
    private lateinit var crypto: CryptoEngine
    private lateinit var service: AllNotifyListenerService

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        db = Room.inMemoryDatabaseBuilder(context, AllNotifyDatabase::class.java)
            .allowMainThreadQueries()
            .build()
        blobCache = BlobCacheManager(tempFolder.newFolder("listener-cache"))
        server = MockWebServer().apply { start() }
        blobApiClient = BlobApiClient(OkHttpClient())

        val keyBytes = ByteArray(32) { (it + 1).toByte() }
        crypto = CryptoEngine(keyBytes)
        val baseUrl = server.url("").toString().trimEnd('/')
        config = PairingConfig(
            version = 1,
            serverUrl = baseUrl,
            wsUrl = baseUrl.replaceFirst("http://", "ws://") + "/v1/ws",
            token = "tok_listener",
            keyBase64Url = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA",
            keyBytes = keyBytes,
            deviceId = "dev_ANDROID_SRC",
            deviceName = "Pixel Test"
        )

        service = Robolectric.buildService(AllNotifyListenerService::class.java).create().get()
    }

    @After
    fun tearDown() {
        service.onDestroy()
        db.close()
        server.shutdown()
    }

    private fun sampleInput(
        pkg: String = "com.whatsapp",
        isOngoing: Boolean = false
    ) = NotificationFilterInput(
        packageName = pkg,
        isOngoing = isOngoing,
        isForegroundService = false,
        isGroupSummary = false,
        category = Notification.CATEGORY_MESSAGE,
        isMediaStyle = false,
        importance = NotificationManager.IMPORTANCE_DEFAULT,
        title = "Alice",
        body = "Photo attached"
    )

    @Test
    fun filteredAndPausedNotificationsNeverExtractAttachments() = runBlocking {
        val extractorCalls = AtomicInteger(0)
        val sentEvents = mutableListOf<String>()

        // 1. Muted app in denylist mode
        db.appFilterDao().upsert(AppFilterEntity("com.muted.app", "Muted", enabled = false))
        service.processPostedNotification(
            context = context,
            config = config,
            crypto = crypto,
            database = db,
            blobCache = blobCache,
            blobApiClient = blobApiClient,
            enqueueAndSend = { id, _ -> sentEvents.add(id); true },
            filterInput = sampleInput(pkg = "com.muted.app"),
            extrasSnapshot = Bundle(),
            sbnKey = "0|com.muted.app|1|null|100",
            pkgName = "com.muted.app",
            title = "Alice",
            body = "Photo attached",
            subText = null,
            postedAt = 1_764_060_000_000L,
            groupKey = null,
            category = Notification.CATEGORY_MESSAGE,
            appNameResolver = { "Muted" },
            iconEncoder = { null },
            attachmentExtractor = { _, _ ->
                extractorCalls.incrementAndGet()
                null
            }
        ).join()

        // 2. Ongoing notification (blocked by default)
        service.processPostedNotification(
            context = context,
            config = config,
            crypto = crypto,
            database = db,
            blobCache = blobCache,
            blobApiClient = blobApiClient,
            enqueueAndSend = { id, _ -> sentEvents.add(id); true },
            filterInput = sampleInput(pkg = "com.whatsapp", isOngoing = true),
            extrasSnapshot = Bundle(),
            sbnKey = "0|com.whatsapp|2|null|100",
            pkgName = "com.whatsapp",
            title = "Alice",
            body = "Ongoing call",
            subText = null,
            postedAt = 1_764_060_000_001L,
            groupKey = null,
            category = Notification.CATEGORY_MESSAGE,
            appNameResolver = { "WhatsApp" },
            iconEncoder = { null },
            attachmentExtractor = { _, _ ->
                extractorCalls.incrementAndGet()
                null
            }
        ).join()

        // 3. Paused mode
        db.setPaused(true)
        service.processPostedNotification(
            context = context,
            config = config,
            crypto = crypto,
            database = db,
            blobCache = blobCache,
            blobApiClient = blobApiClient,
            enqueueAndSend = { id, _ -> sentEvents.add(id); true },
            filterInput = sampleInput(pkg = "com.whatsapp"),
            extrasSnapshot = Bundle(),
            sbnKey = "0|com.whatsapp|3|null|100",
            pkgName = "com.whatsapp",
            title = "Alice",
            body = "While paused",
            subText = null,
            postedAt = 1_764_060_000_002L,
            groupKey = null,
            category = Notification.CATEGORY_MESSAGE,
            appNameResolver = { "WhatsApp" },
            iconEncoder = { null },
            attachmentExtractor = { _, _ ->
                extractorCalls.incrementAndGet()
                null
            }
        ).join()

        assertEquals("filtered/paused notifications must never extract attachments", 0, extractorCalls.get())
        assertTrue(sentEvents.isEmpty())
        assertEquals(0, db.notificationDao().count())
    }

    @Test
    fun allowedNotificationExtractsAttachmentOnIoThreadAndPersistsEvent() = runBlocking {
        // Prepare a high-res 3200x2400 MessagingStyle image URI
        val imgFile = tempFolder.newFile("listener_highres.png")
        val bigBitmap = Bitmap.createBitmap(3200, 2400, Bitmap.Config.ARGB_8888)
        FileOutputStream(imgFile).use { out ->
            assertTrue(bigBitmap.compress(Bitmap.CompressFormat.PNG, 100, out))
        }
        val msgBundle = Bundle().apply {
            putString("type", "image/png")
            putParcelable("uri", Uri.fromFile(imgFile))
        }
        val extras = Bundle().apply {
            putParcelableArray(Notification.EXTRA_MESSAGES, arrayOf(msgBundle))
        }

        // Mock PUT /v1/blobs/img_... -> 201 Created
        server.enqueue(MockResponse().setResponseCode(201))

        val callerThreadName = Thread.currentThread().name
        val extractorThreadName = AtomicReference<String?>(null)
        val sentEvent = CompletableDeferred<Pair<String, String>>()

        val job = service.processPostedNotification(
            context = context,
            config = config,
            crypto = crypto,
            database = db,
            blobCache = blobCache,
            blobApiClient = blobApiClient,
            enqueueAndSend = { id, ct ->
                sentEvent.complete(id to ct)
                true
            },
            filterInput = sampleInput(pkg = "com.whatsapp"),
            extrasSnapshot = extras,
            sbnKey = "0|com.whatsapp|10|null|100",
            pkgName = "com.whatsapp",
            title = "Alice",
            body = "Photo attached",
            subText = null,
            postedAt = 1_764_060_000_000L,
            groupKey = null,
            category = Notification.CATEGORY_MESSAGE,
            appNameResolver = { "WhatsApp" },
            iconEncoder = { null },
            attachmentExtractor = { ctx, b ->
                extractorThreadName.set(Thread.currentThread().name)
                MediaProcessor.extractAttachmentBitmap(ctx, b)
            }
        )
        withTimeout(5_000L) { job.join() }

        assertNotNull(extractorThreadName.get())
        assertNotEquals(
            "attachment extraction must run on Dispatchers.IO off the caller thread",
            callerThreadName,
            extractorThreadName.get()
        )
        val (eventId, ciphertext) = withTimeout(3_000L) { sentEvent.await() }
        val decrypted = crypto.decryptEvent(eventId, config.deviceId, ciphertext)
        assertTrue(decrypted.contains("\"kind\":\"image\""))
        assertTrue(decrypted.contains("\"width\":800"))
        assertTrue(decrypted.contains("\"height\":600"))
        assertEquals(1, db.notificationDao().count())
        assertEquals(1, db.activeKeyMapDao().findBySbnKey("0|com.whatsapp|10|null|100").size)
    }

    @Test
    fun removedNotificationDuringAttachmentUploadAbortsAndCleansOrphanFile() = runBlocking {
        server.enqueue(MockResponse().setResponseCode(201))

        val sbnKey = "0|com.whatsapp|99|null|100"
        val sentCount = AtomicInteger(0)

        val job = service.processPostedNotification(
            context = context,
            config = config,
            crypto = crypto,
            database = db,
            blobCache = blobCache,
            blobApiClient = blobApiClient,
            enqueueAndSend = { _, _ ->
                sentCount.incrementAndGet()
                true
            },
            filterInput = sampleInput(pkg = "com.whatsapp"),
            extrasSnapshot = Bundle(),
            sbnKey = sbnKey,
            pkgName = "com.whatsapp",
            title = "Alice",
            body = "Swiped away during upload",
            subText = null,
            postedAt = 1_764_060_000_000L,
            groupKey = null,
            category = Notification.CATEGORY_MESSAGE,
            appNameResolver = { "WhatsApp" },
            iconEncoder = { null },
            attachmentExtractor = { _, _ ->
                // Simulate user swiping the notification away right as image extraction finishes
                service.markRemovedForTest(sbnKey)
                Bitmap.createBitmap(200, 200, Bitmap.Config.ARGB_8888)
            }
        )
        withTimeout(5_000L) { job.join() }

        assertEquals("aborted notification must not be sent", 0, sentCount.get())
        assertEquals(0, db.notificationDao().count())
        val leftoverAttachments = blobCache.attachmentsDir.listFiles()?.filter { it.isFile && !it.name.endsWith(".tmp") }.orEmpty()
        assertTrue("aborted upload must not leave orphan attachment on disk: $leftoverAttachments", leftoverAttachments.isEmpty())
    }

    @Test
    fun requestRebindIfNeededGuardsPermissionThrottleForceAndConnectedState() {
        AllNotifyListenerService.resetRebindThrottleForTest()
        val rebindComponents = mutableListOf<android.content.ComponentName>()
        var now = 100_000L

        // 1. Permission NOT enabled -> never calls requestRebind
        assertFalse(
            AllNotifyListenerService.requestRebindIfNeeded(
                context = context,
                nowMs = { now },
                isEnabled = { false },
                triggerRebind = { rebindComponents.add(it) }
            )
        )
        assertEquals(0, rebindComponents.size)

        // 2. Permission enabled & disconnected -> calls requestRebind with AllNotifyListenerService
        assertTrue(
            AllNotifyListenerService.requestRebindIfNeeded(
                context = context,
                nowMs = { now },
                isEnabled = { true },
                triggerRebind = { rebindComponents.add(it) }
            )
        )
        assertEquals(1, rebindComponents.size)
        assertEquals(AllNotifyListenerService::class.java.name, rebindComponents[0].className)

        // 3. Repeat within 15s throttle window -> skipped
        now += 5_000L
        assertFalse(
            AllNotifyListenerService.requestRebindIfNeeded(
                context = context,
                nowMs = { now },
                isEnabled = { true },
                triggerRebind = { rebindComponents.add(it) }
            )
        )
        assertEquals(1, rebindComponents.size)

        // 4. force = true bypasses throttle
        assertTrue(
            AllNotifyListenerService.requestRebindIfNeeded(
                context = context,
                force = true,
                nowMs = { now },
                isEnabled = { true },
                triggerRebind = { rebindComponents.add(it) }
            )
        )
        assertEquals(2, rebindComponents.size)

        // 5. After 15s window expires -> allowed again
        now += 15_000L
        assertTrue(
            AllNotifyListenerService.requestRebindIfNeeded(
                context = context,
                nowMs = { now },
                isEnabled = { true },
                triggerRebind = { rebindComponents.add(it) }
            )
        )
        assertEquals(3, rebindComponents.size)

        // 6. When listener is already connected -> skipped even with force = true
        service.onListenerConnected()
        assertTrue(AllNotifyListenerService.isConnected())
        assertTrue(AllNotifyListenerService.connectedState.value)
        assertFalse(
            AllNotifyListenerService.requestRebindIfNeeded(
                context = context,
                force = true,
                nowMs = { now + 60_000L },
                isEnabled = { true },
                triggerRebind = { rebindComponents.add(it) }
            )
        )
        assertEquals(3, rebindComponents.size)

        // 7. Disconnecting clears connectedState back to false
        service.onListenerDisconnected()
        assertFalse(AllNotifyListenerService.isConnected())
        assertFalse(AllNotifyListenerService.connectedState.value)
    }
}
