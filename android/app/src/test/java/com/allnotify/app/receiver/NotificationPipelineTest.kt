package com.allnotify.app.receiver

import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import com.allnotify.app.crypto.CryptoEngine
import com.allnotify.app.crypto.PairingConfig
import com.allnotify.app.data.ActiveKeyMapEntity
import com.allnotify.app.data.AllNotifyDatabase
import com.allnotify.app.data.BlobCacheManager
import com.allnotify.app.data.NotificationEntity
import com.allnotify.app.protocol.AppInfoPayload
import com.allnotify.app.protocol.ContentPayload
import com.allnotify.app.protocol.EventFrame
import com.allnotify.app.protocol.NotificationDismissedPayload
import com.allnotify.app.protocol.NotificationPostedPayload
import com.allnotify.app.protocol.ReplayCompleteFrame
import com.allnotify.app.protocol.encodeDismissedPayload
import com.allnotify.app.protocol.encodePostedPayload
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.File

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class)
class NotificationPipelineTest {

    @get:Rule
    val tempFolder = TemporaryFolder()

    private lateinit var db: AllNotifyDatabase
    private lateinit var blobCache: BlobCacheManager
    private lateinit var crypto: CryptoEngine
    private lateinit var config: PairingConfig

    private val shownCalls = mutableListOf<Pair<NotificationEntity, Boolean>>()
    private val summaryCalls = mutableListOf<List<NotificationEntity>>()
    private val cancelledMirrored = mutableListOf<Long>()
    private val cancelledLocalSbnKeys = mutableListOf<String>()
    private val sentAcks = mutableListOf<Long>()
    private var dndBlocking = false
    private var clockMs = 1_764_060_000_000L

    private lateinit var pipeline: NotificationPipeline

    @Before
    fun setUp() {
        db = Room.inMemoryDatabaseBuilder(
            ApplicationProvider.getApplicationContext(),
            AllNotifyDatabase::class.java
        ).allowMainThreadQueries().build()
        blobCache = BlobCacheManager(tempFolder.newFolder("pipeline-cache"))

        val keyBytes = ByteArray(32) { it.toByte() }
        crypto = CryptoEngine(keyBytes)
        config = PairingConfig(
            version = 1,
            serverUrl = "https://notify.example.com",
            wsUrl = "wss://notify.example.com/v1/ws",
            token = "tok_self",
            keyBase64Url = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
            keyBytes = keyBytes,
            deviceId = "dev_SELF",
            deviceName = "Pixel Self"
        )

        val fakeDisplay = object : MirroredDisplayPort {
            override fun showNotification(
                entity: NotificationEntity,
                iconFile: File?,
                attachmentFile: File?,
                silentUpdate: Boolean
            ) {
                shownCalls.add(entity to silentUpdate)
            }

            override fun showReplaySummary(activeEntities: List<NotificationEntity>) {
                summaryCalls.add(activeEntities)
            }

            override fun cancelMirrored(notificationRowId: Long) {
                cancelledMirrored.add(notificationRowId)
            }

            override fun isOsDndBlocking(): Boolean = dndBlocking
        }

        val fakeBlobFetcher = object : BlobFetcher {
            override suspend fun fetchIcon(sha256: String, blobId: String): File? = null
            override suspend fun fetchAttachment(blobId: String, sha256: String): File? = null
        }

        val fakeRemoteCancel = object : RemoteCancelPort {
            override fun cancelLocalBySbnKey(sbnKey: String) {
                cancelledLocalSbnKeys.add(sbnKey)
            }
        }

        pipeline = NotificationPipeline(
            configProvider = { config },
            cryptoProvider = { crypto },
            database = db,
            blobCache = blobCache,
            blobFetcher = fakeBlobFetcher,
            displayPort = fakeDisplay,
            remoteCancelPort = fakeRemoteCancel,
            sendAck = { seq -> sentAcks.add(seq) },
            nowMs = { clockMs }
        )
    }

    @After
    fun tearDown() {
        db.close()
    }

    private fun makePostedEvent(
        seq: Long,
        eventId: String,
        senderDeviceId: String,
        senderName: String,
        uid: String,
        postedAt: Long,
        pkg: String = "com.whatsapp",
        title: String = "Alice",
        body: String = "Dinner at 7?"
    ): EventFrame {
        val payload = NotificationPostedPayload(
            notificationUid = uid,
            senderDeviceName = senderName,
            postedAt = postedAt,
            app = AppInfoPayload(packageName = pkg, name = "WhatsApp"),
            content = ContentPayload(title = title, body = body)
        )
        val ct = crypto.encryptEvent(eventId, senderDeviceId, encodePostedPayload(payload))
        return EventFrame(
            seq = seq,
            eventId = eventId,
            senderDeviceId = senderDeviceId,
            serverTs = postedAt,
            ciphertext = ct
        )
    }

    private fun makeDismissedEvent(
        seq: Long,
        eventId: String,
        senderDeviceId: String,
        uids: List<String>,
        dismissedAt: Long
    ): EventFrame {
        val payload = NotificationDismissedPayload(
            notificationUids = uids,
            dismissedAt = dismissedAt,
            dismissedByDeviceName = "MacBook"
        )
        val ct = crypto.encryptEvent(eventId, senderDeviceId, encodeDismissedPayload(payload))
        return EventFrame(
            seq = seq,
            eventId = eventId,
            senderDeviceId = senderDeviceId,
            serverTs = dismissedAt,
            ciphertext = ct
        )
    }

    @Test
    fun fiveSecondDedupMergesSendersAndUidsWithoutSecondPopup() = runBlocking {
        pipeline.onReplayStart()
        pipeline.onReplayComplete(ReplayCompleteFrame(latestSeq = 0))

        // Phone A posts at T=0
        pipeline.onEvent(makePostedEvent(1, "e1", "dev_A", "Phone A", "uid_A", clockMs))
        // Phone B posts identical content at T+3s (within 5s window)
        pipeline.onEvent(makePostedEvent(2, "e2", "dev_B", "Phone B", "uid_B", clockMs + 3_000L))

        assertEquals(1, db.notificationDao().count())
        assertEquals(2, shownCalls.size)
        assertFalse("first popup should alert", shownCalls[0].second)
        assertTrue("merged update must be silent", shownCalls[1].second)

        val merged = shownCalls[1].first
        assertEquals(listOf("uid_A", "uid_B"), Deduplicator.decodeStringList(merged.notificationUidsJson))
        assertEquals(listOf("Phone A", "Phone B"), Deduplicator.decodeStringList(merged.senderDevicesJson))

        // Phone C posts identical content at T+10s (outside 5s window) -> new row & popup
        pipeline.onEvent(makePostedEvent(3, "e3", "dev_C", "Phone C", "uid_C", clockMs + 10_000L))
        assertEquals(2, db.notificationDao().count())
        assertEquals(3, shownCalls.size)
        assertFalse("outside 5s window should alert", shownCalls[2].second)
    }

    @Test
    fun antiPopupStormReplayArchivesDismissedSilentlyAndPopsOnlyStillActive() = runBlocking {
        pipeline.onReplayStart()

        // 10 notifications arrive during replay
        for (i in 1..10) {
            pipeline.onEvent(
                makePostedEvent(
                    seq = i.toLong(),
                    eventId = "ev_p_$i",
                    senderDeviceId = "dev_A",
                    senderName = "Phone A",
                    uid = "uid_$i",
                    postedAt = clockMs + i * 1_000L,
                    title = "Msg $i",
                    body = "Body $i"
                )
            )
        }
        // 7 of them were already dismissed while offline
        for (i in 1..7) {
            pipeline.onEvent(
                makeDismissedEvent(
                    seq = (10 + i).toLong(),
                    eventId = "ev_d_$i",
                    senderDeviceId = "dev_A",
                    uids = listOf("uid_$i"),
                    dismissedAt = clockMs + 20_000L + i
                )
            )
        }

        // Before replay_complete: ZERO popups and ZERO acks!
        assertEquals(0, shownCalls.size)
        assertEquals(0, summaryCalls.size)
        assertEquals(0, sentAcks.size)

        pipeline.onReplayComplete(ReplayCompleteFrame(latestSeq = 17))

        // After replay_complete: all 10 persisted in history, ONLY 3 still-active pop up, single bulk ack!
        assertEquals(10, db.notificationDao().count())
        assertEquals(3, shownCalls.size)
        assertEquals(listOf("Msg 8", "Msg 9", "Msg 10"), shownCalls.map { it.first.title })
        assertEquals(listOf(17L), sentAcks)
        assertEquals(17L, db.getLastAckedSeq())
    }

    @Test
    fun replayCollapsesMoreThanFiveActiveIntoSingleSummary() = runBlocking {
        pipeline.onReplayStart()
        for (i in 1..8) {
            pipeline.onEvent(
                makePostedEvent(
                    seq = i.toLong(),
                    eventId = "ev_$i",
                    senderDeviceId = "dev_A",
                    senderName = "Phone A",
                    uid = "uid_$i",
                    postedAt = clockMs + i * 1_000L,
                    title = "Title $i",
                    body = "Body $i"
                )
            )
        }
        pipeline.onReplayComplete(ReplayCompleteFrame(latestSeq = 8))

        assertEquals(0, shownCalls.size)
        assertEquals(1, summaryCalls.size)
        assertEquals(8, summaryCalls[0].size)
        assertEquals(listOf(8L), sentAcks)
    }

    @Test
    fun remoteDismissCancelsLocalOriginatorAndClearsMirroredNotification() = runBlocking {
        pipeline.onReplayStart()
        pipeline.onReplayComplete(ReplayCompleteFrame(latestSeq = 0))

        // Local originator mapping on Phone A
        db.activeKeyMapDao().upsert(ActiveKeyMapEntity("uid_local_1", "0|com.whatsapp|42|null|100", clockMs))
        // Plus a mirrored notification from Phone B
        pipeline.onEvent(makePostedEvent(1, "e1", "dev_B", "Phone B", "uid_mirror_1", clockMs))
        val mirroredRowId = shownCalls.single().first.id

        // Remote dismiss clears both
        pipeline.onEvent(makeDismissedEvent(2, "e2", "dev_MAC", listOf("uid_local_1", "uid_mirror_1"), clockMs + 5_000L))

        assertEquals(listOf("0|com.whatsapp|42|null|100"), cancelledLocalSbnKeys)
        assertNull(db.activeKeyMapDao().findByUid("uid_local_1"))
        assertEquals(listOf(mirroredRowId), cancelledMirrored)
        assertNotNull(db.notificationDao().getById(mirroredRowId)?.dismissedAt)
    }

    @Test
    fun pauseAndOsDndSuppressPopupsWhileStillSavingHistoryAndAcking() = runBlocking {
        pipeline.onReplayStart()
        pipeline.onReplayComplete(ReplayCompleteFrame(latestSeq = 0))

        // Pause mode
        db.setPaused(true)
        pipeline.onEvent(makePostedEvent(1, "e1", "dev_A", "Phone A", "uid_1", clockMs))
        assertEquals(0, shownCalls.size)
        assertEquals(1, db.notificationDao().count())
        assertEquals(listOf(1L), sentAcks)

        // Unpause, enable OS DND
        db.setPaused(false)
        dndBlocking = true
        pipeline.onEvent(makePostedEvent(2, "e2", "dev_A", "Phone A", "uid_2", clockMs + 10_000L, title = "DND"))
        assertEquals(0, shownCalls.size)
        assertEquals(2, db.notificationDao().count())
        assertEquals(listOf(1L, 2L), sentAcks)
    }

    @Test
    fun tamperedCiphertextAndIdempotentDuplicateUidAreHandledSafely() = runBlocking {
        pipeline.onReplayStart()
        pipeline.onReplayComplete(ReplayCompleteFrame(latestSeq = 0))

        // Corrupted ciphertext must not crash pipeline and should ack live seq
        pipeline.onEvent(
            EventFrame(
                seq = 1,
                eventId = "bad_1",
                senderDeviceId = "dev_A",
                serverTs = clockMs,
                ciphertext = "A".repeat(64)
            )
        )
        assertEquals(0, db.notificationDao().count())
        assertEquals(listOf(1L), sentAcks)

        // Idempotent redelivery of same notification_uid
        pipeline.onEvent(makePostedEvent(2, "e2", "dev_A", "Phone A", "uid_same", clockMs))
        pipeline.onEvent(makePostedEvent(3, "e3", "dev_A", "Phone A", "uid_same", clockMs + 500L))
        assertEquals(1, db.notificationDao().count())
        assertEquals(1, shownCalls.size)
    }

    @Test
    fun interruptedReplayStillPopsActiveNotificationsOnReconnect() = runBlocking {
        // First connection receives seq 1 & 2 during replay, then disconnects BEFORE replay_complete!
        pipeline.onReplayStart()
        pipeline.onEvent(makePostedEvent(1, "e1", "dev_A", "Phone A", "uid_r1", clockMs, title = "First"))
        pipeline.onEvent(makePostedEvent(2, "e2", "dev_A", "Phone A", "uid_r2", clockMs + 1_000L, title = "Second"))
        assertEquals(0, shownCalls.size)
        assertEquals(0L, db.getLastAckedSeq())

        // Reconnect: server replays seq 1, seq 2, and a dismissal for uid_r1, then replay_complete(3).
        pipeline.onReplayStart()
        pipeline.onEvent(makePostedEvent(1, "e1", "dev_A", "Phone A", "uid_r1", clockMs, title = "First"))
        pipeline.onEvent(makePostedEvent(2, "e2", "dev_A", "Phone A", "uid_r2", clockMs + 1_000L, title = "Second"))
        pipeline.onEvent(makeDismissedEvent(3, "e3", "dev_A", listOf("uid_r1"), clockMs + 2_000L))
        pipeline.onReplayComplete(ReplayCompleteFrame(latestSeq = 3))

        // uid_r1 was dismissed silently; uid_r2 MUST pop up despite already being persisted in Room!
        assertEquals(2, db.notificationDao().count())
        assertEquals(listOf("Second"), shownCalls.map { it.first.title })
        assertEquals(listOf(3L), sentAcks)
    }

    @Test
    fun dedupMergingIntoLocalSentRowDoesNotPostRedundantMirroredPopup() = runBlocking {
        pipeline.onReplayStart()
        pipeline.onReplayComplete(ReplayCompleteFrame(latestSeq = 0))

        // Phone SELF already captured this WhatsApp notification locally (isMirrored = false).
        val dedupHash = Deduplicator.fingerprint("com.whatsapp", "Alice", "Dinner at 7?")
        val localRowId = db.notificationDao().insert(
            NotificationEntity(
                notificationUidsJson = Deduplicator.encodeStringList(listOf("uid_local")),
                senderDevicesJson = Deduplicator.encodeStringList(listOf("Pixel Self")),
                senderDeviceIdsJson = Deduplicator.encodeStringList(listOf("dev_SELF")),
                packageName = "com.whatsapp",
                appName = "WhatsApp",
                title = "Alice",
                body = "Dinner at 7?",
                dedupHash = dedupHash,
                postedAt = clockMs,
                isMirrored = false
            )
        )

        // 2s later Phone B relays the same WhatsApp notification.
        pipeline.onEvent(makePostedEvent(1, "e1", "dev_B", "Phone B", "uid_phoneB", clockMs + 2_000L))

        // Must merge into local row so dismissing clears both phones, WITHOUT popping a ghost mirrored banner!
        assertEquals(1, db.notificationDao().count())
        assertEquals(0, shownCalls.size)
        val merged = db.notificationDao().getById(localRowId)!!
        assertEquals(listOf("uid_local", "uid_phoneB"), Deduplicator.decodeStringList(merged.notificationUidsJson))
        assertEquals(listOf("Pixel Self", "Phone B"), Deduplicator.decodeStringList(merged.senderDevicesJson))
        assertFalse(merged.isMirrored)
    }

    @Test
    fun remoteDismissCleansAllActiveKeyMappingsSharingSameSbnKey() = runBlocking {
        pipeline.onReplayStart()
        pipeline.onReplayComplete(ReplayCompleteFrame(latestSeq = 0))

        val sharedKey = "0|com.whatsapp|1|null|1000"
        db.activeKeyMapDao().upsert(ActiveKeyMapEntity("uid_msg_1", sharedKey, clockMs))
        db.activeKeyMapDao().upsert(ActiveKeyMapEntity("uid_msg_2", sharedKey, clockMs + 1_000L))

        pipeline.onEvent(makeDismissedEvent(1, "e1", "dev_MAC", listOf("uid_msg_2"), clockMs + 5_000L))

        assertEquals(listOf(sharedKey), cancelledLocalSbnKeys)
        assertTrue(db.activeKeyMapDao().findBySbnKey(sharedKey).isEmpty())
    }
}
