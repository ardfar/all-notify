package com.allnotify.app.net

import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import com.allnotify.app.crypto.CryptoEngine
import com.allnotify.app.crypto.PairingConfig
import com.allnotify.app.data.AllNotifyDatabase
import com.allnotify.app.data.BlobCacheManager
import com.allnotify.app.data.OutboxEntity
import com.allnotify.app.protocol.EventFrame
import com.allnotify.app.protocol.ReplayCompleteFrame
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okio.ByteString
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okio.Buffer
import org.junit.After
import org.junit.Assert.assertArrayEquals
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

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class)
class RelayAndBlobClientTest {

    @get:Rule
    val tempFolder = TemporaryFolder()

    private lateinit var server: MockWebServer
    private lateinit var db: AllNotifyDatabase
    private lateinit var httpClient: OkHttpClient
    private lateinit var crypto: CryptoEngine
    private lateinit var config: PairingConfig

    @Before
    fun setUp() {
        server = MockWebServer()
        server.start()

        db = Room.inMemoryDatabaseBuilder(
            ApplicationProvider.getApplicationContext(),
            AllNotifyDatabase::class.java
        ).allowMainThreadQueries().build()

        httpClient = OkHttpClient()
        val keyBytes = ByteArray(32) { it.toByte() }
        crypto = CryptoEngine(keyBytes)

        val baseUrl = server.url("").toString().trimEnd('/')
        val wsUrl = baseUrl.replaceFirst("http://", "ws://") + "/v1/ws"
        config = PairingConfig(
            version = 1,
            serverUrl = baseUrl,
            wsUrl = wsUrl,
            token = "tok_test_123",
            keyBase64Url = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
            keyBytes = keyBytes,
            deviceId = "dev_ANDROID_1",
            deviceName = "Pixel 9"
        )
    }

    @After
    fun tearDown() {
        db.close()
        server.shutdown()
    }

    @Test
    fun blobIconUploadChecksHeadThenPutsEncryptedAndCachesHit() = runBlocking {
        val blobCache = BlobCacheManager(tempFolder.newFolder("blobs"))
        val client = BlobApiClient(httpClient)
        val iconPlaintext = "RIFF-FAKE-WEBP-ICON".toByteArray()
        val sha256 = BlobApiClient.sha256Hex(iconPlaintext)
        val expectedBlobId = "icon_${sha256.take(16)}"

        // First call: HEAD 404 -> PUT 201
        server.enqueue(MockResponse().setResponseCode(404))
        server.enqueue(MockResponse().setResponseCode(201))

        val blobId = client.ensureIconUploaded(config, crypto, blobCache, sha256, iconPlaintext)
        assertEquals(expectedBlobId, blobId)

        val headReq = server.takeRequest()
        assertEquals("HEAD", headReq.method)
        assertEquals("/v1/blobs/$expectedBlobId", headReq.path)
        assertEquals("Bearer tok_test_123", headReq.getHeader("Authorization"))

        val putReq = server.takeRequest()
        assertEquals("PUT", putReq.method)
        assertEquals("/v1/blobs/$expectedBlobId", putReq.path)
        val encryptedBytes = putReq.body.readByteArray()
        assertArrayEquals(iconPlaintext, crypto.decryptBlob(expectedBlobId, encryptedBytes))

        // Second call: local cache hit -> ZERO HTTP requests!
        val beforeCount = server.requestCount
        val cachedId = client.ensureIconUploaded(config, crypto, blobCache, sha256, iconPlaintext)
        assertEquals(expectedBlobId, cachedId)
        assertEquals(beforeCount, server.requestCount)
    }

    @Test
    fun blobDownloadDecryptsVerifiesSha256AndRejectsTamperedPlaintext() = runBlocking {
        val blobCache = BlobCacheManager(tempFolder.newFolder("blobs-dl"))
        val client = BlobApiClient(httpClient)

        val imgPlaintext = byteArrayOf(10, 20, 30, 40, 50)
        val sha256 = BlobApiClient.sha256Hex(imgPlaintext)
        val blobId = "img_01JABCDEF1234567890"
        val ct = crypto.encryptBlob(blobId, imgPlaintext)

        server.enqueue(MockResponse().setResponseCode(200).setBody(Buffer().write(ct)))
        val file = client.downloadAndCacheAttachment(config, crypto, blobCache, blobId, sha256)
        assertNotNull(file)
        assertArrayEquals(imgPlaintext, file!!.readBytes())

        // Second download hits disk cache (0 HTTP calls)
        val countAfterFirst = server.requestCount
        val cached = client.downloadAndCacheAttachment(config, crypto, blobCache, blobId, sha256)
        assertNotNull(cached)
        assertEquals(countAfterFirst, server.requestCount)

        // Wrong expected sha256 must fail verification
        val badBlobId = "img_01JABCDEF1234567891"
        val ct2 = crypto.encryptBlob(badBlobId, imgPlaintext)
        server.enqueue(MockResponse().setResponseCode(200).setBody(Buffer().write(ct2)))
        val rejected = client.downloadAndCacheAttachment(config, crypto, blobCache, badBlobId, "0".repeat(64))
        assertNull(rejected)

        // Oversize encrypted blob (>550KB) rejected before network
        assertFalse(
            client.putEncryptedBlob(
                config.serverUrl,
                config.token,
                "img_01JOVERSIZE00000001",
                ByteArray(BlobApiClient.MAX_ENCRYPTED_BLOB_BYTES + 1)
            )
        )
    }

    @Test
    fun relayWsClientSendsAuthHeadersFlushesOutboxReceivesReplayAndStopsOnRevoke() = runBlocking {
        db.setLastAckedSeq(12L)
        db.outboxDao().enqueue(OutboxEntity("evt_out_1", "B".repeat(64), System.currentTimeMillis()))

        val receivedOutboxFrame = CompletableDeferred<String>()
        val replayDone = CompletableDeferred<Long>()
        val gotEvent = CompletableDeferred<EventFrame>()
        val receivedAck = CompletableDeferred<String>()

        server.enqueue(
            MockResponse().withWebSocketUpgrade(object : WebSocketListener() {
                override fun onOpen(webSocket: WebSocket, response: Response) {
                    webSocket.send(
                        """{"op":"event","seq":13,"event_id":"evt_in_1","sender_device_id":"dev_OTHER","server_ts":1764060000000,"ciphertext":"${"C".repeat(64)}"}"""
                    )
                    webSocket.send("""{"op":"replay_complete","latest_seq":13}""")
                }

                override fun onMessage(webSocket: WebSocket, text: String) {
                    if (text.contains("\"op\":\"relay\"")) {
                        receivedOutboxFrame.complete(text)
                    } else if (text.contains("\"op\":\"ack\"")) {
                        receivedAck.complete(text)
                        webSocket.close(1008, "device revoked")
                    }
                }
            })
        )

        lateinit var wsClient: RelayWsClient
        val handler = object : RelayFrameHandler {
            override suspend fun onReplayStart() {}
            override suspend fun onEvent(frame: EventFrame) {
                gotEvent.complete(frame)
            }

            override suspend fun onReplayComplete(frame: ReplayCompleteFrame) {
                replayDone.complete(frame.latestSeq)
                wsClient.sendAck(frame.latestSeq)
            }
        }

        wsClient = RelayWsClient(
            httpClient = httpClient,
            database = db,
            handler = handler,
            backoffScheduleMs = longArrayOf(100L)
        )
        wsClient.start(config)

        try {
            val req = withTimeout(5_000L) { server.takeRequest() }
            assertEquals("/v1/ws?after_seq=12", req.path)
            assertEquals("Bearer tok_test_123", req.getHeader("Authorization"))
            assertEquals("1", req.getHeader("X-AllNotify-Protocol"))

            val outboxMsg = withTimeout(5_000L) { receivedOutboxFrame.await() }
            assertTrue(outboxMsg.contains("\"event_id\":\"evt_out_1\""))

            val ev = withTimeout(5_000L) { gotEvent.await() }
            assertEquals(13L, ev.seq)

            assertEquals(13L, withTimeout(5_000L) { replayDone.await() })
            val ackMsg = withTimeout(5_000L) { receivedAck.await() }
            assertTrue(ackMsg.contains("\"seq\":13"))

            // Wait for close code 1008 ("device revoked") to transition state to REVOKED
            withTimeout(5_000L) {
                while (wsClient.state.value != ConnectionState.REVOKED) {
                    kotlinx.coroutines.delay(25L)
                }
            }
            assertEquals(ConnectionState.REVOKED, wsClient.state.value)
            assertTrue("outbox should be empty after flush", db.outboxDao().listValid(0L).isEmpty())
        } finally {
            wsClient.shutdown()
        }
    }

    @Test
    fun triggerImmediateReconnectDropsActiveSocketAndSkipsLongBackoff() = runBlocking {
        val firstOpened = CompletableDeferred<Unit>()
        val secondOpened = CompletableDeferred<Unit>()

        server.enqueue(
            MockResponse().withWebSocketUpgrade(object : WebSocketListener() {
                override fun onOpen(webSocket: WebSocket, response: Response) {
                    webSocket.send("""{"op":"replay_complete","latest_seq":0}""")
                    firstOpened.complete(Unit)
                }

                override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
                    webSocket.close(1000, null)
                }
            })
        )
        server.enqueue(
            MockResponse().withWebSocketUpgrade(object : WebSocketListener() {
                override fun onOpen(webSocket: WebSocket, response: Response) {
                    webSocket.send("""{"op":"replay_complete","latest_seq":0}""")
                    secondOpened.complete(Unit)
                }

                override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
                    webSocket.close(1000, null)
                }
            })
        )

        val noopHandler = object : RelayFrameHandler {
            override suspend fun onReplayStart() {}
            override suspend fun onEvent(frame: EventFrame) {}
            override suspend fun onReplayComplete(frame: ReplayCompleteFrame) {}
        }

        // Huge 30s backoff: if triggerImmediateReconnect failed to drop active socket or skip backoff,
        // this test would time out in 3s.
        val wsClient = RelayWsClient(
            httpClient = httpClient,
            database = db,
            handler = noopHandler,
            backoffScheduleMs = longArrayOf(30_000L)
        )
        wsClient.start(config)
        try {
            withTimeout(3_000L) { firstOpened.await() }
            withTimeout(3_000L) {
                while (wsClient.state.value != ConnectionState.CONNECTED) {
                    kotlinx.coroutines.delay(15L)
                }
            }

            // Simulate Wi-Fi -> LTE handoff while socket is CONNECTED.
            wsClient.triggerImmediateReconnect(forceCloseActive = true)

            withTimeout(3_000L) { secondOpened.await() }
            assertEquals(2, server.requestCount)
        } finally {
            wsClient.shutdown()
        }
    }

    @Test
    fun outboxFlushAndLiveEnqueuePreserveStrictFifoWithoutDuplicates() = runBlocking {
        val now = System.currentTimeMillis()
        db.outboxDao().enqueue(OutboxEntity("evt_1", "A".repeat(64), now))
        db.outboxDao().enqueue(OutboxEntity("evt_2", "B".repeat(64), now + 1))

        val receivedIds = java.util.Collections.synchronizedList(mutableListOf<String>())
        val allThreeReceived = CompletableDeferred<Unit>()

        server.enqueue(
            MockResponse().withWebSocketUpgrade(object : WebSocketListener() {
                override fun onOpen(webSocket: WebSocket, response: Response) {
                    webSocket.send("""{"op":"replay_complete","latest_seq":0}""")
                }

                override fun onMessage(webSocket: WebSocket, text: String) {
                    val match = Regex("\"event_id\":\"([^\"]+)\"").find(text)
                    if (match != null) {
                        receivedIds.add(match.groupValues[1])
                        if (receivedIds.size >= 3) {
                            allThreeReceived.complete(Unit)
                        }
                    }
                }

                override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
                    webSocket.close(1000, null)
                }
            })
        )

        val noopHandler = object : RelayFrameHandler {
            override suspend fun onReplayStart() {}
            override suspend fun onEvent(frame: EventFrame) {}
            override suspend fun onReplayComplete(frame: ReplayCompleteFrame) {}
        }

        val wsClient = RelayWsClient(httpClient, db, noopHandler, backoffScheduleMs = longArrayOf(100L))
        wsClient.start(config)
        try {
            withTimeout(3_000L) {
                while (wsClient.state.value != ConnectionState.CONNECTED) {
                    kotlinx.coroutines.delay(15L)
                }
            }
            assertTrue(wsClient.enqueueAndSend("evt_3", "C".repeat(64)))
            withTimeout(3_000L) { allThreeReceived.await() }
            kotlinx.coroutines.delay(100L)

            assertEquals(listOf("evt_1", "evt_2", "evt_3"), receivedIds)
            assertTrue(db.outboxDao().listValid(0L).isEmpty())
        } finally {
            wsClient.shutdown()
        }
    }

    @Test
    fun fastOnOpenBeforeNewWebSocketReturnsStillConnectsAndFlushesOutbox() = runBlocking {
        db.outboxDao().enqueue(OutboxEntity("evt_fast_1", "D".repeat(64), System.currentTimeMillis()))

        val sentFrames = java.util.Collections.synchronizedList(mutableListOf<String>())
        val outboxFlushed = CompletableDeferred<Unit>()
        val liveSent = CompletableDeferred<Unit>()
        val onOpenFiredBeforeReturn = CompletableDeferred<Unit>()

        val racingHttpClient = object : OkHttpClient() {
            override fun newWebSocket(request: Request, listener: WebSocketListener): WebSocket {
                val fakeWs = object : WebSocket {
                    override fun request(): Request = request
                    override fun queueSize(): Long = 0L
                    override fun send(text: String): Boolean {
                        sentFrames.add(text)
                        if (text.contains("\"event_id\":\"evt_fast_1\"")) {
                            outboxFlushed.complete(Unit)
                        }
                        if (text.contains("\"event_id\":\"evt_fast_2\"")) {
                            liveSent.complete(Unit)
                        }
                        return true
                    }

                    override fun send(bytes: ByteString): Boolean = true
                    override fun close(code: Int, reason: String?): Boolean {
                        listener.onClosed(this, code, reason.orEmpty())
                        return true
                    }

                    override fun cancel() {
                        listener.onFailure(this, java.io.IOException("cancelled"), null)
                    }
                }
                val fakeResp = Response.Builder()
                    .request(request)
                    .protocol(Protocol.HTTP_1_1)
                    .code(101)
                    .message("Switching Protocols")
                    .build()
                // Fire onOpen on another thread and stall before returning fakeWs so onOpen
                // deterministically races ahead of newWebSocket's return.
                Thread {
                    listener.onOpen(fakeWs, fakeResp)
                    onOpenFiredBeforeReturn.complete(Unit)
                }.start()
                while (!onOpenFiredBeforeReturn.isCompleted) {
                    Thread.sleep(5L)
                }
                Thread.sleep(60L)
                return fakeWs
            }
        }

        val noopHandler = object : RelayFrameHandler {
            override suspend fun onReplayStart() {}
            override suspend fun onEvent(frame: EventFrame) {}
            override suspend fun onReplayComplete(frame: ReplayCompleteFrame) {}
        }

        val wsClient = RelayWsClient(
            httpClient = racingHttpClient,
            database = db,
            handler = noopHandler,
            backoffScheduleMs = longArrayOf(100L)
        )
        wsClient.start(config)
        try {
            withTimeout(3_000L) {
                while (wsClient.state.value != ConnectionState.CONNECTED) {
                    kotlinx.coroutines.delay(15L)
                }
            }
            withTimeout(3_000L) { outboxFlushed.await() }
            assertTrue(wsClient.enqueueAndSend("evt_fast_2", "E".repeat(64)))
            withTimeout(3_000L) { liveSent.await() }
            assertTrue(db.outboxDao().listValid(0L).isEmpty())
            assertEquals(2, sentFrames.size)
        } finally {
            wsClient.shutdown()
        }
    }

    @Test
    fun immediateReplayCompleteAfterOnOpenStillSendsAck() = runBlocking {
        val ackReceived = CompletableDeferred<String>()
        val replayCompleteProcessed = CompletableDeferred<Boolean>()

        val immediateReplayHttpClient = object : OkHttpClient() {
            override fun newWebSocket(request: Request, listener: WebSocketListener): WebSocket {
                val fakeWs = object : WebSocket {
                    override fun request(): Request = request
                    override fun queueSize(): Long = 0L
                    override fun send(text: String): Boolean {
                        if (text.contains("\"op\":\"ack\"")) {
                            ackReceived.complete(text)
                        }
                        return true
                    }

                    override fun send(bytes: ByteString): Boolean = true
                    override fun close(code: Int, reason: String?): Boolean {
                        listener.onClosed(this, code, reason.orEmpty())
                        return true
                    }

                    override fun cancel() {
                        listener.onFailure(this, java.io.IOException("cancelled"), null)
                    }
                }
                val fakeResp = Response.Builder()
                    .request(request)
                    .protocol(Protocol.HTTP_1_1)
                    .code(101)
                    .message("Switching Protocols")
                    .build()
                // Fire onOpen and immediately onMessage(replay_complete) back-to-back on OkHttp thread.
                Thread {
                    listener.onOpen(fakeWs, fakeResp)
                    listener.onMessage(fakeWs, """{"op":"replay_complete","latest_seq":99}""")
                }.start()
                return fakeWs
            }
        }

        lateinit var wsClient: RelayWsClient
        val handler = object : RelayFrameHandler {
            override suspend fun onReplayStart() {}
            override suspend fun onEvent(frame: EventFrame) {}
            override suspend fun onReplayComplete(frame: ReplayCompleteFrame) {
                val ok = wsClient.sendAck(frame.latestSeq)
                replayCompleteProcessed.complete(ok)
            }
        }

        wsClient = RelayWsClient(
            httpClient = immediateReplayHttpClient,
            database = db,
            handler = handler,
            backoffScheduleMs = longArrayOf(100L)
        )
        wsClient.start(config)
        try {
            assertTrue("sendAck during immediate replay_complete must succeed", withTimeout(3_000L) { replayCompleteProcessed.await() })
            val ackJson = withTimeout(3_000L) { ackReceived.await() }
            assertTrue(ackJson.contains("\"seq\":99"))
        } finally {
            wsClient.shutdown()
        }
    }

    @Test
    fun stopDuringNewWebSocketCancelsStaleSocketAndNeverSticksConnected() = runBlocking {
        val enteredNewWs = CompletableDeferred<Unit>()
        val allowReturn = CompletableDeferred<Unit>()
        val staleCancelled = CompletableDeferred<Unit>()

        val stallingHttpClient = object : OkHttpClient() {
            override fun newWebSocket(request: Request, listener: WebSocketListener): WebSocket {
                val fakeWs = object : WebSocket {
                    override fun request(): Request = request
                    override fun queueSize(): Long = 0L
                    override fun send(text: String): Boolean = true
                    override fun send(bytes: ByteString): Boolean = true
                    override fun close(code: Int, reason: String?): Boolean = true
                    override fun cancel() {
                        staleCancelled.complete(Unit)
                    }
                }
                val fakeResp = Response.Builder()
                    .request(request)
                    .protocol(Protocol.HTTP_1_1)
                    .code(101)
                    .message("Switching Protocols")
                    .build()
                enteredNewWs.complete(Unit)
                runBlocking { allowReturn.await() }
                // Even if onOpen fires right after stop(), state must NOT flip back to CONNECTED.
                listener.onOpen(fakeWs, fakeResp)
                return fakeWs
            }
        }

        val noopHandler = object : RelayFrameHandler {
            override suspend fun onReplayStart() {}
            override suspend fun onEvent(frame: EventFrame) {}
            override suspend fun onReplayComplete(frame: ReplayCompleteFrame) {}
        }

        val wsClient = RelayWsClient(
            httpClient = stallingHttpClient,
            database = db,
            handler = noopHandler,
            backoffScheduleMs = longArrayOf(100L)
        )
        wsClient.start(config)
        try {
            withTimeout(3_000L) { enteredNewWs.await() }
            wsClient.stop()
            allowReturn.complete(Unit)

            withTimeout(3_000L) { staleCancelled.await() }
            kotlinx.coroutines.delay(100L)
            assertEquals(ConnectionState.DISCONNECTED, wsClient.state.value)
            assertFalse("stopped client must not have an activeSocket", wsClient.sendAck(1L))
        } finally {
            wsClient.shutdown()
        }
    }
}
