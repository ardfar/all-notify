package com.allnotify.app.net

import android.app.Application
import android.graphics.Bitmap
import android.graphics.Color
import android.graphics.drawable.BitmapDrawable
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import com.allnotify.app.crypto.CryptoEngine
import com.allnotify.app.crypto.PairingConfig
import com.allnotify.app.crypto.PairingLink
import com.allnotify.app.crypto.PairingUriParser
import com.allnotify.app.crypto.Ulid
import com.allnotify.app.ui.QrCodeGenerator
import com.google.zxing.BinaryBitmap
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader
import com.allnotify.app.data.ActiveKeyMapEntity
import com.allnotify.app.data.AllNotifyDatabase
import com.allnotify.app.data.BlobCacheManager
import com.allnotify.app.data.NotificationEntity
import com.allnotify.app.protocol.AppInfoPayload
import com.allnotify.app.protocol.AttachmentPayload
import com.allnotify.app.protocol.ContentPayload
import com.allnotify.app.protocol.NotificationDismissedPayload
import com.allnotify.app.protocol.NotificationPostedPayload
import com.allnotify.app.protocol.encodeDismissedPayload
import com.allnotify.app.protocol.encodePostedPayload
import com.allnotify.app.receiver.BlobFetcher
import com.allnotify.app.receiver.Deduplicator
import com.allnotify.app.receiver.MirroredDisplayPort
import com.allnotify.app.receiver.NotificationPipeline
import com.allnotify.app.receiver.RemoteCancelPort
import com.allnotify.app.service.MediaProcessor
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import okhttp3.OkHttpClient
import okhttp3.Request
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.File
import java.net.ServerSocket
import java.util.concurrent.TimeUnit

/**
 * End-to-end cross-language integration test exercising TWO Kotlin Android client pipelines
 * (Phone A <-> Phase 1 Go all-notify-server <-> Phone B):
 *  - CLI keygen + token create -> PairingUriParser
 *  - E2EE icon + image blob upload (HEAD/PUT) & download/decrypt/verify (GET)
 *  - Live E2EE notification.posted fan-out
 *  - Two-way E2EE notification.dismissed cancelling Phone A's local sbn.key
 *  - CLI token revoke immediately disconnecting Phone B
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = Application::class)
class GoServerInteropTest {

    @get:Rule
    val tempFolder = TemporaryFolder()

    private fun findServerDir(): File? = listOf(
        File("../../server"),
        File("../server"),
        File("server")
    ).firstOrNull { File(it, "go.mod").exists() }

    private fun runCmd(dir: File, vararg args: String): String {
        val proc = ProcessBuilder(*args)
            .directory(dir)
            .redirectErrorStream(true)
            .start()
        val output = proc.inputStream.bufferedReader().readText()
        val code = proc.waitFor()
        if (code != 0) error("Command ${args.joinToString(" ")} exited $code:\n$output")
        return output
    }

    @Test
    fun bidirectionalMirroringBlobsDismissAndRevokeAgainstRealGoServer() = runBlocking {
        val serverDir = findServerDir()
        Assume.assumeNotNull("server/ directory not found", serverDir)
        val goAvailable = runCatching { runCmd(serverDir!!, "go", "version") }.isSuccess
        Assume.assumeTrue("go toolchain not available", goAvailable)

        val workDir = tempFolder.newFolder("go-interop")
        val exeSuffix = if (System.getProperty("os.name").orEmpty().lowercase().contains("win")) ".exe" else ""
        val binFile = File(workDir, "all-notify-server$exeSuffix")
        val dataDir = File(workDir, "data").apply { mkdirs() }

        // Build Phase 1 Go server binary
        runCmd(serverDir!!, "go", "build", "-o", binFile.absolutePath, "./cmd/all-notify-server")

        val kMasterB64 = runCmd(workDir, binFile.absolutePath, "keygen").trim()
        val port = ServerSocket(0).use { it.localPort }
        val httpBase = "http://127.0.0.1:$port"

        // Mint real tokens via CLI and validate v1 pairing URIs through Kotlin PairingUriParser!
        fun mintDevice(name: String): PairingConfig {
            val out = runCmd(
                workDir,
                binFile.absolutePath,
                "token", "create",
                "--data-dir", dataDir.absolutePath,
                "--name", name,
                "--platform", "android"
            )
            val devId = out.lines().first { it.startsWith("Device ID:") }.substringAfter(":").trim()
            val token = out.lines().first { it.startsWith("Token:") }.substringAfter(":").trim()
            val v1Uri = PairingUriParser.encode(
                PairingConfig(
                    version = 1,
                    serverUrl = "https://127.0.0.1:$port",
                    wsUrl = "wss://127.0.0.1:$port/v1/ws",
                    token = token,
                    keyBase64Url = kMasterB64,
                    keyBytes = java.util.Base64.getUrlDecoder().decode(kMasterB64),
                    deviceId = devId,
                    deviceName = name
                )
            )
            val parsed = PairingUriParser.parse(v1Uri).getOrThrow()
            // Redirect to local plain HTTP/WS test listener while keeping parsed deviceId/token/key intact
            return parsed.copy(
                serverUrl = httpBase,
                wsUrl = "ws://127.0.0.1:$port/v1/ws"
            )
        }

        val cfgA = mintDevice("Phone A")
        val cfgB = mintDevice("Phone B")
        val cryptoA = CryptoEngine(cfgA.keyBytes)
        val cryptoB = CryptoEngine(cfgB.keyBytes)

        // Start real Go relay server
        val serverProc = ProcessBuilder(
            binFile.absolutePath,
            "serve",
            "--addr", "127.0.0.1:$port",
            "--data-dir", dataDir.absolutePath
        ).redirectErrorStream(true).start()

        val httpClient = OkHttpClient.Builder().readTimeout(0, TimeUnit.MILLISECONDS).build()
        val blobClient = BlobApiClient(httpClient)
        val dbA = Room.inMemoryDatabaseBuilder(ApplicationProvider.getApplicationContext(), AllNotifyDatabase::class.java)
            .allowMainThreadQueries().build()
        val dbB = Room.inMemoryDatabaseBuilder(ApplicationProvider.getApplicationContext(), AllNotifyDatabase::class.java)
            .allowMainThreadQueries().build()
        val cacheA = BlobCacheManager(File(workDir, "cacheA"))
        val cacheB = BlobCacheManager(File(workDir, "cacheB"))

        val phoneBShown = CompletableDeferred<Triple<NotificationEntity, File?, File?>>()
        val phoneACancelledSbn = CompletableDeferred<String>()

        lateinit var wsA: RelayWsClient
        lateinit var wsB: RelayWsClient

        try {
            // Wait for /healthz
            withTimeout(10_000L) {
                while (true) {
                    val ok = runCatching {
                        httpClient.newCall(Request.Builder().url("$httpBase/healthz").build()).execute().use { it.isSuccessful }
                    }.getOrDefault(false)
                    if (ok) break
                    delay(50L)
                }
            }

            fun makeFetcher(cfg: PairingConfig, crypto: CryptoEngine, cache: BlobCacheManager) = object : BlobFetcher {
                override suspend fun fetchIcon(sha256: String, blobId: String): File? =
                    blobClient.downloadAndCacheIcon(cfg, crypto, cache, sha256, blobId)
                override suspend fun fetchAttachment(blobId: String, sha256: String): File? =
                    blobClient.downloadAndCacheAttachment(cfg, crypto, cache, blobId, sha256)
            }

            val pipeA = NotificationPipeline(
                configProvider = { cfgA },
                cryptoProvider = { cryptoA },
                database = dbA,
                blobCache = cacheA,
                blobFetcher = makeFetcher(cfgA, cryptoA, cacheA),
                displayPort = object : MirroredDisplayPort {
                    override fun showNotification(entity: NotificationEntity, iconFile: File?, attachmentFile: File?, silentUpdate: Boolean) {}
                    override fun showReplaySummary(activeEntities: List<NotificationEntity>) {}
                    override fun cancelMirrored(notificationRowId: Long) {}
                    override fun isOsDndBlocking(): Boolean = false
                },
                remoteCancelPort = object : RemoteCancelPort {
                    override fun cancelLocalBySbnKey(sbnKey: String) {
                        phoneACancelledSbn.complete(sbnKey)
                    }
                },
                sendAck = { seq -> wsA.sendAck(seq) }
            )

            val pipeB = NotificationPipeline(
                configProvider = { cfgB },
                cryptoProvider = { cryptoB },
                database = dbB,
                blobCache = cacheB,
                blobFetcher = makeFetcher(cfgB, cryptoB, cacheB),
                displayPort = object : MirroredDisplayPort {
                    override fun showNotification(entity: NotificationEntity, iconFile: File?, attachmentFile: File?, silentUpdate: Boolean) {
                        phoneBShown.complete(Triple(entity, iconFile, attachmentFile))
                    }
                    override fun showReplaySummary(activeEntities: List<NotificationEntity>) {}
                    override fun cancelMirrored(notificationRowId: Long) {}
                    override fun isOsDndBlocking(): Boolean = false
                },
                remoteCancelPort = object : RemoteCancelPort {
                    override fun cancelLocalBySbnKey(sbnKey: String) {}
                },
                sendAck = { seq -> wsB.sendAck(seq) }
            )

            wsA = RelayWsClient(httpClient, dbA, pipeA, backoffScheduleMs = longArrayOf(200L))
            wsB = RelayWsClient(httpClient, dbB, pipeB, backoffScheduleMs = longArrayOf(200L))
            wsA.start(cfgA)
            wsB.start(cfgB)

            withTimeout(5_000L) {
                while (wsA.state.value != ConnectionState.CONNECTED || wsB.state.value != ConnectionState.CONNECTED) {
                    delay(25L)
                }
            }
            // Give replay_complete a brief moment to settle
            delay(150L)

            // 1. Phone A uploads encrypted icon + encrypted image blob to real Go server
            val iconBytes = "FAKE-WEBP-ICON-64x64".toByteArray()
            val iconSha = BlobApiClient.sha256Hex(iconBytes)
            val iconBlobId = blobClient.ensureIconUploaded(cfgA, cryptoA, cacheA, iconSha, iconBytes)
            assertNotNull(iconBlobId)

            val imgBytes = "FAKE-WEBP-PHOTO-800x600".toByteArray()
            val imgSha = BlobApiClient.sha256Hex(imgBytes)
            val imgBlobId = "img_${Ulid.generate()}"
            assertTrue(blobClient.uploadImageAttachment(cfgA, cryptoA, imgBlobId, imgBytes))

            // 2. Phone A records active_key_map and sends encrypted notification.posted
            val now = System.currentTimeMillis()
            val notifUid = "${cfgA.deviceId}:$now:abc123"
            dbA.activeKeyMapDao().upsert(ActiveKeyMapEntity(notifUid, "0|com.whatsapp|99|null|1000", now))

            val posted = NotificationPostedPayload(
                notificationUid = notifUid,
                senderDeviceName = cfgA.deviceName,
                postedAt = now,
                app = AppInfoPayload("com.whatsapp", "WhatsApp", iconSha, iconBlobId),
                content = ContentPayload(title = "Alice", body = "See you at 7!"),
                attachments = listOf(AttachmentPayload("image", imgBlobId, "image/webp", 800, 600, imgBytes.size, imgSha))
            )
            val eventId1 = Ulid.generate(now)
            val ct1 = cryptoA.encryptEvent(eventId1, cfgA.deviceId, encodePostedPayload(posted))
            assertTrue(wsA.enqueueAndSend(eventId1, ct1))

            // 3. Phone B receives, decrypts, downloads & decrypts both blobs!
            val (entityB, iconFileB, imgFileB) = withTimeout(5_000L) { phoneBShown.await() }
            assertEquals("Alice", entityB.title)
            assertEquals("See you at 7!", entityB.body)
            assertNotNull(iconFileB)
            assertNotNull(imgFileB)
            assertArrayEquals(iconBytes, iconFileB!!.readBytes())
            assertArrayEquals(imgBytes, imgFileB!!.readBytes())

            // 4. Phone B sends encrypted notification.dismissed -> Phone A cancels its sbn.key!
            val dismissed = NotificationDismissedPayload(
                notificationUids = listOf(notifUid),
                dismissedAt = now + 1_000L,
                dismissedByDeviceName = cfgB.deviceName
            )
            val eventId2 = Ulid.generate(now + 1_000L)
            val ct2 = cryptoB.encryptEvent(eventId2, cfgB.deviceId, encodeDismissedPayload(dismissed))
            assertTrue(wsB.enqueueAndSend(eventId2, ct2))

            assertEquals("0|com.whatsapp|99|null|1000", withTimeout(5_000L) { phoneACancelledSbn.await() })

            // 5. Revoke Phone B via real Go CLI -> Go revocation watcher disconnects Phone B -> REVOKED!
            runCmd(workDir, binFile.absolutePath, "token", "revoke", "--data-dir", dataDir.absolutePath, cfgB.deviceId)
            withTimeout(5_000L) {
                while (wsB.state.value != ConnectionState.REVOKED) {
                    delay(50L)
                }
            }
            assertEquals(ConnectionState.REVOKED, wsB.state.value)
        } finally {
            runCatching { wsA.shutdown() }
            runCatching { wsB.shutdown() }
            dbA.close()
            dbB.close()
            serverProc.destroyForcibly()
        }
    }

    @Test
    fun phase4MatrixMediaIconCacheDedupOfflineReplayAndNoEcho() = runBlocking {
        val serverDir = findServerDir()
        Assume.assumeNotNull("server/ directory not found", serverDir)
        val goAvailable = runCatching { runCmd(serverDir!!, "go", "version") }.isSuccess
        Assume.assumeTrue("go toolchain not available", goAvailable)

        val workDir = tempFolder.newFolder("go-phase4-matrix")
        val exeSuffix = if (System.getProperty("os.name").orEmpty().lowercase().contains("win")) ".exe" else ""
        val binFile = File(workDir, "all-notify-server$exeSuffix")
        val dataDir = File(workDir, "data").apply { mkdirs() }
        runCmd(serverDir!!, "go", "build", "-o", binFile.absolutePath, "./cmd/all-notify-server")

        val kMasterB64 = runCmd(workDir, binFile.absolutePath, "keygen").trim()
        val port = ServerSocket(0).use { it.localPort }
        val httpBase = "http://127.0.0.1:$port"

        fun mintDevice(name: String): PairingConfig {
            val out = runCmd(
                workDir,
                binFile.absolutePath,
                "token", "create",
                "--data-dir", dataDir.absolutePath,
                "--name", name,
                "--platform", "android"
            )
            val devId = out.lines().first { it.startsWith("Device ID:") }.substringAfter(":").trim()
            val token = out.lines().first { it.startsWith("Token:") }.substringAfter(":").trim()
            val v1Uri = PairingUriParser.encode(
                PairingConfig(
                    version = 1,
                    serverUrl = "https://127.0.0.1:$port",
                    wsUrl = "wss://127.0.0.1:$port/v1/ws",
                    token = token,
                    keyBase64Url = kMasterB64,
                    keyBytes = java.util.Base64.getUrlDecoder().decode(kMasterB64),
                    deviceId = devId,
                    deviceName = name
                )
            )
            val parsed = PairingUriParser.parse(v1Uri).getOrThrow()
            return parsed.copy(serverUrl = httpBase, wsUrl = "ws://127.0.0.1:$port/v1/ws")
        }

        val cfgA = mintDevice("Phone A")
        val cfgB = mintDevice("Phone B")
        val cfgC = mintDevice("Phone C")
        val crypto = CryptoEngine(cfgA.keyBytes)

        val serverProc = ProcessBuilder(
            binFile.absolutePath, "serve", "--addr", "127.0.0.1:$port", "--data-dir", dataDir.absolutePath
        ).redirectErrorStream(true).start()

        val httpClient = OkHttpClient.Builder().readTimeout(0, TimeUnit.MILLISECONDS).build()
        val blobClient = BlobApiClient(httpClient)
        val ctx = ApplicationProvider.getApplicationContext<Application>()
        val dbA = Room.inMemoryDatabaseBuilder(ctx, AllNotifyDatabase::class.java).allowMainThreadQueries().build()
        val dbB = Room.inMemoryDatabaseBuilder(ctx, AllNotifyDatabase::class.java).allowMainThreadQueries().build()
        val dbC = Room.inMemoryDatabaseBuilder(ctx, AllNotifyDatabase::class.java).allowMainThreadQueries().build()
        val cacheA = BlobCacheManager(File(workDir, "cacheA"))
        val cacheB = BlobCacheManager(File(workDir, "cacheB"))
        val cacheC = BlobCacheManager(File(workDir, "cacheC"))

        val phoneACancelled = mutableListOf<String>()
        val phoneBCancelled = mutableListOf<String>()
        val phoneBShown = mutableListOf<Triple<NotificationEntity, File?, File?>>()
        val phoneBReplaySummaries = mutableListOf<List<NotificationEntity>>()
        val phoneBRemovedMirrored = mutableListOf<Long>()
        val phoneCShown = mutableListOf<Pair<NotificationEntity, Boolean>>()

        lateinit var wsA: RelayWsClient
        lateinit var wsB: RelayWsClient
        lateinit var wsC: RelayWsClient

        try {
            withTimeout(10_000L) {
                while (true) {
                    val ok = runCatching {
                        httpClient.newCall(Request.Builder().url("$httpBase/healthz").build()).execute().use { it.isSuccessful }
                    }.getOrDefault(false)
                    if (ok) break
                    delay(50L)
                }
            }

            fun makeFetcher(cfg: PairingConfig, cache: BlobCacheManager) = object : BlobFetcher {
                override suspend fun fetchIcon(sha256: String, blobId: String): File? =
                    blobClient.downloadAndCacheIcon(cfg, crypto, cache, sha256, blobId)
                override suspend fun fetchAttachment(blobId: String, sha256: String): File? =
                    blobClient.downloadAndCacheAttachment(cfg, crypto, cache, blobId, sha256)
            }

            val pipeA = NotificationPipeline(
                configProvider = { cfgA }, cryptoProvider = { crypto }, database = dbA,
                blobCache = cacheA, blobFetcher = makeFetcher(cfgA, cacheA),
                displayPort = object : MirroredDisplayPort {
                    override fun showNotification(entity: NotificationEntity, iconFile: File?, attachmentFile: File?, silentUpdate: Boolean) {}
                    override fun showReplaySummary(activeEntities: List<NotificationEntity>) {}
                    override fun cancelMirrored(notificationRowId: Long) {}
                    override fun isOsDndBlocking(): Boolean = false
                },
                remoteCancelPort = object : RemoteCancelPort {
                    override fun cancelLocalBySbnKey(sbnKey: String) { synchronized(phoneACancelled) { phoneACancelled.add(sbnKey) } }
                },
                sendAck = { seq -> wsA.sendAck(seq) }
            )
            val pipeB = NotificationPipeline(
                configProvider = { cfgB }, cryptoProvider = { crypto }, database = dbB,
                blobCache = cacheB, blobFetcher = makeFetcher(cfgB, cacheB),
                displayPort = object : MirroredDisplayPort {
                    override fun showNotification(entity: NotificationEntity, iconFile: File?, attachmentFile: File?, silentUpdate: Boolean) {
                        synchronized(phoneBShown) { phoneBShown.add(Triple(entity, iconFile, attachmentFile)) }
                    }
                    override fun showReplaySummary(activeEntities: List<NotificationEntity>) {
                        synchronized(phoneBReplaySummaries) { phoneBReplaySummaries.add(activeEntities) }
                    }
                    override fun cancelMirrored(notificationRowId: Long) {
                        synchronized(phoneBRemovedMirrored) { phoneBRemovedMirrored.add(notificationRowId) }
                    }
                    override fun isOsDndBlocking(): Boolean = false
                },
                remoteCancelPort = object : RemoteCancelPort {
                    override fun cancelLocalBySbnKey(sbnKey: String) { synchronized(phoneBCancelled) { phoneBCancelled.add(sbnKey) } }
                },
                sendAck = { seq -> wsB.sendAck(seq) }
            )
            val pipeC = NotificationPipeline(
                configProvider = { cfgC }, cryptoProvider = { crypto }, database = dbC,
                blobCache = cacheC, blobFetcher = makeFetcher(cfgC, cacheC),
                displayPort = object : MirroredDisplayPort {
                    override fun showNotification(entity: NotificationEntity, iconFile: File?, attachmentFile: File?, silentUpdate: Boolean) {
                        synchronized(phoneCShown) { phoneCShown.add(entity to silentUpdate) }
                    }
                    override fun showReplaySummary(activeEntities: List<NotificationEntity>) {}
                    override fun cancelMirrored(notificationRowId: Long) {}
                    override fun isOsDndBlocking(): Boolean = false
                },
                remoteCancelPort = object : RemoteCancelPort {
                    override fun cancelLocalBySbnKey(sbnKey: String) {}
                },
                sendAck = { seq -> wsC.sendAck(seq) }
            )

            wsA = RelayWsClient(httpClient, dbA, pipeA, backoffScheduleMs = longArrayOf(200L))
            wsB = RelayWsClient(httpClient, dbB, pipeB, backoffScheduleMs = longArrayOf(200L))
            wsC = RelayWsClient(httpClient, dbC, pipeC, backoffScheduleMs = longArrayOf(200L))
            wsA.start(cfgA); wsB.start(cfgB); wsC.start(cfgC)

            withTimeout(5_000L) {
                while (wsA.state.value != ConnectionState.CONNECTED ||
                    wsB.state.value != ConnectionState.CONNECTED ||
                    wsC.state.value != ConnectionState.CONNECTED
                ) {
                    delay(25L)
                }
            }
            delay(150L)

            // 1. Real MediaProcessor 64x64 WebP icon + downscaled <=800px/<=512KB photo + icon cache hit!
            val rawIconBmp = Bitmap.createBitmap(128, 128, Bitmap.Config.ARGB_8888).apply { eraseColor(Color.BLUE) }
            val encodedIcon = MediaProcessor.encodeAppIcon(BitmapDrawable(ctx.resources, rawIconBmp))
            assertNotNull(encodedIcon)
            val rawPhotoBmp = Bitmap.createBitmap(1600, 1200, Bitmap.Config.ARGB_8888).apply { eraseColor(Color.GREEN) }
            val encodedPhoto = MediaProcessor.compressImageAttachment(rawPhotoBmp)
            assertNotNull(encodedPhoto)
            assertTrue(encodedPhoto!!.width <= 800 && encodedPhoto.height <= 800)
            assertTrue(encodedPhoto.bytes.size <= 512 * 1024)

            val iconBlobId = blobClient.ensureIconUploaded(cfgA, crypto, cacheA, encodedIcon!!.sha256, encodedIcon.bytes)
            assertNotNull(iconBlobId)
            val imgBlobId = "img_${Ulid.generate()}"
            assertTrue(blobClient.uploadImageAttachment(cfgA, crypto, imgBlobId, encodedPhoto.bytes))

            val t0 = System.currentTimeMillis()
            val uidMedia = "${cfgA.deviceId}:$t0:media1"
            val postedMedia = NotificationPostedPayload(
                notificationUid = uidMedia,
                senderDeviceName = cfgA.deviceName,
                postedAt = t0,
                app = AppInfoPayload("com.whatsapp", "WhatsApp", encodedIcon.sha256, iconBlobId),
                content = ContentPayload("Alice", "Photo attached"),
                attachments = listOf(AttachmentPayload("image", imgBlobId, encodedPhoto.mime, encodedPhoto.width, encodedPhoto.height, encodedPhoto.bytes.size, encodedPhoto.sha256))
            )
            val evMedia1 = Ulid.generate(t0)
            wsA.enqueueAndSend(evMedia1, crypto.encryptEvent(evMedia1, cfgA.deviceId, encodePostedPayload(postedMedia)))
            // Wait for Phone B to receive media notification and cache icon + photo.
            withTimeout(5_000L) {
                while (synchronized(phoneBShown) { phoneBShown.size } < 1) delay(25L)
            }
            val (firstEntityB, firstIconB, firstImgB) = synchronized(phoneBShown) { phoneBShown[0] }
            assertArrayEquals(encodedIcon.bytes, firstIconB!!.readBytes())
            assertArrayEquals(encodedPhoto.bytes, firstImgB!!.readBytes())

            // Delete icon blob from VPS disk; 2nd notification MUST still resolve icon from local caches with 0 PUT/GET!
            val serverIconFile = File(File(dataDir, "blobs"), "$iconBlobId.bin")
            assertTrue(serverIconFile.delete())
            assertEquals(iconBlobId, blobClient.ensureIconUploaded(cfgA, crypto, cacheA, encodedIcon.sha256, encodedIcon.bytes))

            val evMedia2 = Ulid.generate(t0 + 10_000L)
            val uidMedia2 = "${cfgA.deviceId}:${t0 + 10_000L}:media2"
            val postedMedia2 = NotificationPostedPayload(
                notificationUid = uidMedia2,
                senderDeviceName = cfgA.deviceName,
                postedAt = t0 + 10_000L,
                app = AppInfoPayload("com.whatsapp", "WhatsApp", encodedIcon.sha256, iconBlobId),
                content = ContentPayload("Alice", "Second message hits icon cache")
            )
            wsA.enqueueAndSend(evMedia2, crypto.encryptEvent(evMedia2, cfgA.deviceId, encodePostedPayload(postedMedia2)))
            withTimeout(5_000L) {
                while (synchronized(phoneBShown) { phoneBShown.size } < 2) delay(25L)
            }
            assertArrayEquals(encodedIcon.bytes, synchronized(phoneBShown) { phoneBShown[1].second!!.readBytes() })

            // 2. Phone A dismisses uidMedia -> clears Phone B's mirrored notification & does NOT echo back to Phone A!
            val evDisA = Ulid.generate(t0 + 11_000L)
            wsA.enqueueAndSend(
                evDisA,
                crypto.encryptEvent(
                    evDisA, cfgA.deviceId,
                    encodeDismissedPayload(
                        NotificationDismissedPayload(
                            notificationUids = listOf(uidMedia),
                            dismissedAt = t0 + 11_000L,
                            dismissedByDeviceName = cfgA.deviceName
                        )
                    )
                )
            )
            withTimeout(5_000L) {
                while (!synchronized(phoneBRemovedMirrored) { phoneBRemovedMirrored.contains(firstEntityB.id) }) delay(25L)
            }
            assertTrue(synchronized(phoneACancelled) { phoneACancelled.isEmpty() })

            // 3. 5-Second Dedup: Phone A + Phone B post identical notification -> Phone C merges; Phone C dismisses -> cancels BOTH A & B!
            val tDedup = t0 + 30_000L
            val uidDupA = "${cfgA.deviceId}:$tDedup:dupA"
            val uidDupB = "${cfgB.deviceId}:${tDedup + 1_000L}:dupB"
            dbA.activeKeyMapDao().upsert(ActiveKeyMapEntity(uidDupA, "0|com.dup|1|null|1000", tDedup))
            dbB.activeKeyMapDao().upsert(ActiveKeyMapEntity(uidDupB, "0|com.dup|2|null|1000", tDedup + 1_000L))

            val evDupA = Ulid.generate(tDedup)
            wsA.enqueueAndSend(
                evDupA,
                crypto.encryptEvent(
                    evDupA, cfgA.deviceId,
                    encodePostedPayload(
                        NotificationPostedPayload(
                            notificationUid = uidDupA,
                            senderDeviceName = cfgA.deviceName,
                            postedAt = tDedup,
                            app = AppInfoPayload("com.dup", "DupApp"),
                            content = ContentPayload("Shared", "Same body")
                        )
                    )
                )
            )
            // Wait for Phone C to ingest Phone A's notification before Phone B posts the duplicate so merge order is deterministic.
            withTimeout(5_000L) {
                while (dbC.notificationDao().observeAll().first().none { it.packageName == "com.dup" }) {
                    delay(25L)
                }
            }
            val evDupB = Ulid.generate(tDedup + 1_000L)
            wsB.enqueueAndSend(
                evDupB,
                crypto.encryptEvent(
                    evDupB, cfgB.deviceId,
                    encodePostedPayload(
                        NotificationPostedPayload(
                            notificationUid = uidDupB,
                            senderDeviceName = cfgB.deviceName,
                            postedAt = tDedup + 1_000L,
                            app = AppInfoPayload("com.dup", "DupApp"),
                            content = ContentPayload("Shared", "Same body")
                        )
                    )
                )
            )

            withTimeout(5_000L) {
                while (true) {
                    val row = dbC.notificationDao().observeAll().first().firstOrNull { it.packageName == "com.dup" }
                    if (row != null && Deduplicator.decodeStringList(row.notificationUidsJson).size == 2) break
                    delay(25L)
                }
            }
            val mergedOnC = dbC.notificationDao().observeAll().first().first { it.packageName == "com.dup" }
            val mergedUids = Deduplicator.decodeStringList(mergedOnC.notificationUidsJson)
            val mergedSenders = Deduplicator.decodeStringList(mergedOnC.senderDevicesJson)
            assertEquals(listOf(uidDupA, uidDupB), mergedUids)
            assertEquals(listOf("Phone A", "Phone B"), mergedSenders)
            val dupShownOnC = synchronized(phoneCShown) { phoneCShown.filter { it.first.packageName == "com.dup" } }
            assertEquals(2, dupShownOnC.size)
            assertEquals(false, dupShownOnC[0].second)
            assertEquals(true, dupShownOnC[1].second)

            val evDisC = Ulid.generate(tDedup + 2_000L)
            wsC.enqueueAndSend(
                evDisC,
                crypto.encryptEvent(
                    evDisC, cfgC.deviceId,
                    encodeDismissedPayload(
                        NotificationDismissedPayload(
                            notificationUids = mergedUids,
                            dismissedAt = tDedup + 2_000L,
                            dismissedByDeviceName = cfgC.deviceName
                        )
                    )
                )
            )
            withTimeout(5_000L) {
                while (synchronized(phoneACancelled) { !phoneACancelled.contains("0|com.dup|1|null|1000") } ||
                    synchronized(phoneBCancelled) { !phoneBCancelled.contains("0|com.dup|2|null|1000") }
                ) {
                    delay(25L)
                }
            }

            // 4. Offline Replay on Android: disconnect Phone B, Phone A posts 10 & dismisses 7, Phone B reconnects -> ONLY 3 pop up!
            wsB.stop()
            delay(150L)
            val beforeReplayCount = synchronized(phoneBShown) { phoneBShown.size }

            val tOff = t0 + 100_000L
            val offUids = (1..10).map { i -> "${cfgA.deviceId}:${tOff + i * 10_000L}:off_$i" }
            for ((idx, uid) in offUids.withIndex()) {
                val ts = tOff + (idx + 1) * 10_000L
                val ev = Ulid.generate(ts)
                wsA.enqueueAndSend(
                    ev,
                    crypto.encryptEvent(
                        ev, cfgA.deviceId,
                        encodePostedPayload(
                            NotificationPostedPayload(
                                notificationUid = uid,
                                senderDeviceName = cfgA.deviceName,
                                postedAt = ts,
                                app = AppInfoPayload("com.off", "OfflineApp"),
                                content = ContentPayload("Off ${idx + 1}", "Body ${idx + 1}")
                            )
                        )
                    )
                )
            }
            val evOffDis = Ulid.generate(tOff + 200_000L)
            wsA.enqueueAndSend(
                evOffDis,
                crypto.encryptEvent(
                    evOffDis, cfgA.deviceId,
                    encodeDismissedPayload(
                        NotificationDismissedPayload(
                            notificationUids = offUids.take(7),
                            dismissedAt = tOff + 200_000L,
                            dismissedByDeviceName = cfgA.deviceName
                        )
                    )
                )
            )
            // Wait until online Phone C reflects all 10 posts + 7 dismissals, proving Go server committed all 11 events.
            withTimeout(5_000L) {
                while (true) {
                    val offOnC = dbC.notificationDao().observeAll().first().filter { it.packageName == "com.off" }
                    if (offOnC.size == 10 && offOnC.count { it.dismissedAt != null } == 7) break
                    delay(25L)
                }
            }

            wsB.start(cfgB)
            withTimeout(5_000L) {
                while (synchronized(phoneBShown) { phoneBShown.size } < beforeReplayCount + 3) delay(25L)
            }
            delay(150L)
            val replayPopups = synchronized(phoneBShown) { phoneBShown.drop(beforeReplayCount).map { it.first.title } }
            assertEquals(listOf("Off 8", "Off 9", "Off 10"), replayPopups)
            val allOffOnB = dbB.notificationDao().observeAll().first().filter { it.packageName == "com.off" }
            assertEquals(10, allOffOnB.size)
            assertEquals(7, allOffOnB.count { it.dismissedAt != null })
            assertEquals(3, allOffOnB.count { it.dismissedAt == null })
            assertTrue(synchronized(phoneBReplaySummaries) { phoneBReplaySummaries.isEmpty() })

            // 5. Offline Replay >5 active collapse on Android: disconnect Phone B, send 7 active -> reconnect -> 1 summary!
            wsB.stop()
            delay(150L)
            val beforeStormCount = synchronized(phoneBShown) { phoneBShown.size }
            val tStorm = tOff + 300_000L
            for (i in 1..7) {
                val ts = tStorm + i * 10_000L
                val ev = Ulid.generate(ts)
                val uid = "${cfgA.deviceId}:$ts:storm_$i"
                wsA.enqueueAndSend(
                    ev,
                    crypto.encryptEvent(
                        ev, cfgA.deviceId,
                        encodePostedPayload(
                            NotificationPostedPayload(
                                notificationUid = uid,
                                senderDeviceName = cfgA.deviceName,
                                postedAt = ts,
                                app = AppInfoPayload("com.storm", "StormApp"),
                                content = ContentPayload("Storm $i", "Burst $i")
                            )
                        )
                    )
                )
            }
            withTimeout(5_000L) {
                while (dbC.notificationDao().observeAll().first().count { it.packageName == "com.storm" } < 7) {
                    delay(25L)
                }
            }
            wsB.start(cfgB)
            withTimeout(5_000L) {
                while (synchronized(phoneBReplaySummaries) { phoneBReplaySummaries.isEmpty() }) delay(25L)
            }
            assertEquals(1, synchronized(phoneBReplaySummaries) { phoneBReplaySummaries.size })
            assertEquals(7, synchronized(phoneBReplaySummaries) { phoneBReplaySummaries[0].size })
            assertEquals(beforeStormCount, synchronized(phoneBShown) { phoneBShown.size })
        } finally {
            runCatching { wsA.shutdown() }
            runCatching { wsB.shutdown() }
            runCatching { wsC.shutdown() }
            dbA.close()
            dbB.close()
            dbC.close()
            serverProc.destroyForcibly()
        }
    }

    @Test
    fun phase5PairingClaimTrustedAddDeviceAndQrRoundTrip() = runBlocking {
        val serverDir = findServerDir()
        Assume.assumeNotNull("server/ directory not found", serverDir)
        val goAvailable = runCatching { runCmd(serverDir!!, "go", "version") }.isSuccess
        Assume.assumeTrue("go toolchain not available", goAvailable)

        val workDir = tempFolder.newFolder("go-phase5-pairing")
        val exeSuffix = if (System.getProperty("os.name").orEmpty().lowercase().contains("win")) ".exe" else ""
        val binFile = File(workDir, "all-notify-server$exeSuffix")
        val dataDir = File(workDir, "data").apply { mkdirs() }
        runCmd(serverDir!!, "go", "build", "-o", binFile.absolutePath, "./cmd/all-notify-server")

        val kMasterB64 = runCmd(workDir, binFile.absolutePath, "keygen").trim()
        val kMasterBytes = java.util.Base64.getUrlDecoder().decode(kMasterB64)
        val port = ServerSocket(0).use { it.localPort }
        val httpBase = "http://127.0.0.1:$port"

        // Create a trusted pairing code via CLI `pair create --can-add-devices`
        val pairOut = runCmd(
            workDir,
            binFile.absolutePath,
            "pair", "create",
            "--data-dir", dataDir.absolutePath,
            "--name", "Trusted Phone",
            "--platform", "android",
            "--can-add-devices"
        )
        val initialCode = pairOut.lines().first { it.startsWith("Pairing Code:") }.substringAfter(":").trim()

        val serverProc = ProcessBuilder(
            binFile.absolutePath, "serve", "--addr", "127.0.0.1:$port", "--data-dir", dataDir.absolutePath
        ).redirectErrorStream(true).start()

        val httpClient = OkHttpClient.Builder().readTimeout(0, TimeUnit.MILLISECONDS).build()
        val pairingApi = PairingApiClient(httpClient)
        val ctx = ApplicationProvider.getApplicationContext<Application>()
        val dbA = Room.inMemoryDatabaseBuilder(ctx, AllNotifyDatabase::class.java).allowMainThreadQueries().build()
        val dbB = Room.inMemoryDatabaseBuilder(ctx, AllNotifyDatabase::class.java).allowMainThreadQueries().build()
        val cacheA = BlobCacheManager(File(workDir, "cacheA"))
        val cacheB = BlobCacheManager(File(workDir, "cacheB"))

        var wsA: RelayWsClient? = null
        var wsB: RelayWsClient? = null
        try {
            withTimeout(10_000L) {
                while (true) {
                    val ok = runCatching {
                        httpClient.newCall(Request.Builder().url("$httpBase/healthz").build()).execute().use { it.isSuccessful }
                    }.getOrDefault(false)
                    if (ok) break
                    delay(50L)
                }
            }

            // 1. Parse v2 link + claim happy path
            val initialV2Uri = PairingUriParser.encodeV2("https://127.0.0.1:$port", initialCode, kMasterB64, "Trusted Phone")
            val parsedV2 = PairingUriParser.parseLink(initialV2Uri).getOrThrow() as PairingLink.V2
            assertEquals(initialCode, parsedV2.code)

            val claimA = pairingApi.claimCode(httpBase, parsedV2.code, "android")
            assertEquals("Trusted Phone", claimA.name)
            assertTrue(claimA.canAddDevices)

            // 2. Reused code returns 410 CODE_EXPIRED_OR_USED
            val reuseErr = runCatching { pairingApi.claimCode(httpBase, parsedV2.code, "android") }.exceptionOrNull()
            assertTrue("expected PairingApiException 410, got $reuseErr", reuseErr is PairingApiException && reuseErr.httpStatus == 410)

            // 3. GET /v1/me confirms can_add_devices=true for Phone A
            val meA = pairingApi.fetchMe(httpBase, claimA.token)
            assertTrue(meA.canAddDevices)

            // 4. Trusted Phone A creates pairing code for Phone B -> QR round-trip (encode -> decode -> parse)
            val createdB = pairingApi.createPairingCode(httpBase, claimA.token, "Phone B", "android")
            assertTrue(!createdB.canAddDevices)
            val v2UriB = PairingUriParser.encodeV2("https://127.0.0.1:$port", createdB.code, kMasterB64, createdB.name)

            val qrBmp = QrCodeGenerator.encode(v2UriB, 400)
            val pixels = IntArray(qrBmp.width * qrBmp.height)
            qrBmp.getPixels(pixels, 0, qrBmp.width, 0, 0, qrBmp.width, qrBmp.height)
            val decodedQr = QRCodeReader().decode(
                BinaryBitmap(HybridBinarizer(RGBLuminanceSource(qrBmp.width, qrBmp.height, pixels)))
            ).text
            assertEquals(v2UriB, decodedQr)
            val parsedB = PairingUriParser.parseLink(decodedQr).getOrThrow() as PairingLink.V2
            assertEquals(createdB.code, parsedB.code)

            // 5. Phone B claims the code -> untrusted -> 403 NOT_TRUSTED on POST /v1/pairing-codes
            val claimB = pairingApi.claimCode(httpBase, parsedB.code, "android")
            assertTrue(!claimB.canAddDevices)
            val meB = pairingApi.fetchMe(httpBase, claimB.token)
            assertTrue(!meB.canAddDevices)

            val untrustedErr = runCatching {
                pairingApi.createPairingCode(httpBase, claimB.token, "Rogue", "android")
            }.exceptionOrNull()
            assertTrue("expected 403 NOT_TRUSTED, got $untrustedErr", untrustedErr is PairingApiException && untrustedErr.httpStatus == 403)

            // Phone A's listPairingCodes shows code claimed
            val codesA = pairingApi.listPairingCodes(httpBase, claimA.token)
            assertEquals("claimed", codesA.first { it.codeId == createdB.codeId }.status)

            // 6. Both claimed devices connect via WS and relay an E2EE notification!
            val cfgA = PairingConfig(1, httpBase, "ws://127.0.0.1:$port/v1/ws", claimA.token, kMasterB64, kMasterBytes, claimA.deviceId, claimA.name)
            val cfgB = PairingConfig(1, httpBase, "ws://127.0.0.1:$port/v1/ws", claimB.token, kMasterB64, kMasterBytes, claimB.deviceId, claimB.name)
            val crypto = CryptoEngine(kMasterBytes)
            val receivedOnB = CompletableDeferred<NotificationEntity>()

            val noopFetcher = object : BlobFetcher {
                override suspend fun fetchIcon(sha256: String, blobId: String): File? = null
                override suspend fun fetchAttachment(blobId: String, sha256: String): File? = null
            }
            val pipeA = NotificationPipeline(
                configProvider = { cfgA }, cryptoProvider = { crypto }, database = dbA,
                blobCache = cacheA, blobFetcher = noopFetcher,
                displayPort = object : MirroredDisplayPort {
                    override fun showNotification(entity: NotificationEntity, iconFile: File?, attachmentFile: File?, silentUpdate: Boolean) {}
                    override fun showReplaySummary(activeEntities: List<NotificationEntity>) {}
                    override fun cancelMirrored(notificationRowId: Long) {}
                    override fun isOsDndBlocking(): Boolean = false
                },
                remoteCancelPort = object : RemoteCancelPort { override fun cancelLocalBySbnKey(sbnKey: String) {} },
                sendAck = { seq -> wsA?.sendAck(seq) }
            )
            val pipeB = NotificationPipeline(
                configProvider = { cfgB }, cryptoProvider = { crypto }, database = dbB,
                blobCache = cacheB, blobFetcher = noopFetcher,
                displayPort = object : MirroredDisplayPort {
                    override fun showNotification(entity: NotificationEntity, iconFile: File?, attachmentFile: File?, silentUpdate: Boolean) {
                        receivedOnB.complete(entity)
                    }
                    override fun showReplaySummary(activeEntities: List<NotificationEntity>) {}
                    override fun cancelMirrored(notificationRowId: Long) {}
                    override fun isOsDndBlocking(): Boolean = false
                },
                remoteCancelPort = object : RemoteCancelPort { override fun cancelLocalBySbnKey(sbnKey: String) {} },
                sendAck = { seq -> wsB?.sendAck(seq) }
            )
            wsA = RelayWsClient(httpClient, dbA, pipeA, backoffScheduleMs = longArrayOf(200L))
            wsB = RelayWsClient(httpClient, dbB, pipeB, backoffScheduleMs = longArrayOf(200L))
            wsA!!.start(cfgA)
            wsB!!.start(cfgB)

            withTimeout(5_000L) {
                while (wsA!!.state.value != ConnectionState.CONNECTED || wsB!!.state.value != ConnectionState.CONNECTED) {
                    delay(25L)
                }
            }
            delay(150L)

            val now = System.currentTimeMillis()
            val evId = Ulid.generate(now)
            val posted = NotificationPostedPayload(
                notificationUid = "${cfgA.deviceId}:$now:p5",
                senderDeviceName = cfgA.deviceName,
                postedAt = now,
                app = AppInfoPayload("com.example", "Example"),
                content = ContentPayload("Phase 5", "Paired via one-time code!")
            )
            wsA!!.enqueueAndSend(evId, crypto.encryptEvent(evId, cfgA.deviceId, encodePostedPayload(posted)))

            val got = withTimeout(5_000L) { receivedOnB.await() }
            assertEquals("Phase 5", got.title)
            assertEquals("Paired via one-time code!", got.body)
        } finally {
            runCatching { wsA?.shutdown() }
            runCatching { wsB?.shutdown() }
            dbA.close()
            dbB.close()
            serverProc.destroyForcibly()
        }
    }

    @Test
    fun xchacha20Poly1305MatchesGoAcrossEdgeCaseLengthsAndHighBitKeys() {
        val serverDir = findServerDir()
        Assume.assumeNotNull("server/ directory not found", serverDir)
        val goAvailable = runCatching { runCmd(serverDir!!, "go", "version") }.isSuccess
        Assume.assumeTrue("go toolchain not available", goAvailable)

        val workDir = tempFolder.newFolder("go-crypto-fuzz")
        val casesFile = File(workDir, "cases.txt")
        val rng = java.util.Random(0x5EED1234L)

        fun toHex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }

        val lengths = listOf(0, 1, 2, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 1024, 65536)
        val aadLengths = listOf(0, 1, 15, 16, 17, 31, 48)
        val lines = mutableListOf<String>()

        // Edge-case keys/nonces (all 0xFF, all 0x00, MSB-set bytes to stress unsigned Poly1305 loads)
        val edgeKeys = listOf(
            ByteArray(32) { 0xff.toByte() },
            ByteArray(32) { 0x00 },
            ByteArray(32) { (0x80 + it).toByte() }
        )
        for ((idx, key) in edgeKeys.withIndex()) {
            val nonce = ByteArray(24) { if (idx == 0) 0xff.toByte() else (0xf0 - it).toByte() }
            val aad = ByteArray(17) { (0xa0 + it).toByte() }
            val pt = ByteArray(129) { (0xfe - it).toByte() }
            val ct = com.allnotify.app.crypto.XChaCha20Poly1305.seal(key, nonce, pt, aad)
            assertArrayEquals(pt, com.allnotify.app.crypto.XChaCha20Poly1305.open(key, nonce, ct, aad))
            lines.add("${toHex(key)}|${toHex(nonce)}|${toHex(aad)}|${toHex(pt)}|${toHex(ct)}")
        }

        // Randomized cases covering block/chunk boundaries up to 64 KiB
        for (len in lengths) {
            for (aadLen in aadLengths) {
                val key = ByteArray(32).also { rng.nextBytes(it) }
                val nonce = ByteArray(24).also { rng.nextBytes(it) }
                val aad = ByteArray(aadLen).also { rng.nextBytes(it) }
                val pt = ByteArray(len).also { rng.nextBytes(it) }
                val ct = com.allnotify.app.crypto.XChaCha20Poly1305.seal(key, nonce, pt, aad)
                assertArrayEquals(pt, com.allnotify.app.crypto.XChaCha20Poly1305.open(key, nonce, ct, aad))
                lines.add("${toHex(key)}|${toHex(nonce)}|${toHex(aad)}|${toHex(pt)}|${toHex(ct)}")
            }
        }
        casesFile.writeText(lines.joinToString("\n"))

        // Run a tiny Go verifier inside serverDir (reusing its golang.org/x/crypto module)
        val goVerifier = File(workDir, "verify.go")
        goVerifier.writeText(
            """
            package main

            import (
                "bufio"
                "bytes"
                "encoding/hex"
                "fmt"
                "os"
                "strings"

                "golang.org/x/crypto/chacha20poly1305"
            )

            func mustHex(s string) []byte {
                b, err := hex.DecodeString(s)
                if err != nil {
                    panic(err)
                }
                return b
            }

            func main() {
                f, err := os.Open(os.Args[1])
                if err != nil {
                    panic(err)
                }
                defer f.Close()
                sc := bufio.NewScanner(f)
                sc.Buffer(make([]byte, 1024*1024), 4*1024*1024)
                n := 0
                for sc.Scan() {
                    line := strings.TrimSpace(sc.Text())
                    if line == "" {
                        continue
                    }
                    parts := strings.Split(line, "|")
                    if len(parts) != 5 {
                        panic("bad line")
                    }
                    key := mustHex(parts[0])
                    nonce := mustHex(parts[1])
                    aad := mustHex(parts[2])
                    pt := mustHex(parts[3])
                    wantCT := mustHex(parts[4])

                    aead, err := chacha20poly1305.NewX(key)
                    if err != nil {
                        panic(err)
                    }
                    gotCT := aead.Seal(nil, nonce, pt, aad)
                    if !bytes.Equal(gotCT, wantCT) {
                        fmt.Fprintf(os.Stderr, "MISMATCH at case %d (ptLen=%d aadLen=%d)\n", n, len(pt), len(aad))
                        os.Exit(1)
                    }
                    opened, err := aead.Open(nil, nonce, wantCT, aad)
                    if err != nil || !bytes.Equal(opened, pt) {
                        fmt.Fprintf(os.Stderr, "OPEN MISMATCH at case %d: %v\n", n, err)
                        os.Exit(1)
                    }
                    n++
                }
                if err := sc.Err(); err != nil {
                    panic(err)
                }
                fmt.Printf("VERIFIED %d CASES\n", n)
            }
            """.trimIndent()
        )

        val out = runCmd(serverDir!!, "go", "run", goVerifier.absolutePath, casesFile.absolutePath)
        assertTrue("Expected Go verifier to confirm all ${lines.size} cases, got: $out", out.contains("VERIFIED ${lines.size} CASES"))
    }
}
