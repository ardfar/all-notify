package com.allnotify.app

import android.app.Application
import com.allnotify.app.crypto.CryptoEngine
import com.allnotify.app.crypto.PairingConfig
import com.allnotify.app.crypto.PairingLink
import com.allnotify.app.crypto.Ulid
import com.allnotify.app.data.AllNotifyDatabase
import com.allnotify.app.data.BlobCacheManager
import com.allnotify.app.data.RetentionWorker
import com.allnotify.app.data.SecureCredentialStore
import com.allnotify.app.net.BlobApiClient
import com.allnotify.app.net.ConnectionState
import com.allnotify.app.net.PairingApiClient
import com.allnotify.app.net.RelayWsClient
import com.allnotify.app.protocol.NotificationDismissedPayload
import com.allnotify.app.protocol.encodeDismissedPayload
import com.allnotify.app.receiver.BlobFetcher
import com.allnotify.app.receiver.MirroredNotificationPoster
import com.allnotify.app.receiver.NotificationPipeline
import com.allnotify.app.receiver.RemoteCancelPort
import com.allnotify.app.service.AllNotifyListenerService
import com.allnotify.app.service.RelayForegroundService
import com.allnotify.app.service.RemoteCancelGuard
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import okhttp3.OkHttpClient
import java.io.File
import java.util.concurrent.TimeUnit

class AllNotifyApp : Application() {

    private val appScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    lateinit var credentialStore: SecureCredentialStore
        private set
    lateinit var database: AllNotifyDatabase
        private set
    lateinit var blobCache: BlobCacheManager
        private set
    lateinit var blobApiClient: BlobApiClient
        private set
    lateinit var pairingApiClient: PairingApiClient
        private set
    lateinit var mirroredPoster: MirroredNotificationPoster
        private set
    lateinit var remoteCancelGuard: RemoteCancelGuard
        private set
    lateinit var pipeline: NotificationPipeline
        private set
    lateinit var relayClient: RelayWsClient
        private set

    private val _pairingConfig = MutableStateFlow<PairingConfig?>(null)
    val pairingConfig: StateFlow<PairingConfig?> = _pairingConfig.asStateFlow()

    @Volatile
    private var cryptoEngine: CryptoEngine? = null

    override fun onCreate() {
        super.onCreate()
        credentialStore = SecureCredentialStore.create(this)
        database = AllNotifyDatabase.build(this)
        blobCache = BlobCacheManager(cacheDir)
        remoteCancelGuard = RemoteCancelGuard()
        mirroredPoster = MirroredNotificationPoster(this).apply { ensureChannels() }

        val blobHttp = OkHttpClient.Builder()
            .connectTimeout(15, TimeUnit.SECONDS)
            .readTimeout(30, TimeUnit.SECONDS)
            .writeTimeout(30, TimeUnit.SECONDS)
            .build()
        blobApiClient = BlobApiClient(blobHttp)
        pairingApiClient = PairingApiClient(blobHttp)

        val wsHttp = OkHttpClient.Builder()
            .connectTimeout(15, TimeUnit.SECONDS)
            .readTimeout(0, TimeUnit.MILLISECONDS)
            .writeTimeout(15, TimeUnit.SECONDS)
            .pingInterval(30, TimeUnit.SECONDS)
            .build()

        val blobFetcher = object : BlobFetcher {
            override suspend fun fetchIcon(sha256: String, blobId: String): File? {
                val cfg = currentConfig() ?: return null
                val crypto = currentCrypto() ?: return null
                return blobApiClient.downloadAndCacheIcon(cfg, crypto, blobCache, sha256, blobId)
            }

            override suspend fun fetchAttachment(blobId: String, sha256: String): File? {
                val cfg = currentConfig() ?: return null
                val crypto = currentCrypto() ?: return null
                return blobApiClient.downloadAndCacheAttachment(cfg, crypto, blobCache, blobId, sha256)
            }
        }

        val remoteCancelPort = object : RemoteCancelPort {
            override fun cancelLocalBySbnKey(sbnKey: String) {
                AllNotifyListenerService.cancelRemote(sbnKey, remoteCancelGuard)
            }
        }

        pipeline = NotificationPipeline(
            configProvider = { currentConfig() },
            cryptoProvider = { currentCrypto() },
            database = database,
            blobCache = blobCache,
            blobFetcher = blobFetcher,
            displayPort = mirroredPoster,
            remoteCancelPort = remoteCancelPort,
            sendAck = { seq -> relayClient.sendAck(seq) }
        )

        relayClient = RelayWsClient(
            httpClient = wsHttp,
            database = database,
            handler = pipeline
        )

        val saved = credentialStore.load()
        if (saved != null) {
            _pairingConfig.value = saved
            cryptoEngine = CryptoEngine(saved.keyBytes)
            ensureRelayRunning()
        }

        RetentionWorker.schedule(this)
        appScope.launch {
            database.pruneRetention(blobCache)
        }
        // Refresh GET /v1/me on every WS connect to keep can_add_devices up to date.
        appScope.launch {
            relayClient.state.collect { st ->
                if (st == ConnectionState.CONNECTED) {
                    refreshDeviceMe()
                }
            }
        }
    }

    suspend fun refreshDeviceMe() {
        val cfg = currentConfig() ?: return
        runCatching {
            val me = pairingApiClient.fetchMe(cfg.serverUrl, cfg.token)
            database.setCanAddDevices(me.canAddDevices)
        }
    }

    suspend fun pairFromLink(link: PairingLink): Result<PairingConfig> = runCatching {
        when (link) {
            is PairingLink.V1 -> {
                database.setCanAddDevices(false)
                applyPairing(link.config)
                link.config
            }
            is PairingLink.V2 -> {
                val claimed = pairingApiClient.claimCode(
                    serverUrl = link.serverUrl,
                    code = link.code,
                    platform = "android"
                )
                val cfg = PairingConfig(
                    version = 1,
                    serverUrl = link.serverUrl,
                    wsUrl = link.wsUrl,
                    token = claimed.token,
                    keyBase64Url = link.keyBase64Url,
                    keyBytes = link.keyBytes,
                    deviceId = claimed.deviceId,
                    deviceName = claimed.name
                )
                database.setCanAddDevices(claimed.canAddDevices)
                applyPairing(cfg)
                cfg
            }
        }
    }

    fun currentConfig(): PairingConfig? = _pairingConfig.value

    fun currentCrypto(): CryptoEngine? = cryptoEngine

    /**
     * Starts RelayForegroundService when permitted; if blocked by Android 12+ background FGS
     * restrictions (e.g. cold background wake before battery exemption), falls back to starting
     * the WebSocket client directly so relay remains operational without crashing.
     */
    fun ensureRelayRunning() {
        val cfg = currentConfig() ?: return
        if (!RelayForegroundService.start(this)) {
            relayClient.start(cfg)
        }
    }

    fun applyPairing(config: PairingConfig) {
        val previous = _pairingConfig.value
        credentialStore.save(config)
        _pairingConfig.value = config
        cryptoEngine = CryptoEngine(config.keyBytes)
        appScope.launch {
            val serverOrDeviceChanged = previous?.deviceId != config.deviceId ||
                previous?.serverUrl != config.serverUrl
            val keyChanged = previous?.keyBase64Url != config.keyBase64Url
            if (serverOrDeviceChanged) {
                database.resetSyncState()
            }
            if (serverOrDeviceChanged || keyChanged) {
                blobCache.clearUploadedIconCache()
            }
            ensureRelayRunning()
        }
    }

    fun unpair() {
        RelayForegroundService.stop(this)
        relayClient.stop()
        credentialStore.clear()
        _pairingConfig.value = null
        cryptoEngine = null
        appScope.launch {
            database.resetSyncState()
            database.setCanAddDevices(false)
            blobCache.clearUploadedIconCache()
        }
    }

    suspend fun emitDismissal(notificationUids: List<String>) {
        val uniqueUids = notificationUids.filter { it.isNotBlank() }.distinct()
        if (uniqueUids.isEmpty()) return
        val cfg = currentConfig() ?: return
        val crypto = currentCrypto() ?: return
        val now = System.currentTimeMillis()
        val eventId = Ulid.generate(now)
        val payload = NotificationDismissedPayload(
            notificationUids = uniqueUids,
            dismissedAt = now,
            dismissedByDeviceName = cfg.deviceName.take(128)
        )
        val ciphertext = crypto.encryptEvent(
            eventId = eventId,
            senderDeviceId = cfg.deviceId,
            plaintextUtf8 = encodeDismissedPayload(payload)
        )
        relayClient.enqueueAndSend(eventId, ciphertext)
    }

    suspend fun dismissHistoryItem(rowId: Long) {
        val row = database.notificationDao().getById(rowId) ?: return
        if (row.dismissedAt != null) return
        val now = System.currentTimeMillis()
        database.notificationDao().markDismissedById(rowId, now)
        if (row.isMirrored) {
            mirroredPoster.cancelMirrored(rowId)
        }
        val uids = com.allnotify.app.receiver.Deduplicator.decodeStringList(row.notificationUidsJson)
        for (uid in uids) {
            val mapping = database.activeKeyMapDao().findByUid(uid)
            if (mapping != null) {
                AllNotifyListenerService.cancelRemote(mapping.sbnKey, remoteCancelGuard)
                database.activeKeyMapDao().deleteBySbnKey(mapping.sbnKey)
            }
        }
        emitDismissal(uids)
    }

    suspend fun clearHistory() {
        database.notificationDao().deleteAll()
        blobCache.clearAttachments()
    }
}
