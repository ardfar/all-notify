package com.allnotify.app.data

import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
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

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class)
class DatabaseAndCacheTest {

    @get:Rule
    val tempFolder = TemporaryFolder()

    private lateinit var db: AllNotifyDatabase

    @Before
    fun setUp() {
        db = Room.inMemoryDatabaseBuilder(
            ApplicationProvider.getApplicationContext(),
            AllNotifyDatabase::class.java
        ).allowMainThreadQueries().build()
    }

    @After
    fun tearDown() {
        db.close()
    }

    @Test
    fun retentionPrunesOldRowsExcessRowsExpiredOutboxAndOrphanAttachments() = runBlocking {
        val cache = BlobCacheManager(tempFolder.newFolder("cache"))
        val now = 2_000_000_000_000L

        val keptFile = cache.putAttachment("img_KEPT000001", byteArrayOf(1, 2, 3))
        val expiredFile = cache.putAttachment("img_EXPIRED001", byteArrayOf(4, 5, 6))
        val orphanFile = cache.putAttachment("img_ORPHAN0001", byteArrayOf(7, 8, 9))

        // Insert 1 notification older than 30 days (should be pruned + its attachment orphaned)
        db.notificationDao().insert(
            NotificationEntity(
                notificationUidsJson = """["old_1"]""",
                senderDevicesJson = """["Phone A"]""",
                packageName = "com.example",
                appName = "Example",
                title = "Old",
                body = "Expired",
                attachmentPath = expiredFile.absolutePath,
                dedupHash = "h_old",
                postedAt = now - AllNotifyDatabase.RETENTION_MS - 1_000L,
                isMirrored = true
            )
        )
        // Insert 1 recent notification referencing keptFile
        db.notificationDao().insert(
            NotificationEntity(
                notificationUidsJson = """["new_1"]""",
                senderDevicesJson = """["Phone A"]""",
                packageName = "com.example",
                appName = "Example",
                title = "New",
                body = "Fresh",
                attachmentPath = keptFile.absolutePath,
                dedupHash = "h_new",
                postedAt = now - 5_000L,
                isMirrored = true
            )
        )

        // Outbox: 1 expired (>24h), 1 fresh
        db.outboxDao().enqueue(OutboxEntity("evt_old", "cipher1", now - AllNotifyDatabase.OUTBOX_TTL_MS - 1L))
        db.outboxDao().enqueue(OutboxEntity("evt_new", "cipher2", now - 10_000L))

        val stats = db.pruneRetention(cache, now)
        assertEquals(1, stats.deletedNotifications)
        assertEquals(1, stats.deletedOutbox)
        assertEquals(2, stats.deletedOrphanAttachments)
        assertEquals(1, db.notificationDao().count())
        assertTrue(keptFile.exists())
        assertFalse(expiredFile.exists())
        assertFalse(orphanFile.exists())
        assertEquals(1, db.outboxDao().listValid(0L).size)
    }

    @Test
    fun trimToMaxRowsKeepsNewest5000() = runBlocking {
        val dao = db.notificationDao()
        val baseTs = 1_764_060_000_000L
        for (i in 1..5_005) {
            dao.insert(
                NotificationEntity(
                    notificationUidsJson = """["uid_$i"]""",
                    senderDevicesJson = """["Phone"]""",
                    packageName = "com.test",
                    appName = "Test",
                    title = "T$i",
                    body = "B$i",
                    dedupHash = "d$i",
                    postedAt = baseTs + i,
                    isMirrored = true
                )
            )
        }
        assertEquals(5_005, dao.count())
        val trimmed = dao.trimToMaxRows(AllNotifyDatabase.MAX_HISTORY_ROWS)
        assertEquals(5, trimmed)
        assertEquals(5_000, dao.count())
    }

    @Test
    fun blobCacheEnforcesPathSafetyAndLruEviction() {
        var now = 1_000_000L
        val cache = BlobCacheManager(tempFolder.newFolder("lru"), maxIcons = 2, nowMs = { now })

        val h1 = "1".repeat(64)
        val h2 = "2".repeat(64)
        val h3 = "3".repeat(64)

        cache.putIcon(h1, byteArrayOf(1))
        now += 1_000L
        cache.putIcon(h2, byteArrayOf(2))
        now += 1_000L
        // Touch h1 so h2 becomes LRU
        assertNotNull(cache.getIconFile(h1))
        now += 1_000L
        cache.putIcon(h3, byteArrayOf(3))

        assertNotNull("h1 should survive LRU because it was recently touched", cache.getIconFile(h1))
        assertNull("h2 should be evicted as LRU", cache.getIconFile(h2))
        assertNotNull("h3 should be present", cache.getIconFile(h3))

        // Path traversal safety
        assertNull(cache.getIconFile("../evil"))
        assertNull(cache.getAttachmentFile("../etc/passwd"))
        var threw = false
        try {
            cache.putAttachment("../etc/passwd", byteArrayOf(1))
        } catch (_: IllegalArgumentException) {
            threw = true
        }
        assertTrue("invalid blob_id must throw", threw)

        // Uploaded icon re-verify TTL
        cache.markIconUploaded(h1)
        assertTrue(cache.isIconRecentlyUploaded(h1))
        now += BlobCacheManager.ICON_REVERIFY_MS + 1L
        assertFalse(cache.isIconRecentlyUploaded(h1))

        // In-flight .tmp attachment files must not be deleted by orphan pruning
        val inFlightTmp = java.io.File(cache.attachmentsDir, "img_INFLIGHT.tmp").apply { writeBytes(byteArrayOf(1)) }
        assertEquals(0, cache.pruneOrphanAttachments(emptySet()))
        assertTrue(inFlightTmp.exists())
    }

    @Test
    fun secureCredentialStoreRoundTripsAndRejectsCorruptedKey() {
        val ctx = ApplicationProvider.getApplicationContext<android.content.Context>()
        val prefs = ctx.getSharedPreferences("test_creds", android.content.Context.MODE_PRIVATE)
        val store = SecureCredentialStore(prefs)
        assertNull(store.load())

        val cfg = com.allnotify.app.crypto.PairingUriParser.parse(
            "allnotify://pair?v=1&url=https%3A%2F%2Fnotify.example.com&token=tok_123&key=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8&device_id=dev_1&name=Pixel%209"
        ).getOrThrow()
        store.save(cfg)
        assertEquals(cfg, store.load())

        // Corrupted short key returns null cleanly
        prefs.edit().putString("k_master_b64", "AQID").apply()
        assertNull(store.load())

        store.clear()
        assertNull(store.load())
    }

    @Test
    fun secureCredentialStoreRecoveryDeletesPrefsAndMasterKeyAliasBeforeRetrying() {
        val ctx = ApplicationProvider.getApplicationContext<android.content.Context>()
        val recoveredPrefs = ctx.getSharedPreferences("recovered_creds", android.content.Context.MODE_PRIVATE)
        val events = mutableListOf<String>()
        var attempts = 0

        val store = SecureCredentialStore.create(
            context = ctx,
            prefsOpener = {
                attempts++
                events.add("open#$attempts")
                if (attempts == 1) {
                    throw java.security.GeneralSecurityException("corrupted keystore alias")
                }
                recoveredPrefs
            },
            deletePrefs = { events.add("deletePrefs") },
            clearMasterKey = { events.add("clearMasterKey") }
        )

        assertEquals(listOf("open#1", "deletePrefs", "clearMasterKey", "open#2"), events)
        assertNull(store.load())
        val cfg = com.allnotify.app.crypto.PairingUriParser.parse(
            "allnotify://pair?v=1&url=https%3A%2F%2Fnotify.example.com&token=tok_rec&key=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8&device_id=dev_rec&name=Recovered"
        ).getOrThrow()
        store.save(cfg)
        assertEquals(cfg, store.load())
    }

    @Test
    fun deleteMasterKeyAliasRemovesEntryFromRealKeyStoreAndIsSafeWhenAbsent() {
        val ks = java.security.KeyStore.getInstance("PKCS12")
        ks.load(null, null)
        val keyGen = javax.crypto.KeyGenerator.getInstance("AES").apply { init(256) }
        val secretKey = keyGen.generateKey()
        val alias = androidx.security.crypto.MasterKey.DEFAULT_MASTER_KEY_ALIAS
        ks.setEntry(
            alias,
            java.security.KeyStore.SecretKeyEntry(secretKey),
            java.security.KeyStore.PasswordProtection("test".toCharArray())
        )
        assertTrue(ks.containsAlias(alias))

        SecureCredentialStore.deleteMasterKeyAlias(keyStoreProvider = { ks }, alias = alias)
        assertFalse("master key alias must be removed from keystore", ks.containsAlias(alias))

        // Second call when alias is absent must be a clean no-op.
        SecureCredentialStore.deleteMasterKeyAlias(keyStoreProvider = { ks }, alias = alias)
        assertFalse(ks.containsAlias(alias))
    }

    @Test
    fun secureCredentialStoreLoadRecoversFromSecurityExceptionWithoutCrashing() {
        val ctx = ApplicationProvider.getApplicationContext<android.content.Context>()
        val backing = ctx.getSharedPreferences("corrupt_val_creds", android.content.Context.MODE_PRIVATE)
        backing.edit().putString("server_url", "https://notify.example.com").apply()
        var cleared = false
        val throwingPrefs = object : android.content.SharedPreferences by backing {
            override fun getString(key: String?, defValue: String?): String? {
                throw SecurityException("corrupted AEAD value")
            }

            override fun edit(): android.content.SharedPreferences.Editor {
                val delegate = backing.edit()
                return object : android.content.SharedPreferences.Editor by delegate {
                    override fun clear(): android.content.SharedPreferences.Editor {
                        cleared = true
                        return delegate.clear()
                    }
                }
            }
        }

        val store = SecureCredentialStore(throwingPrefs)
        assertNull(store.load())
        assertTrue("corrupted preferences should be cleared on SecurityException", cleared)
    }
}
