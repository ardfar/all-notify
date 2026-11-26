package com.allnotify.app.data

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.allnotify.app.crypto.PairingConfig
import java.security.GeneralSecurityException
import java.security.KeyStore
import java.util.Base64

/** Stores sensitive pairing credentials in Android Keystore-backed EncryptedSharedPreferences. */
class SecureCredentialStore(private val prefs: SharedPreferences) {

    fun load(): PairingConfig? {
        val serverUrl: String
        val wsUrl: String
        val token: String
        val keyB64: String
        val deviceId: String
        val deviceName: String
        try {
            serverUrl = prefs.getString(KEY_SERVER_URL, null) ?: return null
            wsUrl = prefs.getString(KEY_WS_URL, null) ?: return null
            token = prefs.getString(KEY_TOKEN, null) ?: return null
            keyB64 = prefs.getString(KEY_MASTER_B64, null) ?: return null
            deviceId = prefs.getString(KEY_DEVICE_ID, null) ?: return null
            deviceName = prefs.getString(KEY_DEVICE_NAME, null) ?: return null
        } catch (_: SecurityException) {
            runCatching { clear() }
            return null
        } catch (_: GeneralSecurityException) {
            runCatching { clear() }
            return null
        }
        val keyBytes = try {
            Base64.getUrlDecoder().decode(keyB64)
        } catch (_: IllegalArgumentException) {
            return null
        }
        if (keyBytes.size != 32) return null
        return PairingConfig(
            version = 1,
            serverUrl = serverUrl,
            wsUrl = wsUrl,
            token = token,
            keyBase64Url = keyB64,
            keyBytes = keyBytes,
            deviceId = deviceId,
            deviceName = deviceName
        )
    }

    fun save(config: PairingConfig) {
        prefs.edit()
            .putString(KEY_SERVER_URL, config.serverUrl)
            .putString(KEY_WS_URL, config.wsUrl)
            .putString(KEY_TOKEN, config.token)
            .putString(KEY_MASTER_B64, config.keyBase64Url)
            .putString(KEY_DEVICE_ID, config.deviceId)
            .putString(KEY_DEVICE_NAME, config.deviceName)
            .apply()
    }

    fun clear() {
        prefs.edit().clear().apply()
    }

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val PREFS_NAME = "all_notify_secure_creds"
        private const val KEY_SERVER_URL = "server_url"
        private const val KEY_WS_URL = "ws_url"
        private const val KEY_TOKEN = "device_token"
        private const val KEY_MASTER_B64 = "k_master_b64"
        private const val KEY_DEVICE_ID = "device_id"
        private const val KEY_DEVICE_NAME = "device_name"

        fun create(context: Context): SecureCredentialStore =
            create(
                context = context,
                prefsOpener = ::openEncryptedPrefs,
                deletePrefs = { it.deleteSharedPreferences(PREFS_NAME) },
                clearMasterKey = ::deleteMasterKeyAlias
            )

        internal fun create(
            context: Context,
            prefsOpener: (Context) -> SharedPreferences,
            deletePrefs: (Context) -> Unit,
            clearMasterKey: () -> Unit
        ): SecureCredentialStore {
            return try {
                SecureCredentialStore(prefsOpener(context))
            } catch (_: Exception) {
                // Recover from corrupted Keystore / EncryptedSharedPreferences after OS restore or key invalidation.
                runCatching { deletePrefs(context) }
                runCatching { clearMasterKey() }
                SecureCredentialStore(prefsOpener(context))
            }
        }

        internal fun deleteMasterKeyAlias(
            keyStoreProvider: () -> KeyStore = {
                KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            },
            alias: String = MasterKey.DEFAULT_MASTER_KEY_ALIAS
        ) {
            val keyStore = keyStoreProvider()
            if (keyStore.containsAlias(alias)) {
                keyStore.deleteEntry(alias)
            }
        }

        private fun openEncryptedPrefs(context: Context): SharedPreferences {
            val masterKey = MasterKey.Builder(context)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build()
            return EncryptedSharedPreferences.create(
                context,
                PREFS_NAME,
                masterKey,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
            )
        }
    }
}
