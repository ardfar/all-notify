package com.allnotify.app.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import com.allnotify.app.AllNotifyApp
import com.allnotify.app.MainActivity
import com.allnotify.app.R
import com.allnotify.app.data.KvKeys
import com.allnotify.app.net.ConnectionState
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.launch

class RelayForegroundService : Service() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    @Volatile
    private var lastNetwork: Network? = null

    override fun onCreate() {
        super.onCreate()
        ensureChannel()
        val initialNotif = buildStatusNotification("Connecting...")
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(
                FOREGROUND_NOTIFICATION_ID,
                initialNotif,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC
            )
        } else {
            startForeground(FOREGROUND_NOTIFICATION_ID, initialNotif)
        }

        val app = applicationContext as AllNotifyApp
        registerNetworkCallback(app)
        observeStatus(app)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val app = applicationContext as AllNotifyApp
        when (intent?.action) {
            ACTION_STOP -> {
                app.relayClient.stop()
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
                return START_NOT_STICKY
            }
            else -> {
                val cfg = app.currentConfig()
                if (cfg == null) {
                    stopForeground(STOP_FOREGROUND_REMOVE)
                    stopSelf()
                    return START_NOT_STICKY
                }
                app.relayClient.start(cfg)
            }
        }
        return START_STICKY
    }

    override fun onTimeout(startId: Int, fgsType: Int) {
        // Android 15 (API 35) enforces a 6-hour dataSync FGS timeout; stop cleanly to avoid crash.
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf(startId)
    }

    override fun onDestroy() {
        unregisterNetworkCallback()
        scope.cancel()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun observeStatus(app: AllNotifyApp) {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        scope.launch {
            combine(
                app.relayClient.state,
                app.database.kvStateDao().observe(KvKeys.PAUSED_UNTIL)
            ) { connState, pausedRaw ->
                val pausedUntil = pausedRaw?.toLongOrNull() ?: 0L
                val isPaused = pausedUntil == Long.MAX_VALUE || pausedUntil > System.currentTimeMillis()
                when {
                    connState == ConnectionState.REVOKED -> "Device revoked — re-pair required"
                    isPaused -> "Paused"
                    connState == ConnectionState.CONNECTED -> "All-Notify Connected"
                    else -> "Reconnecting..."
                }
            }.collect { statusText ->
                nm.notify(FOREGROUND_NOTIFICATION_ID, buildStatusNotification(statusText))
            }
        }
    }

    private fun registerNetworkCallback(app: AllNotifyApp) {
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        lastNetwork = cm.activeNetwork
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                val prev = lastNetwork
                lastNetwork = network
                if (prev == null || prev != network) {
                    app.relayClient.triggerImmediateReconnect(forceCloseActive = true)
                }
            }

            override fun onLost(network: Network) {
                if (lastNetwork == network) {
                    lastNetwork = null
                }
            }
        }
        networkCallback = cb
        runCatching { cm.registerDefaultNetworkCallback(cb) }
    }

    private fun unregisterNetworkCallback() {
        val cb = networkCallback ?: return
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        runCatching { cm.unregisterNetworkCallback(cb) }
        networkCallback = null
    }

    private fun ensureChannel() {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        val channel = NotificationChannel(
            CHANNEL_STATUS,
            "Connection Status",
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            description = "Keeps the encrypted All-Notify relay connection alive"
            setShowBadge(false)
        }
        nm.createNotificationChannel(channel)
    }

    private fun buildStatusNotification(text: String): Notification {
        val contentIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
            },
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        return NotificationCompat.Builder(this, CHANNEL_STATUS)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle("All-Notify")
            .setContentText(text)
            .setOngoing(true)
            .setSilent(true)
            .setContentIntent(contentIntent)
            .build()
    }

    companion object {
        const val CHANNEL_STATUS = "relay_status"
        const val FOREGROUND_NOTIFICATION_ID = 1001
        const val ACTION_START = "com.allnotify.app.ACTION_START_RELAY"
        const val ACTION_STOP = "com.allnotify.app.ACTION_STOP_RELAY"

        fun start(context: Context): Boolean {
            val intent = Intent(context, RelayForegroundService::class.java).apply {
                action = ACTION_START
            }
            return runCatching {
                ContextCompat.startForegroundService(context, intent)
                true
            }.getOrDefault(false)
        }

        fun stop(context: Context) {
            runCatching {
                context.stopService(Intent(context, RelayForegroundService::class.java))
            }
        }
    }
}
