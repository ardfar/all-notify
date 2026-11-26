package com.allnotify.app

import android.Manifest
import android.content.Intent
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.mutableStateOf
import com.allnotify.app.ui.AllNotifyRoot
import com.allnotify.app.ui.AllNotifyTheme
import com.allnotify.app.ui.PermissionHelpers
import com.allnotify.app.ui.PermissionStatus
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions

class MainActivity : ComponentActivity() {

    private val permissionState = mutableStateOf(
        PermissionStatus(
            notificationAccessGranted = false,
            postNotificationsGranted = false,
            batteryOptimizationIgnored = false
        )
    )
    private val pendingPairingUri = mutableStateOf<String?>(null)

    private val postNotificationLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) {
        refreshPermissions()
    }

    private val qrScanLauncher = registerForActivityResult(ScanContract()) { result ->
        val contents = result.contents
        if (!contents.isNullOrBlank()) {
            pendingPairingUri.value = contents
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        handleIncomingIntent(intent)
        refreshPermissions()

        val app = application as AllNotifyApp
        setContent {
            AllNotifyTheme {
                AllNotifyRoot(
                    app = app,
                    permissionStatus = permissionState.value,
                    pendingPairingUri = pendingPairingUri.value,
                    onConsumePendingUri = { pendingPairingUri.value = null },
                    onScanQr = { launchQrScanner() },
                    onRequestPostNotifications = { requestPostNotifications() },
                    onRefreshPermissions = { refreshPermissions() }
                )
            }
        }
    }

    override fun onResume() {
        super.onResume()
        refreshPermissions()
        (application as? AllNotifyApp)?.ensureRelayRunning()
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleIncomingIntent(intent)
    }

    private fun handleIncomingIntent(intent: Intent?) {
        val data = intent?.dataString ?: return
        if (data.startsWith("allnotify://pair")) {
            pendingPairingUri.value = data
        }
    }

    private fun refreshPermissions() {
        permissionState.value = PermissionHelpers.checkStatus(this)
    }

    private fun requestPostNotifications() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            postNotificationLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        } else {
            refreshPermissions()
        }
    }

    private fun launchQrScanner() {
        val options = ScanOptions().apply {
            setDesiredBarcodeFormats(ScanOptions.QR_CODE)
            setPrompt("Scan All-Notify pairing QR code")
            setBeepEnabled(false)
            setOrientationLocked(false)
        }
        qrScanLauncher.launch(options)
    }
}
