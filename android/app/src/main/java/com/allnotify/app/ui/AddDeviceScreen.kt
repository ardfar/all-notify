package com.allnotify.app.ui

import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.ContextWrapper
import android.content.Intent
import android.graphics.Bitmap
import android.os.Build
import android.view.WindowManager
import android.widget.Toast
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.allnotify.app.AllNotifyApp
import com.allnotify.app.crypto.PairingConfig
import com.allnotify.app.crypto.PairingUriParser
import com.allnotify.app.net.CreatedPairingCodeResponse
import com.allnotify.app.net.PairingApiException
import com.google.zxing.BarcodeFormat
import com.journeyapps.barcodescanner.BarcodeEncoder
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

object QrCodeGenerator {
    fun encode(content: String, sizePx: Int = 600): Bitmap =
        BarcodeEncoder().encodeBitmap(content, BarcodeFormat.QR_CODE, sizePx, sizePx)
}

@Composable
fun AddDeviceScreen(
    app: AllNotifyApp,
    config: PairingConfig,
    onBack: () -> Unit
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    BackHandler(onBack = onBack)

    // Block screenshots & recents thumbnails while this screen (QR with K_master) is shown.
    DisposableEffect(context) {
        val window = context.findActivity()?.window
        window?.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        onDispose {
            window?.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
        }
    }

    var deviceName by rememberSaveable { mutableStateOf("") }
    var platform by rememberSaveable { mutableStateOf("android") }
    var submitting by remember { mutableStateOf(false) }
    var errorText by remember { mutableStateOf<String?>(null) }

    var activeCode by remember { mutableStateOf<CreatedPairingCodeResponse?>(null) }
    var pairingUri by remember { mutableStateOf<String?>(null) }
    var qrBitmap by remember { mutableStateOf<Bitmap?>(null) }
    var codeStatus by remember { mutableStateOf("pending") }
    var remainingSeconds by remember { mutableLongStateOf(0L) }

    // Countdown timer
    LaunchedEffect(activeCode, codeStatus) {
        val code = activeCode ?: return@LaunchedEffect
        while (codeStatus == "pending") {
            val rem = ((code.expiresAt - System.currentTimeMillis()) / 1000L).coerceAtLeast(0L)
            remainingSeconds = rem
            if (rem == 0L) {
                codeStatus = "expired"
                break
            }
            delay(1000L)
        }
    }

    // Status polling every 3s while pending
    LaunchedEffect(activeCode, codeStatus) {
        val code = activeCode ?: return@LaunchedEffect
        while (codeStatus == "pending") {
            delay(3000L)
            runCatching {
                app.pairingApiClient.listPairingCodes(config.serverUrl, config.token)
            }.onSuccess { list ->
                val match = list.firstOrNull { it.codeId == code.codeId }
                if (match != null && match.status != "pending") {
                    codeStatus = match.status
                }
            }.onFailure { err ->
                if (err is PairingApiException && err.httpStatus == 403) {
                    app.database.setCanAddDevices(false)
                }
            }
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text("Add Device", style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
            TextButton(onClick = onBack) { Text("Done") }
        }

        val currentCode = activeCode
        if (currentCode == null) {
            Text(
                "Create a one-time pairing code (valid 10 minutes). Your group encryption key stays on this device and is embedded locally into the QR code.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            OutlinedTextField(
                value = deviceName,
                onValueChange = {
                    deviceName = it
                    errorText = null
                },
                label = { Text("Device name") },
                placeholder = { Text("e.g. MacBook Pro or Work Phone") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )

            Text("Platform", style = MaterialTheme.typography.labelLarge)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                listOf("android" to "Android", "macos" to "macOS", "windows" to "Windows").forEach { (id, label) ->
                    FilterChip(
                        selected = platform == id,
                        onClick = { platform = id },
                        label = { Text(label) }
                    )
                }
            }

            if (errorText != null) {
                Text(
                    text = errorText!!,
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodySmall
                )
            }

            Button(
                onClick = {
                    val trimmed = deviceName.trim()
                    if (trimmed.isEmpty()) {
                        errorText = "Enter a device name"
                        return@Button
                    }
                    submitting = true
                    errorText = null
                    scope.launch {
                        runCatching {
                            val created = app.pairingApiClient.createPairingCode(
                                serverUrl = config.serverUrl,
                                token = config.token,
                                name = trimmed,
                                platform = platform
                            )
                            val uri = PairingUriParser.encodeV2(
                                serverUrl = config.serverUrl,
                                code = created.code,
                                keyBase64Url = config.keyBase64Url,
                                deviceName = created.name
                            )
                            val bmp = withContext(Dispatchers.Default) {
                                QrCodeGenerator.encode(uri, 600)
                            }
                            Triple(created, uri, bmp)
                        }.onSuccess { (created, uri, bmp) ->
                            activeCode = created
                            pairingUri = uri
                            qrBitmap = bmp
                            codeStatus = "pending"
                            remainingSeconds = ((created.expiresAt - System.currentTimeMillis()) / 1000L).coerceAtLeast(0L)
                        }.onFailure { err ->
                            if (err is PairingApiException && err.httpStatus == 403) {
                                app.database.setCanAddDevices(false)
                            }
                            errorText = err.message ?: "Failed to create pairing code"
                        }
                        submitting = false
                    }
                },
                enabled = !submitting && deviceName.isNotBlank(),
                modifier = Modifier.fillMaxWidth()
            ) {
                if (submitting) {
                    CircularProgressIndicator(modifier = Modifier.size(18.dp), strokeWidth = 2.dp)
                } else {
                    Text("Generate Pairing QR")
                }
            }
        } else {
            Card(Modifier.fillMaxWidth()) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(16.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Text(
                        "${currentCode.name} (${currentCode.platform})",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.SemiBold
                    )

                    val statusLabel = when (codeStatus) {
                        "claimed" -> "Claimed ✓"
                        "expired" -> "Expired"
                        "cancelled" -> "Cancelled"
                        else -> "Expires in ${remainingSeconds / 60}:${"%02d".format(remainingSeconds % 60)}"
                    }
                    Surface(
                        color = if (codeStatus == "claimed") Color(0xFF1B5E20).copy(alpha = 0.2f)
                        else MaterialTheme.colorScheme.secondaryContainer,
                        shape = RoundedCornerShape(12.dp)
                    ) {
                        Text(
                            text = statusLabel,
                            style = MaterialTheme.typography.labelLarge,
                            modifier = Modifier.padding(horizontal = 12.dp, vertical = 4.dp)
                        )
                    }

                    val bmp = qrBitmap
                    if (bmp != null) {
                        Box(
                            modifier = Modifier
                                .background(Color.White, RoundedCornerShape(12.dp))
                                .padding(12.dp)
                        ) {
                            Image(
                                bitmap = bmp.asImageBitmap(),
                                contentDescription = "Pairing QR code",
                                modifier = Modifier.size(240.dp)
                            )
                        }
                    }

                    val uri = pairingUri.orEmpty()
                    Row(
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        OutlinedButton(
                            onClick = { copySensitive(context, "All-Notify Pairing Link", uri) },
                            modifier = Modifier.weight(1f)
                        ) {
                            Text("Copy Link")
                        }
                        OutlinedButton(
                            onClick = {
                                val share = Intent(Intent.ACTION_SEND).apply {
                                    type = "text/plain"
                                    putExtra(Intent.EXTRA_TEXT, uri)
                                }
                                context.startActivity(Intent.createChooser(share, "Share Pairing Link"))
                            },
                            modifier = Modifier.weight(1f)
                        ) {
                            Text("Share Link")
                        }
                    }

                    Spacer(Modifier.height(4.dp))
                    TextButton(onClick = {
                        activeCode = null
                        pairingUri = null
                        qrBitmap = null
                        deviceName = ""
                    }) {
                        Text("Create another code")
                    }
                }
            }
        }
    }
}

private tailrec fun Context.findActivity(): Activity? = when (this) {
    is Activity -> this
    is ContextWrapper -> baseContext.findActivity()
    else -> null
}

private fun copySensitive(context: Context, label: String, text: String) {
    val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    val clip = ClipData.newPlainText(label, text)
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
        clip.description.extras = android.os.PersistableBundle().apply {
            putBoolean(android.content.ClipDescription.EXTRA_IS_SENSITIVE, true)
        }
    }
    cm.setPrimaryClip(clip)
    Toast.makeText(context, "Copied to clipboard", Toast.LENGTH_SHORT).show()
}
