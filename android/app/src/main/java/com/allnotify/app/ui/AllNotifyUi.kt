package com.allnotify.app.ui

import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.graphics.BitmapFactory
import android.os.Build
import android.util.LruCache
import android.widget.Toast
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.List
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Notifications
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.SwipeToDismissBox
import androidx.compose.material3.SwipeToDismissBoxValue
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.rememberSwipeToDismissBoxState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.allnotify.app.AllNotifyApp
import com.allnotify.app.BuildConfig
import com.allnotify.app.crypto.CryptoEngine
import com.allnotify.app.crypto.PairingConfig
import com.allnotify.app.crypto.PairingLink
import com.allnotify.app.crypto.PairingUriParser
import com.allnotify.app.data.AppFilterEntity
import com.allnotify.app.data.KvKeys
import com.allnotify.app.data.NotificationEntity
import com.allnotify.app.net.ConnectionState
import com.allnotify.app.receiver.Deduplicator
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.text.DateFormat
import java.util.Date

private enum class Tab { HOME, FILTERS, SETTINGS }

private val decodedBitmapCache = object : LruCache<String, ImageBitmap>(12 * 1024) {
    override fun sizeOf(key: String, value: ImageBitmap): Int {
        val bytes = value.width.toLong() * value.height.toLong() * 4L
        return (bytes / 1024L).toInt().coerceAtLeast(1)
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AllNotifyRoot(
    app: AllNotifyApp,
    permissionStatus: PermissionStatus,
    pendingPairingUri: String?,
    onConsumePendingUri: () -> Unit,
    onScanQr: () -> Unit,
    onRequestPostNotifications: () -> Unit,
    onRefreshPermissions: () -> Unit
) {
    val config by app.pairingConfig.collectAsState()
    val connState by app.relayClient.state.collectAsState()
    val context = LocalContext.current

    if (config == null) {
        OnboardingScreen(
            app = app,
            permissionStatus = permissionStatus,
            initialUri = pendingPairingUri,
            onConsumePendingUri = onConsumePendingUri,
            onScanQr = onScanQr,
            onRequestPostNotifications = onRequestPostNotifications,
            onRefreshPermissions = onRefreshPermissions
        )
        return
    }

    var selectedTab by rememberSaveable { mutableStateOf(Tab.HOME) }
    var showAddDevice by rememberSaveable { mutableStateOf(false) }
    var pendingReplaceLink by remember { mutableStateOf<PairingLink?>(null) }
    val pausedRaw by app.database.kvStateDao().observe(KvKeys.PAUSED_UNTIL).collectAsState(initial = null)
    val canAddDevicesRaw by app.database.kvStateDao().observe(KvKeys.CAN_ADD_DEVICES).collectAsState(initial = null)
    val canAddDevices = canAddDevicesRaw == "true"
    LaunchedEffect(canAddDevices) {
        if (!canAddDevices) {
            showAddDevice = false
        }
    }
    val isPaused = remember(pausedRaw) {
        val v = pausedRaw?.toLongOrNull() ?: 0L
        v == Long.MAX_VALUE || v > System.currentTimeMillis()
    }
    val scope = rememberCoroutineScope()

    fun executePairing(link: PairingLink) {
        scope.launch {
            app.pairFromLink(link)
                .onSuccess { paired ->
                    Toast.makeText(context, "Paired as ${paired.deviceName}", Toast.LENGTH_SHORT).show()
                }
                .onFailure { err ->
                    Toast.makeText(
                        context,
                        err.message ?: "Pairing failed",
                        Toast.LENGTH_LONG
                    ).show()
                }
        }
    }

    LaunchedEffect(pendingPairingUri) {
        if (!pendingPairingUri.isNullOrBlank()) {
            PairingUriParser.parseLink(pendingPairingUri)
                .onSuccess { link ->
                    val cur = config
                    val needsConfirm = cur != null && (
                        cur.serverUrl != link.serverUrl ||
                            CryptoEngine.computeKcv(cur.keyBytes) != CryptoEngine.computeKcv(link.keyBytes)
                        )
                    if (needsConfirm) {
                        pendingReplaceLink = link
                    } else {
                        executePairing(link)
                    }
                }
                .onFailure { err ->
                    Toast.makeText(
                        context,
                        err.message ?: "Invalid pairing URI",
                        Toast.LENGTH_LONG
                    ).show()
                }
            onConsumePendingUri()
        }
    }

    val confirmLink = pendingReplaceLink
    if (confirmLink != null) {
        AlertDialog(
            onDismissRequest = { pendingReplaceLink = null },
            title = { Text("Replace current pairing?") },
            text = {
                Text("This pairing link uses a different relay server or encryption key than your current setup. Replace your current pairing?")
            },
            confirmButton = {
                Button(onClick = {
                    pendingReplaceLink = null
                    executePairing(confirmLink)
                }) { Text("Replace") }
            },
            dismissButton = {
                TextButton(onClick = { pendingReplaceLink = null }) { Text("Cancel") }
            }
        )
    }

    if (showAddDevice && canAddDevices) {
        Scaffold(
            topBar = {
                TopAppBar(
                    title = { Text("All-Notify") },
                    actions = {
                        ConnectionPill(connState = connState, isPaused = isPaused)
                        Spacer(Modifier.width(12.dp))
                    }
                )
            }
        ) { padding ->
            Box(Modifier.padding(padding).fillMaxSize()) {
                AddDeviceScreen(
                    app = app,
                    config = config!!,
                    onBack = { showAddDevice = false }
                )
            }
        }
        return
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("All-Notify") },
                actions = {
                    ConnectionPill(connState = connState, isPaused = isPaused)
                    Spacer(Modifier.width(12.dp))
                }
            )
        },
        bottomBar = {
            NavigationBar {
                NavigationBarItem(
                    selected = selectedTab == Tab.HOME,
                    onClick = { selectedTab = Tab.HOME },
                    icon = { Icon(Icons.Default.Home, contentDescription = "Home") },
                    label = { Text("History") }
                )
                NavigationBarItem(
                    selected = selectedTab == Tab.FILTERS,
                    onClick = { selectedTab = Tab.FILTERS },
                    icon = { Icon(Icons.AutoMirrored.Filled.List, contentDescription = "Filters") },
                    label = { Text("App Filters") }
                )
                NavigationBarItem(
                    selected = selectedTab == Tab.SETTINGS,
                    onClick = { selectedTab = Tab.SETTINGS },
                    icon = { Icon(Icons.Default.Settings, contentDescription = "Settings") },
                    label = { Text("Settings") }
                )
            }
        }
    ) { padding ->
        Box(Modifier.padding(padding).fillMaxSize()) {
            when (selectedTab) {
                Tab.HOME -> HomeScreen(
                    app = app,
                    connState = connState,
                    isPaused = isPaused,
                    onTogglePause = { paused -> scope.launch { app.database.setPaused(paused) } },
                    onRepair = onScanQr
                )
                Tab.FILTERS -> AppFiltersScreen(app = app)
                Tab.SETTINGS -> SettingsScreen(
                    app = app,
                    config = config!!,
                    canAddDevices = canAddDevices,
                    permissionStatus = permissionStatus,
                    onOpenAddDevice = { showAddDevice = true },
                    onScanQr = onScanQr,
                    onRequestPostNotifications = onRequestPostNotifications,
                    onRefreshPermissions = onRefreshPermissions
                )
            }
        }
    }
}

@Composable
private fun ConnectionPill(connState: ConnectionState, isPaused: Boolean) {
    val (label, bg) = when {
        connState == ConnectionState.REVOKED -> "Revoked" to MaterialTheme.colorScheme.errorContainer
        isPaused -> "Paused" to MaterialTheme.colorScheme.secondaryContainer
        connState == ConnectionState.CONNECTED -> "Connected" to Color(0xFF1B5E20).copy(alpha = 0.2f)
        connState == ConnectionState.CONNECTING -> "Connecting" to MaterialTheme.colorScheme.tertiaryContainer
        else -> "Offline" to MaterialTheme.colorScheme.surfaceVariant
    }
    Surface(color = bg, shape = RoundedCornerShape(16.dp)) {
        Text(
            text = label,
            style = MaterialTheme.typography.labelMedium,
            modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp)
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun HomeScreen(
    app: AllNotifyApp,
    connState: ConnectionState,
    isPaused: Boolean,
    onTogglePause: (Boolean) -> Unit,
    onRepair: () -> Unit
) {
    var query by rememberSaveable { mutableStateOf("") }
    val itemsFlow = remember(query) {
        if (query.isBlank()) app.database.notificationDao().observeAll()
        else app.database.notificationDao().search(query.trim())
    }
    val notifications by itemsFlow.collectAsState(initial = emptyList())
    val scope = rememberCoroutineScope()

    Column(Modifier.fillMaxSize()) {
        if (connState == ConnectionState.REVOKED) {
            Surface(
                color = MaterialTheme.colorScheme.errorContainer,
                modifier = Modifier.fillMaxWidth()
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp, vertical = 10.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text(
                        text = "Device token revoked. Re-pair to resume.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onErrorContainer,
                        modifier = Modifier.weight(1f)
                    )
                    TextButton(onClick = onRepair) {
                        Text("Re-pair")
                    }
                }
            }
        }

        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Text(
                text = if (isPaused) "Mirroring paused" else "Mirroring active",
                style = MaterialTheme.typography.titleSmall
            )
            Switch(checked = !isPaused, onCheckedChange = { active -> onTogglePause(!active) })
        }

        OutlinedTextField(
            value = query,
            onValueChange = { query = it },
            placeholder = { Text("Search notifications...") },
            leadingIcon = { Icon(Icons.Default.Search, contentDescription = null) },
            trailingIcon = {
                if (query.isNotEmpty()) {
                    IconButton(onClick = { query = "" }) {
                        Icon(Icons.Default.Close, contentDescription = "Clear")
                    }
                }
            },
            singleLine = true,
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 4.dp)
        )

        if (notifications.isEmpty()) {
            Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                Text(
                    text = if (query.isBlank()) "No notifications yet" else "No matching notifications",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        } else {
            LazyColumn(
                contentPadding = PaddingValues(16.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                items(notifications, key = { it.id }) { item ->
                    val currentItem by rememberUpdatedState(item)
                    val isActive = currentItem.dismissedAt == null
                    val dismissState = rememberSwipeToDismissBoxState(
                        confirmValueChange = { value ->
                            if ((value == SwipeToDismissBoxValue.EndToStart || value == SwipeToDismissBoxValue.StartToEnd) &&
                                currentItem.dismissedAt == null
                            ) {
                                scope.launch { app.dismissHistoryItem(currentItem.id) }
                            }
                            false
                        }
                    )
                    SwipeToDismissBox(
                        state = dismissState,
                        enableDismissFromStartToEnd = isActive,
                        enableDismissFromEndToStart = isActive,
                        backgroundContent = {}
                    ) {
                        NotificationHistoryCard(
                            app = app,
                            item = item,
                            onDismiss = { scope.launch { app.dismissHistoryItem(item.id) } }
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun rememberDecodedBitmap(
    cacheKey: String?,
    resolveFile: () -> File?
): ImageBitmap? {
    val cached = cacheKey?.let { decodedBitmapCache.get(it) }
    var bitmap by remember(cacheKey) { mutableStateOf(cached) }
    LaunchedEffect(cacheKey) {
        if (cacheKey == null || bitmap != null) return@LaunchedEffect
        val decoded = withContext(Dispatchers.IO) {
            resolveFile()?.takeIf(File::exists)?.let { f ->
                runCatching { BitmapFactory.decodeFile(f.absolutePath)?.asImageBitmap() }.getOrNull()
            }
        }
        if (decoded != null) {
            decodedBitmapCache.put(cacheKey, decoded)
            bitmap = decoded
        }
    }
    return bitmap
}

@Composable
private fun NotificationHistoryCard(
    app: AllNotifyApp,
    item: NotificationEntity,
    onDismiss: () -> Unit
) {
    val senders = remember(item.senderDevicesJson) {
        Deduplicator.decodeStringList(item.senderDevicesJson).joinToString(", ")
    }
    val iconBitmap = rememberDecodedBitmap(
        cacheKey = item.iconSha256?.let { "icon:$it" },
        resolveFile = { item.iconSha256?.let { app.blobCache.getIconFile(it) } }
    )
    val attachmentBitmap = rememberDecodedBitmap(
        cacheKey = item.attachmentPath?.let { "att:$it" },
        resolveFile = { item.attachmentPath?.let(::File) }
    )
    val formattedTime = remember(item.postedAt) {
        DateFormat.getTimeInstance(DateFormat.SHORT).format(Date(item.postedAt))
    }

    Card(
        colors = CardDefaults.cardColors(
            containerColor = if (item.dismissedAt == null) {
                MaterialTheme.colorScheme.surfaceContainerLow
            } else {
                MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.55f)
            }
        ),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(Modifier.padding(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                val iconBmp = iconBitmap
                if (iconBmp != null) {
                    Image(
                        bitmap = iconBmp,
                        contentDescription = item.appName,
                        modifier = Modifier.size(32.dp).clip(RoundedCornerShape(8.dp))
                    )
                } else {
                    Box(
                        modifier = Modifier
                            .size(32.dp)
                            .clip(CircleShape)
                            .background(MaterialTheme.colorScheme.primaryContainer),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(
                            Icons.Default.Notifications,
                            contentDescription = null,
                            modifier = Modifier.size(18.dp)
                        )
                    }
                }
                Spacer(Modifier.width(10.dp))
                Column(Modifier.weight(1f)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(
                            text = item.appName,
                            style = MaterialTheme.typography.labelLarge,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                        Spacer(Modifier.width(6.dp))
                        val badge = if (item.isMirrored) senders else "Sent"
                        if (badge.isNotBlank()) {
                            Surface(
                                color = MaterialTheme.colorScheme.secondaryContainer,
                                shape = RoundedCornerShape(8.dp)
                            ) {
                                Text(
                                    text = badge,
                                    style = MaterialTheme.typography.labelSmall,
                                    modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis
                                )
                            }
                        }
                    }
                    Text(
                        text = formattedTime + if (item.dismissedAt != null) " • Dismissed" else "",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                if (item.dismissedAt == null) {
                    IconButton(onClick = onDismiss) {
                        Icon(Icons.Default.Close, contentDescription = "Dismiss")
                    }
                }
            }

            if (item.title.isNotBlank()) {
                Spacer(Modifier.height(6.dp))
                Text(
                    text = item.title,
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold
                )
            }
            if (item.body.isNotBlank()) {
                Spacer(Modifier.height(2.dp))
                Text(
                    text = item.body,
                    style = MaterialTheme.typography.bodyMedium,
                    maxLines = 4,
                    overflow = TextOverflow.Ellipsis
                )
            }
            val attBmp = attachmentBitmap
            if (attBmp != null) {
                Spacer(Modifier.height(8.dp))
                Image(
                    bitmap = attBmp,
                    contentDescription = "Attachment",
                    contentScale = ContentScale.Crop,
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(160.dp)
                        .clip(RoundedCornerShape(8.dp))
                )
            }
        }
    }
}

private data class InstalledAppRow(
    val packageName: String,
    val appName: String
)

@Composable
private fun AppFiltersScreen(app: AllNotifyApp) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var search by rememberSaveable { mutableStateOf("") }

    val filterModeRaw by app.database.kvStateDao().observe(KvKeys.FILTER_MODE).collectAsState(initial = null)
    val filterMode = filterModeRaw ?: KvKeys.FILTER_MODE_DENYLIST
    val savedFilters by app.database.appFilterDao().observeAll().collectAsState(initial = emptyList())
    val filterMap = remember(savedFilters) { savedFilters.associateBy { it.packageName } }

    val installedApps by produceState<List<InstalledAppRow>>(initialValue = emptyList()) {
        value = withContext(Dispatchers.IO) {
            val pm = context.packageManager
            val apps: List<ApplicationInfo> = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.getInstalledApplications(PackageManager.ApplicationInfoFlags.of(0))
            } else {
                @Suppress("DEPRECATION")
                pm.getInstalledApplications(0)
            }
            apps
                .filter { it.packageName != BuildConfig.APPLICATION_ID }
                .map { info ->
                    InstalledAppRow(
                        packageName = info.packageName,
                        appName = pm.getApplicationLabel(info).toString()
                    )
                }
                .sortedBy { it.appName.lowercase() }
        }
    }

    val filtered = remember(installedApps, search) {
        if (search.isBlank()) installedApps
        else {
            val q = search.trim().lowercase()
            installedApps.filter {
                it.appName.lowercase().contains(q) || it.packageName.lowercase().contains(q)
            }
        }
    }

    Column(Modifier.fillMaxSize()) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            FilterChip(
                selected = filterMode == KvKeys.FILTER_MODE_DENYLIST,
                onClick = { scope.launch { app.database.setFilterMode(KvKeys.FILTER_MODE_DENYLIST) } },
                label = { Text("Denylist (all except muted)") }
            )
            FilterChip(
                selected = filterMode == KvKeys.FILTER_MODE_ALLOWLIST,
                onClick = { scope.launch { app.database.setFilterMode(KvKeys.FILTER_MODE_ALLOWLIST) } },
                label = { Text("Allowlist") }
            )
        }

        OutlinedTextField(
            value = search,
            onValueChange = { search = it },
            placeholder = { Text("Filter installed apps...") },
            leadingIcon = { Icon(Icons.Default.Search, contentDescription = null) },
            singleLine = true,
            modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 4.dp)
        )

        LazyColumn(contentPadding = PaddingValues(horizontal = 16.dp, vertical = 8.dp)) {
            items(filtered, key = { it.packageName }) { row ->
                val existing = filterMap[row.packageName]
                val defaultEnabled = filterMode != KvKeys.FILTER_MODE_ALLOWLIST
                val enabled = existing?.enabled ?: defaultEnabled
                val allowOngoing = existing?.allowOngoing ?: false

                Column(Modifier.fillMaxWidth().padding(vertical = 6.dp)) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(Modifier.weight(1f)) {
                            Text(row.appName, style = MaterialTheme.typography.bodyLarge)
                            Text(
                                row.packageName,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis
                            )
                        }
                        Switch(
                            checked = enabled,
                            onCheckedChange = { newEnabled ->
                                scope.launch {
                                    app.database.appFilterDao().upsert(
                                        AppFilterEntity(
                                            packageName = row.packageName,
                                            appName = row.appName,
                                            enabled = newEnabled,
                                            allowOngoing = allowOngoing
                                        )
                                    )
                                }
                            }
                        )
                    }
                    if (enabled) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.SpaceBetween,
                            modifier = Modifier.fillMaxWidth().padding(top = 2.dp)
                        ) {
                            Text(
                                "Allow ongoing notifications",
                                style = MaterialTheme.typography.labelMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                            Switch(
                                checked = allowOngoing,
                                onCheckedChange = { newOngoing ->
                                    scope.launch {
                                        app.database.appFilterDao().upsert(
                                            AppFilterEntity(
                                                packageName = row.packageName,
                                                appName = row.appName,
                                                enabled = enabled,
                                                allowOngoing = newOngoing
                                            )
                                        )
                                    }
                                }
                            )
                        }
                    }
                }
                HorizontalDivider()
            }
        }
    }
}

@Composable
private fun OnboardingScreen(
    app: AllNotifyApp,
    permissionStatus: PermissionStatus,
    initialUri: String?,
    onConsumePendingUri: () -> Unit,
    onScanQr: () -> Unit,
    onRequestPostNotifications: () -> Unit,
    onRefreshPermissions: () -> Unit
) {
    var uriInput by rememberSaveable { mutableStateOf("") }
    var errorText by remember { mutableStateOf<String?>(null) }
    var pairing by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    LaunchedEffect(initialUri) {
        if (!initialUri.isNullOrBlank()) {
            uriInput = initialUri
            onConsumePendingUri()
        }
    }

    Surface(Modifier.fillMaxSize()) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .safeDrawingPadding()
                .verticalScroll(rememberScrollState())
                .padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            Spacer(Modifier.height(12.dp))
            Text("All-Notify Setup", style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.Bold)
            Text(
                "Scan the pairing QR code from your All-Notify web admin page or a trusted device, or paste an allnotify://pair URI.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            PermissionChecklistCard(
                status = permissionStatus,
                onRequestPostNotifications = onRequestPostNotifications,
                onRefresh = onRefreshPermissions
            )

            Button(
                onClick = onScanQr,
                enabled = !pairing,
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Scan Pairing QR Code")
            }

            OutlinedTextField(
                value = uriInput,
                onValueChange = {
                    uriInput = it
                    errorText = null
                },
                label = { Text("Pairing URI (allnotify://pair?...)") },
                minLines = 2,
                maxLines = 4,
                isError = errorText != null,
                supportingText = errorText?.let { err -> { Text(err) } },
                modifier = Modifier.fillMaxWidth()
            )

            Button(
                onClick = {
                    val parsed = PairingUriParser.parseLink(uriInput)
                    parsed.onFailure {
                        errorText = it.message ?: "Invalid pairing URI"
                    }.onSuccess { link ->
                        pairing = true
                        errorText = null
                        scope.launch {
                            app.pairFromLink(link)
                                .onFailure { err ->
                                    errorText = err.message ?: "Pairing failed"
                                }
                            pairing = false
                        }
                    }
                },
                enabled = !pairing && uriInput.isNotBlank(),
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(if (pairing) "Pairing..." else "Pair Device")
            }
        }
    }
}

@Composable
private fun SettingsScreen(
    app: AllNotifyApp,
    config: PairingConfig,
    canAddDevices: Boolean,
    permissionStatus: PermissionStatus,
    onOpenAddDevice: () -> Unit,
    onScanQr: () -> Unit,
    onRequestPostNotifications: () -> Unit,
    onRefreshPermissions: () -> Unit
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text("Connected Device", style = MaterialTheme.typography.titleMedium)
                Text("Name: ${config.deviceName}", style = MaterialTheme.typography.bodyMedium)
                Text("Device ID: ${config.deviceId}", style = MaterialTheme.typography.bodySmall)
                Text("Relay URL: ${config.serverUrl}", style = MaterialTheme.typography.bodySmall)
            }
        }

        PermissionChecklistCard(
            status = permissionStatus,
            onRequestPostNotifications = onRequestPostNotifications,
            onRefresh = onRefreshPermissions
        )

        if (canAddDevices) {
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("Add Device", style = MaterialTheme.typography.titleMedium)
                    Text(
                        "Create a one-time pairing QR code to add another phone or laptop to your All-Notify group.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Button(
                        onClick = onOpenAddDevice,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text("Add Device")
                    }
                }
            }
        }

        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
            OutlinedButton(
                onClick = onScanQr,
                modifier = Modifier.weight(1f)
            ) {
                Text("Re-pair via QR")
            }
            OutlinedButton(
                onClick = {
                    scope.launch {
                        app.clearHistory()
                        withContext(Dispatchers.Main) {
                            decodedBitmapCache.evictAll()
                            Toast.makeText(context, "Local history cleared", Toast.LENGTH_SHORT).show()
                        }
                    }
                },
                modifier = Modifier.weight(1f)
            ) {
                Text("Clear History")
            }
        }

        TextButton(
            onClick = {
                decodedBitmapCache.evictAll()
                app.unpair()
            },
            modifier = Modifier.fillMaxWidth()
        ) {
            Text("Unpair This Device", color = MaterialTheme.colorScheme.error)
        }
    }
}

@Composable
private fun PermissionChecklistCard(
    status: PermissionStatus,
    onRequestPostNotifications: () -> Unit,
    onRefresh: () -> Unit
) {
    val context = LocalContext.current
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Row(
                Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text("Permissions & Battery", style = MaterialTheme.typography.titleMedium)
                TextButton(onClick = onRefresh) { Text("Refresh") }
            }
            PermissionRow(
                title = "Notification Access",
                granted = status.notificationAccessGranted,
                onAction = { PermissionHelpers.openNotificationAccessSettings(context) }
            )
            PermissionRow(
                title = "Post Notifications",
                granted = status.postNotificationsGranted,
                onAction = onRequestPostNotifications
            )
            PermissionRow(
                title = "Ignore Battery Optimizations",
                granted = status.batteryOptimizationIgnored,
                onAction = { PermissionHelpers.requestIgnoreBatteryOptimizations(context) }
            )
        }
    }
}

@Composable
private fun PermissionRow(title: String, granted: Boolean, onAction: () -> Unit) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(title, style = MaterialTheme.typography.bodyMedium)
        if (granted) {
            Icon(Icons.Default.Check, contentDescription = "Granted", tint = Color(0xFF2E7D32))
        } else {
            OutlinedButton(onClick = onAction) {
                Text("Grant")
            }
        }
    }
}
