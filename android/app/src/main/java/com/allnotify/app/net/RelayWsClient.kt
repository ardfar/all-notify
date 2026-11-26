package com.allnotify.app.net

import com.allnotify.app.crypto.PairingConfig
import com.allnotify.app.data.AllNotifyDatabase
import com.allnotify.app.data.OutboxEntity
import com.allnotify.app.protocol.AckFrame
import com.allnotify.app.protocol.ErrorFrame
import com.allnotify.app.protocol.EventFrame
import com.allnotify.app.protocol.IncomingWsFrame
import com.allnotify.app.protocol.ProtocolJson
import com.allnotify.app.protocol.RelayFrame
import com.allnotify.app.protocol.ReplayCompleteFrame
import com.allnotify.app.protocol.parseIncomingWsFrame
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.selects.select
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.serialization.encodeToString
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import kotlin.math.roundToLong
import kotlin.random.Random

enum class ConnectionState {
    DISCONNECTED,
    CONNECTING,
    CONNECTED,
    REVOKED
}

interface RelayFrameHandler {
    suspend fun onReplayStart()
    suspend fun onEvent(frame: EventFrame)
    suspend fun onReplayComplete(frame: ReplayCompleteFrame)
    suspend fun onProtocolError(frame: ErrorFrame) {}
}

/**
 * Persistent WebSocket client with exponential backoff (1s -> 30s ±20% jitter),
 * instant reconnect trigger on network changes, and durable Room outbox flushing.
 */
class RelayWsClient(
    private val httpClient: OkHttpClient,
    private val database: AllNotifyDatabase,
    private val handler: RelayFrameHandler,
    private val backoffScheduleMs: LongArray = DEFAULT_BACKOFF_MS,
    private val nowMs: () -> Long = { System.currentTimeMillis() },
    private val jitterRandom: Random = Random.Default
) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    // Lock ordering invariant: always acquire sendMutex before stateLock (never vice versa).
    private val sendMutex = Mutex()
    private val stateLock = Any()
    private val sessionGen = AtomicLong(0L)
    private val reconnectSignal = Channel<Unit>(Channel.CONFLATED)

    private val _state = MutableStateFlow(ConnectionState.DISCONNECTED)
    val state: StateFlow<ConnectionState> = _state.asStateFlow()

    @Volatile
    private var dialingOrActiveSocket: WebSocket? = null
    @Volatile
    private var activeSocket: WebSocket? = null
    @Volatile
    private var currentConfig: PairingConfig? = null
    private var loopJob: Job? = null

    fun start(config: PairingConfig) {
        val oldSocket: WebSocket?
        val myGen: Long
        synchronized(stateLock) {
            if (currentConfig == config && loopJob?.isActive == true && _state.value != ConnectionState.REVOKED) {
                return
            }
            oldSocket = stopLocked()
            myGen = sessionGen.incrementAndGet()
            currentConfig = config
            loopJob = scope.launch {
                runLoop(config, myGen)
            }
        }
        oldSocket?.close(1000, "client restarting")
    }

    fun stop() {
        val oldSocket = synchronized(stateLock) {
            stopLocked()
        }
        oldSocket?.close(1000, "client stopping")
    }

    private fun stopLocked(): WebSocket? {
        sessionGen.incrementAndGet()
        loopJob?.cancel()
        loopJob = null
        currentConfig = null
        val oldSocket = dialingOrActiveSocket
        dialingOrActiveSocket = null
        activeSocket = null
        _state.value = ConnectionState.DISCONNECTED
        return oldSocket
    }

    private fun setStateIfCurrent(myGen: Long, newState: ConnectionState) {
        synchronized(stateLock) {
            if (sessionGen.get() == myGen) {
                _state.value = newState
            }
        }
    }

    fun shutdown() {
        stop()
        scope.cancel()
    }

    /**
     * Resets backoff and triggers an immediate reconnect (called on NetworkCallback change).
     * When [forceCloseActive] is true, cancels any active/dialing socket so half-open TCP
     * connections on a dropped interface (e.g. Wi-Fi -> cellular handoff) recover immediately.
     */
    fun triggerImmediateReconnect(forceCloseActive: Boolean = true) {
        reconnectSignal.trySend(Unit)
        if (forceCloseActive) {
            dialingOrActiveSocket?.cancel()
        }
    }

    /** Persists to Room outbox first, then flushes in strict FIFO order if connected. */
    suspend fun enqueueAndSend(eventId: String, ciphertext: String): Boolean {
        val frame = RelayFrame(eventId = eventId, ciphertext = ciphertext)
        val raw = ProtocolJson.encodeToString(frame)
        if (raw.toByteArray(Charsets.UTF_8).size > MAX_WS_FRAME_BYTES) {
            return false
        }
        return sendMutex.withLock {
            database.outboxDao().enqueue(
                OutboxEntity(
                    eventId = eventId,
                    ciphertext = ciphertext,
                    createdAt = nowMs()
                )
            )
            val ws = activeSocket ?: return@withLock false
            flushOutboxLocked(ws, targetEventId = eventId)
        }
    }

    suspend fun sendAck(seq: Long): Boolean {
        val raw = ProtocolJson.encodeToString(AckFrame(seq = seq))
        return sendMutex.withLock {
            activeSocket?.send(raw) ?: false
        }
    }

    private suspend fun flushOutboxLocked(ws: WebSocket, targetEventId: String? = null): Boolean {
        val minCreatedAt = nowMs() - AllNotifyDatabase.OUTBOX_TTL_MS
        database.outboxDao().deleteOlderThan(minCreatedAt)
        val pending = database.outboxDao().listValid(minCreatedAt)
        var targetSent = targetEventId == null
        for (item in pending) {
            val raw = ProtocolJson.encodeToString(
                RelayFrame(eventId = item.eventId, ciphertext = item.ciphertext)
            )
            if (raw.toByteArray(Charsets.UTF_8).size > MAX_WS_FRAME_BYTES) {
                database.outboxDao().delete(item.eventId)
                continue
            }
            if (ws.send(raw)) {
                database.outboxDao().delete(item.eventId)
                if (item.eventId == targetEventId) {
                    targetSent = true
                }
            } else {
                break
            }
        }
        return targetSent
    }

    private suspend fun runLoop(config: PairingConfig, myGen: Long) {
        var attempt = 0
        while (currentCoroutineContext().isActive && sessionGen.get() == myGen) {
            // Drain any stale signals before dialing.
            while (reconnectSignal.tryReceive().isSuccess) {
                // no-op
            }
            setStateIfCurrent(myGen, ConnectionState.CONNECTING)
            val outcome = connectOnce(config, myGen)
            if (sessionGen.get() != myGen) return
            when (outcome) {
                ConnectOutcome.REVOKED -> {
                    setStateIfCurrent(myGen, ConnectionState.REVOKED)
                    return
                }
                ConnectOutcome.CONNECTED_THEN_CLOSED -> {
                    attempt = 0
                    setStateIfCurrent(myGen, ConnectionState.DISCONNECTED)
                }
                ConnectOutcome.FAILED -> {
                    setStateIfCurrent(myGen, ConnectionState.DISCONNECTED)
                }
            }

            val delayMs = computeBackoffMs(attempt)
            attempt++
            val resetByNetwork = waitDelayOrSignal(delayMs)
            if (resetByNetwork) {
                attempt = 0
            }
        }
    }

    private enum class ConnectOutcome {
        CONNECTED_THEN_CLOSED,
        FAILED,
        REVOKED
    }

    private suspend fun connectOnce(config: PairingConfig, myGen: Long): ConnectOutcome {
        val afterSeq = database.getLastAckedSeq()
        val wsUrl = "${config.wsUrl}?after_seq=$afterSeq"
        val request = Request.Builder()
            .url(wsUrl)
            .header("Authorization", "Bearer ${config.token}")
            .header("X-AllNotify-Protocol", "1")
            .build()

        val incoming = Channel<String>(Channel.UNLIMITED)
        val closed = CompletableDeferred<ConnectOutcome>()
        val wasOpened = AtomicBoolean(false)

        // Enter replay mode before dialing so no incoming frame can race ahead of onReplayStart.
        handler.onReplayStart()
        if (sessionGen.get() != myGen) return ConnectOutcome.FAILED

        val listener = object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) {
                wasOpened.set(true)
                // Set activeSocket synchronously under stateLock before returning from onOpen so:
                // 1) Fast onOpen firing before newWebSocket() returns is accepted atomically via sessionGen.
                // 2) Subsequent onMessage(replay_complete) -> sendAck() always sees a live activeSocket.
                // 3) Concurrent stop() cannot be overwritten back to CONNECTED.
                val accepted = synchronized(stateLock) {
                    if (sessionGen.get() == myGen && !closed.isCompleted) {
                        dialingOrActiveSocket = webSocket
                        activeSocket = webSocket
                        _state.value = ConnectionState.CONNECTED
                        true
                    } else {
                        false
                    }
                }
                if (accepted) {
                    scope.launch {
                        sendMutex.withLock {
                            if (activeSocket === webSocket) {
                                flushOutboxLocked(webSocket)
                            }
                        }
                    }
                }
            }

            override fun onMessage(webSocket: WebSocket, text: String) {
                incoming.trySend(text)
            }

            override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
                webSocket.close(1000, null)
                val outcome = if (code == 1008 && reason.contains("revoked", ignoreCase = true)) {
                    ConnectOutcome.REVOKED
                } else if (wasOpened.get()) {
                    ConnectOutcome.CONNECTED_THEN_CLOSED
                } else {
                    ConnectOutcome.FAILED
                }
                closed.complete(outcome)
            }

            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                val outcome = if (code == 1008 && reason.contains("revoked", ignoreCase = true)) {
                    ConnectOutcome.REVOKED
                } else if (wasOpened.get()) {
                    ConnectOutcome.CONNECTED_THEN_CLOSED
                } else {
                    ConnectOutcome.FAILED
                }
                closed.complete(outcome)
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                val outcome = when {
                    response?.code == 401 || response?.code == 403 -> ConnectOutcome.REVOKED
                    wasOpened.get() -> ConnectOutcome.CONNECTED_THEN_CLOSED
                    else -> ConnectOutcome.FAILED
                }
                closed.complete(outcome)
            }
        }

        val ws = httpClient.newWebSocket(request, listener)
        val stale = synchronized(stateLock) {
            if (sessionGen.get() == myGen && !closed.isCompleted) {
                dialingOrActiveSocket = ws
                false
            } else {
                true
            }
        }
        if (stale) {
            ws.cancel()
            incoming.close()
            return if (closed.isCompleted) closed.await() else ConnectOutcome.FAILED
        }

        val readerJob = scope.launch {
            for (raw in incoming) {
                val parsed = runCatching { parseIncomingWsFrame(raw) }.getOrNull() ?: continue
                when (parsed) {
                    is IncomingWsFrame.Event -> handler.onEvent(parsed.frame)
                    is IncomingWsFrame.ReplayComplete -> handler.onReplayComplete(parsed.frame)
                    is IncomingWsFrame.Error -> handler.onProtocolError(parsed.frame)
                }
            }
        }

        return try {
            val outcome = closed.await()
            incoming.close()
            readerJob.join()
            outcome
        } finally {
            withContext(NonCancellable) {
                sendMutex.withLock {
                    synchronized(stateLock) {
                        if (activeSocket === ws) {
                            activeSocket = null
                        }
                        if (dialingOrActiveSocket === ws) {
                            dialingOrActiveSocket = null
                        }
                    }
                }
            }
            ws.cancel()
            incoming.close()
            readerJob.cancel()
        }
    }

    internal fun computeBackoffMs(attempt: Int): Long {
        val base = backoffScheduleMs[minOf(attempt, backoffScheduleMs.lastIndex)]
        // ±20% jitter
        val factor = 0.8 + jitterRandom.nextDouble() * 0.4
        return (base * factor).roundToLong().coerceAtLeast(100L)
    }

    private suspend fun waitDelayOrSignal(delayMs: Long): Boolean {
        val timerJob = scope.launch { delay(delayMs) }
        return try {
            select {
                reconnectSignal.onReceive { true }
                timerJob.onJoin { false }
            }
        } finally {
            timerJob.cancel()
        }
    }

    companion object {
        const val MAX_WS_FRAME_BYTES = 65_536
        val DEFAULT_BACKOFF_MS = longArrayOf(1_000, 2_000, 4_000, 8_000, 15_000, 30_000)
    }
}
