package com.allnotify.app.service

import java.util.concurrent.ConcurrentHashMap

/**
 * Tracks sbn.key values cancelled locally due to a remote notification.dismissed event
 * (10-second TTL) so onNotificationRemoved does not re-emit a redundant dismissal echo.
 */
class RemoteCancelGuard(
    private val ttlMs: Long = DEFAULT_TTL_MS,
    private val nowMs: () -> Long = { System.currentTimeMillis() }
) {
    private val entries = ConcurrentHashMap<String, Long>()

    fun markRemotelyCancelled(sbnKey: String) {
        val now = nowMs()
        pruneExpired(now)
        entries[sbnKey] = now
    }

    fun consumeIfRemotelyCancelled(sbnKey: String): Boolean {
        val now = nowMs()
        pruneExpired(now)
        val ts = entries.remove(sbnKey) ?: return false
        return (now - ts) <= ttlMs
    }

    private fun pruneExpired(now: Long) {
        val it = entries.entries.iterator()
        while (it.hasNext()) {
            val entry = it.next()
            if (now - entry.value > ttlMs) {
                it.remove()
            }
        }
    }

    companion object {
        const val DEFAULT_TTL_MS = 10_000L
    }
}
