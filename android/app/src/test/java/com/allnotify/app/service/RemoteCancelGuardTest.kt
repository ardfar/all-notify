package com.allnotify.app.service

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RemoteCancelGuardTest {

    @Test
    fun consumesMarkedKeyOnceWithinTtlAndExpiresAfterTtl() {
        var now = 1_000_000L
        val guard = RemoteCancelGuard(ttlMs = 10_000L, nowMs = { now })

        guard.markRemotelyCancelled("0|com.whatsapp|1|null|10001")
        assertFalse(guard.consumeIfRemotelyCancelled("other-key"))
        assertTrue(guard.consumeIfRemotelyCancelled("0|com.whatsapp|1|null|10001"))
        // Consumed once -> second call returns false
        assertFalse(guard.consumeIfRemotelyCancelled("0|com.whatsapp|1|null|10001"))

        // Expiry check (> 10s TTL)
        guard.markRemotelyCancelled("expiring-key")
        now += 10_001L
        assertFalse(guard.consumeIfRemotelyCancelled("expiring-key"))
    }
}
