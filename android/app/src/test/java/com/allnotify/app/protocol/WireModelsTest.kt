package com.allnotify.app.protocol

import kotlinx.serialization.encodeToString
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class WireModelsTest {

    @Test
    fun parseAndEncodeOuterFrames() {
        val relay = ProtocolJson.encodeToString(
            RelayFrame(eventId = "01JABCDEF", ciphertext = "A".repeat(60))
        )
        assertTrue(relay.contains("\"op\":\"relay\""))
        assertTrue(relay.contains("\"target\":\"broadcast\""))

        val eventRaw = """{"op":"event","seq":42,"event_id":"01JEVT","sender_device_id":"dev_1","server_ts":1764060000123,"ciphertext":"${"A".repeat(60)}"}"""
        val parsedEvent = parseIncomingWsFrame(eventRaw) as IncomingWsFrame.Event
        assertEquals(42L, parsedEvent.frame.seq)
        assertEquals("dev_1", parsedEvent.frame.senderDeviceId)

        val rc = parseIncomingWsFrame("""{"op":"replay_complete","latest_seq":42}""") as IncomingWsFrame.ReplayComplete
        assertEquals(42L, rc.frame.latestSeq)

        val err = parseIncomingWsFrame("""{"op":"error","code":"PAYLOAD_TOO_LARGE","message":"too big"}""") as IncomingWsFrame.Error
        assertEquals("PAYLOAD_TOO_LARGE", err.frame.code)

        assertNull(parseIncomingWsFrame("""{"op":"unknown"}"""))
    }

    @Test
    fun innerPayloadsOmitNullsAndRoundTrip() {
        val minimal = NotificationPostedPayload(
            notificationUid = "dev_1:100:abc",
            senderDeviceName = "Pixel 9",
            postedAt = 100L,
            app = AppInfoPayload(packageName = "com.example", name = "Example"),
            content = ContentPayload(title = "Hi", body = "Hello")
        )
        val raw = encodePostedPayload(minimal)
        assertFalse("null optional fields must be omitted", raw.contains("null"))
        assertFalse(raw.contains("attachments"))

        val decoded = parseInnerPayload(raw) as InnerPayload.Posted
        assertEquals(minimal, decoded.payload)

        val dismissed = NotificationDismissedPayload(
            notificationUids = listOf("u1", "u2"),
            dismissedAt = 200L,
            dismissedByDeviceName = "Pixel 9"
        )
        val dismissedDecoded = parseInnerPayload(encodeDismissedPayload(dismissed)) as InnerPayload.Dismissed
        assertEquals(listOf("u1", "u2"), dismissedDecoded.payload.notificationUids)
        assertNotNull(dismissedDecoded)
    }
}
