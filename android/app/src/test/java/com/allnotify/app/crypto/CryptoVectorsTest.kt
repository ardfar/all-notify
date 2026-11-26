package com.allnotify.app.crypto

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.security.GeneralSecurityException
import java.util.Base64

@Serializable
private data class TestVectorsFile(
    @SerialName("protocol_version") val protocolVersion: Int,
    val kdf: KdfVector,
    @SerialName("event_vectors") val eventVectors: List<EventVector>,
    @SerialName("blob_vectors") val blobVectors: List<BlobVector>,
    @SerialName("pairing_uri_vectors") val pairingUriVectors: PairingUriVectors
)

@Serializable
private data class KdfVector(
    val algorithm: String,
    @SerialName("salt_hex") val saltHex: String,
    @SerialName("k_master_hex") val kMasterHex: String,
    @SerialName("k_master_base64url") val kMasterBase64Url: String,
    @SerialName("event_info") val eventInfo: String,
    @SerialName("blob_info") val blobInfo: String,
    @SerialName("k_event_hex") val kEventHex: String,
    @SerialName("k_blob_hex") val kBlobHex: String
)

@Serializable
private data class EventVector(
    val name: String,
    @SerialName("event_id") val eventId: String,
    @SerialName("sender_device_id") val senderDeviceId: String,
    val aad: String,
    @SerialName("nonce_hex") val nonceHex: String,
    @SerialName("plaintext_utf8") val plaintextUtf8: String,
    @SerialName("ciphertext_base64url") val ciphertextBase64Url: String,
    @SerialName("ciphertext_hex") val ciphertextHex: String
)

@Serializable
private data class BlobVector(
    val name: String,
    @SerialName("blob_id") val blobId: String,
    val aad: String,
    @SerialName("nonce_hex") val nonceHex: String,
    @SerialName("plaintext_hex") val plaintextHex: String,
    @SerialName("ciphertext_hex") val ciphertextHex: String
)

@Serializable
private data class PairingUriVectors(
    val valid: List<ValidPairingVector>,
    val invalid: List<InvalidPairingVector>
)

@Serializable
private data class ValidPairingVector(
    val name: String,
    val uri: String,
    val expected: ExpectedPairing
)

@Serializable
private data class ExpectedPairing(
    val v: Int,
    val url: String,
    @SerialName("ws_url") val wsUrl: String,
    val token: String,
    @SerialName("key_base64url") val keyBase64Url: String,
    @SerialName("key_hex") val keyHex: String,
    @SerialName("device_id") val deviceId: String,
    @SerialName("device_name") val deviceName: String
)

@Serializable
private data class InvalidPairingVector(
    val name: String,
    val uri: String,
    val reason: String
)

class CryptoVectorsTest {

    private val json = Json { ignoreUnknownKeys = false }

    private fun loadVectors(): TestVectorsFile {
        val candidates = listOf(
            File("../../protocol/test_vectors.json"),
            File("../protocol/test_vectors.json"),
            File("protocol/test_vectors.json")
        )
        val file = candidates.firstOrNull { it.exists() }
            ?: error("Could not locate protocol/test_vectors.json from ${File(".").absolutePath}")
        return json.decodeFromString<TestVectorsFile>(file.readText())
    }

    @Test
    fun kdfVectorsMatchExactly() {
        val vectors = loadVectors()
        assertEquals(1, vectors.protocolVersion)

        val kMaster = hexToBytes(vectors.kdf.kMasterHex)
        assertEquals(32, kMaster.size)
        assertEquals(
            vectors.kdf.kMasterBase64Url,
            Base64.getUrlEncoder().withoutPadding().encodeToString(kMaster)
        )

        val engine = CryptoEngine(kMaster)
        assertEquals(vectors.kdf.kEventHex, bytesToHex(engine.kEvent))
        assertEquals(vectors.kdf.kBlobHex, bytesToHex(engine.kBlob))
        assertFalse("kEvent and kBlob must be domain-separated", engine.kEvent.contentEquals(engine.kBlob))
    }

    @Test
    fun eventVectorsEncryptDecryptAndRejectTampering() {
        val vectors = loadVectors()
        val engine = CryptoEngine(hexToBytes(vectors.kdf.kMasterHex))
        assertTrue(vectors.eventVectors.isNotEmpty())

        for (ev in vectors.eventVectors) {
            val wantAad = "v1|${ev.eventId}|${ev.senderDeviceId}"
            assertEquals("AAD mismatch for ${ev.name}", ev.aad, wantAad)

            val nonce = hexToBytes(ev.nonceHex)
            val ctB64 = engine.encryptEvent(ev.eventId, ev.senderDeviceId, ev.plaintextUtf8, nonce)
            assertEquals("ciphertext_base64url mismatch for ${ev.name}", ev.ciphertextBase64Url, ctB64)

            val wireBytes = Base64.getUrlDecoder().decode(ctB64)
            assertEquals("ciphertext_hex mismatch for ${ev.name}", ev.ciphertextHex, bytesToHex(wireBytes))

            val decrypted = engine.decryptEvent(ev.eventId, ev.senderDeviceId, ev.ciphertextBase64Url)
            assertEquals("decrypted plaintext mismatch for ${ev.name}", ev.plaintextUtf8, decrypted)

            // Negative: tampered AAD (sender_device_id)
            assertThrowsSecurity {
                engine.decryptEvent(ev.eventId, ev.senderDeviceId + "x", ev.ciphertextBase64Url)
            }
            // Negative: tampered AAD (event_id)
            assertThrowsSecurity {
                engine.decryptEvent(ev.eventId + "x", ev.senderDeviceId, ev.ciphertextBase64Url)
            }
            // Negative: tampered ciphertext byte
            val tampered = wireBytes.copyOf()
            tampered[tampered.lastIndex] = (tampered[tampered.lastIndex].toInt() xor 0x01).toByte()
            val tamperedB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(tampered)
            assertThrowsSecurity {
                engine.decryptEvent(ev.eventId, ev.senderDeviceId, tamperedB64)
            }
            // Negative: wrong key (blob key instead of event key)
            assertThrowsSecurity {
                XChaCha20Poly1305.open(
                    engine.kBlob,
                    wireBytes.copyOfRange(0, 24),
                    wireBytes.copyOfRange(24, wireBytes.size),
                    CryptoEngine.eventAad(ev.eventId, ev.senderDeviceId)
                )
            }
            // Negative: padded base64url rejected
            assertThrowsSecurity {
                engine.decryptEvent(ev.eventId, ev.senderDeviceId, ev.ciphertextBase64Url + "=")
            }
        }
    }

    @Test
    fun blobVectorsEncryptDecryptAndRejectTampering() {
        val vectors = loadVectors()
        val engine = CryptoEngine(hexToBytes(vectors.kdf.kMasterHex))
        assertTrue(vectors.blobVectors.isNotEmpty())

        for (bv in vectors.blobVectors) {
            assertEquals("v1|blob|${bv.blobId}", bv.aad)
            val nonce = hexToBytes(bv.nonceHex)
            val pt = hexToBytes(bv.plaintextHex)

            val ct = engine.encryptBlob(bv.blobId, pt, nonce)
            assertEquals("blob ciphertext_hex mismatch for ${bv.name}", bv.ciphertextHex, bytesToHex(ct))

            val decoded = engine.decryptBlob(bv.blobId, hexToBytes(bv.ciphertextHex))
            assertArrayEquals("blob plaintext mismatch for ${bv.name}", pt, decoded)

            // Negative: wrong blob_id AAD
            assertThrowsSecurity {
                engine.decryptBlob("icon_0000000000000000", ct)
            }
            // Negative: wrong key (event key instead of blob key)
            assertThrowsSecurity {
                XChaCha20Poly1305.open(
                    engine.kEvent,
                    ct.copyOfRange(0, 24),
                    ct.copyOfRange(24, ct.size),
                    CryptoEngine.blobAad(bv.blobId)
                )
            }
        }
    }

    @Test
    fun pairingUriVectorsMatchAllValidAndInvalidCases() {
        val vectors = loadVectors()
        assertTrue(vectors.pairingUriVectors.valid.isNotEmpty())
        assertTrue(vectors.pairingUriVectors.invalid.isNotEmpty())

        for (tc in vectors.pairingUriVectors.valid) {
            val parsed = PairingUriParser.parse(tc.uri).getOrElse {
                throw AssertionError("Valid pairing URI ${tc.name} failed: ${it.message}", it)
            }
            assertEquals("v (${tc.name})", tc.expected.v, parsed.version)
            assertEquals("url (${tc.name})", tc.expected.url, parsed.serverUrl)
            assertEquals("ws_url (${tc.name})", tc.expected.wsUrl, parsed.wsUrl)
            assertEquals("token (${tc.name})", tc.expected.token, parsed.token)
            assertEquals("key_base64url (${tc.name})", tc.expected.keyBase64Url, parsed.keyBase64Url)
            assertEquals("key_hex (${tc.name})", tc.expected.keyHex, bytesToHex(parsed.keyBytes))
            assertEquals("device_id (${tc.name})", tc.expected.deviceId, parsed.deviceId)
            assertEquals("device_name (${tc.name})", tc.expected.deviceName, parsed.deviceName)

            // Round-trip encode -> parse
            val roundTrip = PairingUriParser.parse(PairingUriParser.encode(parsed)).getOrThrow()
            assertEquals(parsed, roundTrip)

            // Never leak secrets in toString()
            val summary = parsed.toString()
            assertFalse(summary.contains(parsed.token))
            assertFalse(summary.contains(parsed.keyBase64Url))
        }

        for (tc in vectors.pairingUriVectors.invalid) {
            val res = PairingUriParser.parse(tc.uri)
            assertTrue(
                "Invalid pairing URI ${tc.name} (${tc.reason}) unexpectedly succeeded: ${res.getOrNull()}",
                res.isFailure
            )
        }
    }

    @Test
    fun ulidIsValidUniqueAndTimeOrdered() {
        val a = Ulid.generate(1_764_060_000_000L)
        val b = Ulid.generate(1_764_060_000_001L)
        assertEquals(26, a.length)
        assertEquals(26, b.length)
        assertTrue(Regex("^[0-9A-Z]{26}$").matches(a))
        assertTrue(b > a)
    }

    private fun assertThrowsSecurity(block: () -> Unit) {
        try {
            block()
            throw AssertionError("Expected GeneralSecurityException")
        } catch (_: GeneralSecurityException) {
            // expected
        }
    }

    private fun hexToBytes(hex: String): ByteArray {
        require(hex.length % 2 == 0)
        return ByteArray(hex.length / 2) { i ->
            hex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
    }

    private fun bytesToHex(bytes: ByteArray): String =
        bytes.joinToString("") { "%02x".format(it) }
}
