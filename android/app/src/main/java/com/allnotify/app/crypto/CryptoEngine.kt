package com.allnotify.app.crypto

import java.security.GeneralSecurityException
import java.security.SecureRandom
import java.util.Base64

/**
 * Protocol v1 E2EE engine: HKDF-SHA256 domain-separated keys + XChaCha20-Poly1305 with AAD.
 */
class CryptoEngine(kMaster: ByteArray) {
    init {
        require(kMaster.size == 32) { "K_master must be 32 bytes" }
    }

    internal val kEvent: ByteArray = HkdfSha256.derive(
        ikm = kMaster,
        info = EVENT_INFO.toByteArray(Charsets.UTF_8),
        length = 32
    )

    internal val kBlob: ByteArray = HkdfSha256.derive(
        ikm = kMaster,
        info = BLOB_INFO.toByteArray(Charsets.UTF_8),
        length = 32
    )

    private val secureRandom = SecureRandom()

    fun encryptEvent(
        eventId: String,
        senderDeviceId: String,
        plaintextUtf8: String,
        nonce: ByteArray = randomNonce()
    ): String {
        val aad = eventAad(eventId, senderDeviceId)
        val ctAndTag = XChaCha20Poly1305.seal(kEvent, nonce, plaintextUtf8.toByteArray(Charsets.UTF_8), aad)
        val wire = concat(nonce, ctAndTag)
        return Base64.getUrlEncoder().withoutPadding().encodeToString(wire)
    }

    fun decryptEvent(
        eventId: String,
        senderDeviceId: String,
        ciphertextBase64Url: String
    ): String {
        if (!BASE64URL_REGEX.matches(ciphertextBase64Url)) {
            throw GeneralSecurityException("ciphertext is not unpadded base64url")
        }
        val wire = try {
            Base64.getUrlDecoder().decode(ciphertextBase64Url)
        } catch (e: IllegalArgumentException) {
            throw GeneralSecurityException("invalid base64url ciphertext", e)
        }
        if (wire.size < XChaCha20Poly1305.NONCE_SIZE + XChaCha20Poly1305.TAG_SIZE) {
            throw GeneralSecurityException("ciphertext too short")
        }
        val nonce = wire.copyOfRange(0, XChaCha20Poly1305.NONCE_SIZE)
        val ctAndTag = wire.copyOfRange(XChaCha20Poly1305.NONCE_SIZE, wire.size)
        val pt = XChaCha20Poly1305.open(kEvent, nonce, ctAndTag, eventAad(eventId, senderDeviceId))
        return pt.toString(Charsets.UTF_8)
    }

    fun encryptBlob(
        blobId: String,
        plaintext: ByteArray,
        nonce: ByteArray = randomNonce()
    ): ByteArray {
        val ctAndTag = XChaCha20Poly1305.seal(kBlob, nonce, plaintext, blobAad(blobId))
        return concat(nonce, ctAndTag)
    }

    fun decryptBlob(blobId: String, wireBytes: ByteArray): ByteArray {
        if (wireBytes.size < XChaCha20Poly1305.NONCE_SIZE + XChaCha20Poly1305.TAG_SIZE) {
            throw GeneralSecurityException("encrypted blob too short")
        }
        val nonce = wireBytes.copyOfRange(0, XChaCha20Poly1305.NONCE_SIZE)
        val ctAndTag = wireBytes.copyOfRange(XChaCha20Poly1305.NONCE_SIZE, wireBytes.size)
        return XChaCha20Poly1305.open(kBlob, nonce, ctAndTag, blobAad(blobId))
    }

    private fun randomNonce(): ByteArray = ByteArray(XChaCha20Poly1305.NONCE_SIZE).also { secureRandom.nextBytes(it) }

    companion object {
        const val EVENT_INFO = "all-notify:v1:event"
        const val BLOB_INFO = "all-notify:v1:blob"
        private val BASE64URL_REGEX = Regex("^[A-Za-z0-9_-]+$")

        fun eventAad(eventId: String, senderDeviceId: String): ByteArray =
            "v1|$eventId|$senderDeviceId".toByteArray(Charsets.UTF_8)

        fun blobAad(blobId: String): ByteArray =
            "v1|blob|$blobId".toByteArray(Charsets.UTF_8)

        private fun concat(a: ByteArray, b: ByteArray): ByteArray =
            ByteArray(a.size + b.size).also {
                System.arraycopy(a, 0, it, 0, a.size)
                System.arraycopy(b, 0, it, a.size, b.size)
            }
    }
}
