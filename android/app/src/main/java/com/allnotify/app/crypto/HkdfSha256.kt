package com.allnotify.app.crypto

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** RFC 5869 HKDF-SHA256 key derivation. */
object HkdfSha256 {
    private const val HASH_LEN = 32

    fun derive(
        ikm: ByteArray,
        salt: ByteArray = ByteArray(0),
        info: ByteArray,
        length: Int = HASH_LEN
    ): ByteArray {
        require(length in 1..(255 * HASH_LEN)) { "invalid HKDF output length: $length" }
        val effectiveSalt = if (salt.isEmpty()) ByteArray(HASH_LEN) else salt
        val prk = hmacSha256(effectiveSalt, ikm)

        val out = ByteArray(length)
        var offset = 0
        var block = ByteArray(0)
        var counter = 1
        while (offset < length) {
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(prk, "HmacSHA256"))
            mac.update(block)
            mac.update(info)
            mac.update(counter.toByte())
            block = mac.doFinal()
            val toCopy = minOf(block.size, length - offset)
            System.arraycopy(block, 0, out, offset, toCopy)
            offset += toCopy
            counter++
        }
        return out
    }

    private fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data)
    }
}
