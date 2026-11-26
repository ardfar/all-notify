package com.allnotify.app.crypto

import java.security.SecureRandom

/** Crockford Base32 ULID generator (26 chars, matching ^[A-Za-z0-9_-]{1,128}$). */
object Ulid {
    private val ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ".toCharArray()
    private val random = SecureRandom()

    fun generate(timestampMs: Long = System.currentTimeMillis()): String {
        val chars = CharArray(26)
        var t = timestampMs
        for (i in 9 downTo 0) {
            chars[i] = ALPHABET[(t and 0x1fL).toInt()]
            t = t ushr 5
        }
        val randBytes = ByteArray(10)
        random.nextBytes(randBytes)
        // Encode 80 bits of randomness into 16 base32 chars
        var bitBuf = 0
        var bitsLeft = 0
        var byteIdx = 0
        for (i in 10 until 26) {
            if (bitsLeft < 5) {
                bitBuf = (bitBuf shl 8) or (randBytes[byteIdx++].toInt() and 0xff)
                bitsLeft += 8
            }
            bitsLeft -= 5
            chars[i] = ALPHABET[(bitBuf ushr bitsLeft) and 0x1f]
        }
        return String(chars)
    }
}
