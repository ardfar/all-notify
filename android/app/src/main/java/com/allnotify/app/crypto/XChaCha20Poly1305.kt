package com.allnotify.app.crypto

import java.security.GeneralSecurityException
import java.security.MessageDigest

/**
 * Pure Kotlin XChaCha20-Poly1305 (draft-irtf-cfrg-xchacha + RFC 8439).
 * Validated byte-for-byte against protocol/test_vectors.json.
 */
object XChaCha20Poly1305 {
    const val KEY_SIZE = 32
    const val NONCE_SIZE = 24
    const val TAG_SIZE = 16

    private val SIGMA = intArrayOf(
        0x61707865, // "expa"
        0x3320646e, // "nd 3"
        0x79622d32, // "2-by"
        0x6b206574  // "te k"
    )

    /** Returns ciphertext || 16-byte Poly1305 tag. */
    fun seal(key: ByteArray, nonce: ByteArray, plaintext: ByteArray, aad: ByteArray): ByteArray {
        require(key.size == KEY_SIZE) { "key must be $KEY_SIZE bytes" }
        require(nonce.size == NONCE_SIZE) { "nonce must be $NONCE_SIZE bytes" }

        val subKey = hChaCha20(key, nonce)
        val nonce12 = deriveNonce12(nonce)
        val otk = chacha20Block(subKey, 0, nonce12).copyOfRange(0, 32)
        val ciphertext = chacha20Xor(subKey, 1, nonce12, plaintext)
        val tag = poly1305AeadTag(otk, aad, ciphertext)

        return ByteArray(ciphertext.size + TAG_SIZE).apply {
            System.arraycopy(ciphertext, 0, this, 0, ciphertext.size)
            System.arraycopy(tag, 0, this, ciphertext.size, TAG_SIZE)
        }
    }

    /** Decrypts and authenticates ciphertext || 16-byte tag; throws on tag mismatch. */
    fun open(key: ByteArray, nonce: ByteArray, ciphertextAndTag: ByteArray, aad: ByteArray): ByteArray {
        require(key.size == KEY_SIZE) { "key must be $KEY_SIZE bytes" }
        require(nonce.size == NONCE_SIZE) { "nonce must be $NONCE_SIZE bytes" }
        if (ciphertextAndTag.size < TAG_SIZE) {
            throw GeneralSecurityException("ciphertext shorter than Poly1305 tag")
        }

        val ctLen = ciphertextAndTag.size - TAG_SIZE
        val ciphertext = ciphertextAndTag.copyOfRange(0, ctLen)
        val providedTag = ciphertextAndTag.copyOfRange(ctLen, ciphertextAndTag.size)

        val subKey = hChaCha20(key, nonce)
        val nonce12 = deriveNonce12(nonce)
        val otk = chacha20Block(subKey, 0, nonce12).copyOfRange(0, 32)
        val expectedTag = poly1305AeadTag(otk, aad, ciphertext)

        if (!MessageDigest.isEqual(expectedTag, providedTag)) {
            throw GeneralSecurityException("Poly1305 authentication tag mismatch")
        }
        return chacha20Xor(subKey, 1, nonce12, ciphertext)
    }

    private fun deriveNonce12(nonce24: ByteArray): ByteArray {
        val out = ByteArray(12)
        // First 4 bytes are 0x00; last 8 bytes are nonce24[16..23]
        System.arraycopy(nonce24, 16, out, 4, 8)
        return out
    }

    internal fun hChaCha20(key: ByteArray, nonce: ByteArray): ByteArray {
        val state = IntArray(16)
        state[0] = SIGMA[0]
        state[1] = SIGMA[1]
        state[2] = SIGMA[2]
        state[3] = SIGMA[3]
        for (i in 0 until 8) {
            state[4 + i] = loadLE32(key, i * 4)
        }
        for (i in 0 until 4) {
            state[12 + i] = loadLE32(nonce, i * 4)
        }

        repeat(10) {
            quarterRound(state, 0, 4, 8, 12)
            quarterRound(state, 1, 5, 9, 13)
            quarterRound(state, 2, 6, 10, 14)
            quarterRound(state, 3, 7, 11, 15)
            quarterRound(state, 0, 5, 10, 15)
            quarterRound(state, 1, 6, 11, 12)
            quarterRound(state, 2, 7, 8, 13)
            quarterRound(state, 3, 4, 9, 14)
        }

        val out = ByteArray(32)
        for (i in 0 until 4) storeLE32(out, i * 4, state[i])
        for (i in 0 until 4) storeLE32(out, 16 + i * 4, state[12 + i])
        return out
    }

    private fun chacha20Block(key: ByteArray, counter: Int, nonce12: ByteArray): ByteArray {
        val init = IntArray(16)
        init[0] = SIGMA[0]
        init[1] = SIGMA[1]
        init[2] = SIGMA[2]
        init[3] = SIGMA[3]
        for (i in 0 until 8) init[4 + i] = loadLE32(key, i * 4)
        init[12] = counter
        for (i in 0 until 3) init[13 + i] = loadLE32(nonce12, i * 4)

        val work = init.copyOf()
        repeat(10) {
            quarterRound(work, 0, 4, 8, 12)
            quarterRound(work, 1, 5, 9, 13)
            quarterRound(work, 2, 6, 10, 14)
            quarterRound(work, 3, 7, 11, 15)
            quarterRound(work, 0, 5, 10, 15)
            quarterRound(work, 1, 6, 11, 12)
            quarterRound(work, 2, 7, 8, 13)
            quarterRound(work, 3, 4, 9, 14)
        }

        val out = ByteArray(64)
        for (i in 0 until 16) {
            storeLE32(out, i * 4, work[i] + init[i])
        }
        return out
    }

    private fun chacha20Xor(key: ByteArray, initialCounter: Int, nonce12: ByteArray, input: ByteArray): ByteArray {
        val out = ByteArray(input.size)
        var counter = initialCounter
        var offset = 0
        while (offset < input.size) {
            val block = chacha20Block(key, counter++, nonce12)
            val n = minOf(64, input.size - offset)
            for (i in 0 until n) {
                out[offset + i] = (input[offset + i].toInt() xor block[i].toInt()).toByte()
            }
            offset += n
        }
        return out
    }

    private fun quarterRound(s: IntArray, a: Int, b: Int, c: Int, d: Int) {
        s[a] += s[b]; s[d] = (s[d] xor s[a]).rotateLeft(16)
        s[c] += s[d]; s[b] = (s[b] xor s[c]).rotateLeft(12)
        s[a] += s[b]; s[d] = (s[d] xor s[a]).rotateLeft(8)
        s[c] += s[d]; s[b] = (s[b] xor s[c]).rotateLeft(7)
    }

    /** RFC 8439 Poly1305 AEAD construction using 5x26-bit limbs (poly1305-donna). */
    private fun poly1305AeadTag(otk: ByteArray, aad: ByteArray, ciphertext: ByteArray): ByteArray {
        val aadPad = (16 - (aad.size % 16)) % 16
        val ctPad = (16 - (ciphertext.size % 16)) % 16
        val macData = ByteArray(aad.size + aadPad + ciphertext.size + ctPad + 16)

        var pos = 0
        System.arraycopy(aad, 0, macData, pos, aad.size)
        pos += aad.size + aadPad
        System.arraycopy(ciphertext, 0, macData, pos, ciphertext.size)
        pos += ciphertext.size + ctPad
        storeLE64(macData, pos, aad.size.toLong())
        storeLE64(macData, pos + 8, ciphertext.size.toLong())

        return poly1305Mac(otk, macData)
    }

    private fun poly1305Mac(key: ByteArray, msg: ByteArray): ByteArray {
        // Clamp r (RFC 8439 §2.5) into 5 x 26-bit limbs using unsigned 32-bit loads
        val r0 = loadLE32U(key, 0) and 0x03ffffffL
        val r1 = (loadLE32U(key, 3) ushr 2) and 0x03ffff03L
        val r2 = (loadLE32U(key, 6) ushr 4) and 0x03ffc0ffL
        val r3 = (loadLE32U(key, 9) ushr 6) and 0x03f03fffL
        val r4 = (loadLE32U(key, 12) ushr 8) and 0x000fffffL

        val s1 = r1 * 5
        val s2 = r2 * 5
        val s3 = r3 * 5
        val s4 = r4 * 5

        var h0 = 0L
        var h1 = 0L
        var h2 = 0L
        var h3 = 0L
        var h4 = 0L

        var offset = 0
        val block = ByteArray(16)
        while (offset < msg.size) {
            val remaining = msg.size - offset
            val blockLen = minOf(16, remaining)
            block.fill(0)
            System.arraycopy(msg, offset, block, 0, blockLen)

            val hibit: Long
            if (blockLen < 16) {
                block[blockLen] = 1
                hibit = 0L
            } else {
                hibit = 1L shl 24
            }

            h0 += loadLE32U(block, 0) and 0x03ffffffL
            h1 += (loadLE32U(block, 3) ushr 2) and 0x03ffffffL
            h2 += (loadLE32U(block, 6) ushr 4) and 0x03ffffffL
            h3 += (loadLE32U(block, 9) ushr 6) and 0x03ffffffL
            h4 += ((loadLE32U(block, 12) ushr 8) and 0x00ffffffL) or hibit

            val d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1
            var d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2
            var d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3
            var d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4
            var d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0

            var c = d0 ushr 26; h0 = d0 and 0x3ffffffL
            d1 += c; c = d1 ushr 26; h1 = d1 and 0x3ffffffL
            d2 += c; c = d2 ushr 26; h2 = d2 and 0x3ffffffL
            d3 += c; c = d3 ushr 26; h3 = d3 and 0x3ffffffL
            d4 += c; c = d4 ushr 26; h4 = d4 and 0x3ffffffL
            h0 += c * 5; c = h0 ushr 26; h0 = h0 and 0x3ffffffL
            h1 += c

            offset += blockLen
        }

        // Final carry
        var c = h1 ushr 26; h1 = h1 and 0x3ffffffL
        h2 += c; c = h2 ushr 26; h2 = h2 and 0x3ffffffL
        h3 += c; c = h3 ushr 26; h3 = h3 and 0x3ffffffL
        h4 += c; c = h4 ushr 26; h4 = h4 and 0x3ffffffL
        h0 += c * 5; c = h0 ushr 26; h0 = h0 and 0x3ffffffL
        h1 += c

        // Compute h + (-p) = h + 5 - 2^130
        var g0 = h0 + 5; c = g0 ushr 26; g0 = g0 and 0x3ffffffL
        var g1 = h1 + c; c = g1 ushr 26; g1 = g1 and 0x3ffffffL
        var g2 = h2 + c; c = g2 ushr 26; g2 = g2 and 0x3ffffffL
        var g3 = h3 + c; c = g3 ushr 26; g3 = g3 and 0x3ffffffL
        var g4 = h4 + c - (1L shl 26)

        // Constant-time select h if h < p else g
        var mask = (g4 ushr 63) - 1L
        g0 = g0 and mask
        g1 = g1 and mask
        g2 = g2 and mask
        g3 = g3 and mask
        g4 = g4 and mask
        mask = mask.inv()
        h0 = (h0 and mask) or g0
        h1 = (h1 and mask) or g1
        h2 = (h2 and mask) or g2
        h3 = (h3 and mask) or g3
        h4 = (h4 and mask) or g4

        // Pack into 4 x 32-bit words and add s = key[16..31]
        val f0 = ((h0) or (h1 shl 26)) and 0xffffffffL
        val f1 = ((h1 ushr 6) or (h2 shl 20)) and 0xffffffffL
        val f2 = ((h2 ushr 12) or (h3 shl 14)) and 0xffffffffL
        val f3 = ((h3 ushr 18) or (h4 shl 8)) and 0xffffffffL

        var t0 = f0 + (loadLE32(key, 16).toLong() and 0xffffffffL)
        var t1 = f1 + (loadLE32(key, 20).toLong() and 0xffffffffL) + (t0 ushr 32)
        var t2 = f2 + (loadLE32(key, 24).toLong() and 0xffffffffL) + (t1 ushr 32)
        val t3 = f3 + (loadLE32(key, 28).toLong() and 0xffffffffL) + (t2 ushr 32)

        val tag = ByteArray(16)
        storeLE32(tag, 0, t0.toInt())
        storeLE32(tag, 4, t1.toInt())
        storeLE32(tag, 8, t2.toInt())
        storeLE32(tag, 12, t3.toInt())
        return tag
    }

    private fun loadLE32U(b: ByteArray, offset: Int): Long =
        loadLE32(b, offset).toLong() and 0xffffffffL

    private fun loadLE32(b: ByteArray, offset: Int): Int {
        return (b[offset].toInt() and 0xff) or
            ((b[offset + 1].toInt() and 0xff) shl 8) or
            ((b[offset + 2].toInt() and 0xff) shl 16) or
            ((b[offset + 3].toInt() and 0xff) shl 24)
    }

    private fun storeLE32(b: ByteArray, offset: Int, v: Int) {
        b[offset] = (v and 0xff).toByte()
        b[offset + 1] = ((v ushr 8) and 0xff).toByte()
        b[offset + 2] = ((v ushr 16) and 0xff).toByte()
        b[offset + 3] = ((v ushr 24) and 0xff).toByte()
    }

    private fun storeLE64(b: ByteArray, offset: Int, v: Long) {
        storeLE32(b, offset, (v and 0xffffffffL).toInt())
        storeLE32(b, offset + 4, ((v ushr 32) and 0xffffffffL).toInt())
    }
}
