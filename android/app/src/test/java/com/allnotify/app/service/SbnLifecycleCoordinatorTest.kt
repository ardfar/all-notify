package com.allnotify.app.service

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SbnLifecycleCoordinatorTest {

    @Test
    fun removalDuringInFlightUploadAbortsGhostPost() = runBlocking {
        val coord = SbnLifecycleCoordinator()
        val key = "0|com.whatsapp|1|null|1000"

        val uploadStarted = CompletableDeferred<Unit>()
        val allowUploadFinish = CompletableDeferred<Unit>()
        var committed = false

        val postJob = async {
            val postSeq = coord.onPostStarted(key)
            try {
                uploadStarted.complete(Unit)
                allowUploadFinish.await()
                coord.withCommitLock(key, postSeq) {
                    committed = true
                    "sent"
                }
            } finally {
                coord.onPostFinished(key)
            }
        }

        uploadStarted.await()
        // User swipes notification away while icon/image upload is still in flight.
        coord.onRemoved(key)
        allowUploadFinish.complete(Unit)

        assertNull("in-flight post must abort instead of sending ghost notification", postJob.await())
        assertFalse(committed)
    }

    @Test
    fun repostWithSameSbnKeyAfterRemovalCommitsCleanly() = runBlocking {
        val coord = SbnLifecycleCoordinator()
        val key = "0|com.whatsapp|1|null|1000"

        val seq1 = coord.onPostStarted(key)
        coord.onRemoved(key)
        val seq2 = coord.onPostStarted(key)

        assertTrue(coord.wasRemovedAfter(key, seq1))
        assertFalse(coord.wasRemovedAfter(key, seq2))

        val res1 = coord.withCommitLock(key, seq1) { "stale" }
        val res2 = coord.withCommitLock(key, seq2) { "fresh" }

        coord.onPostFinished(key)
        coord.onPostFinished(key)

        assertNull(res1)
        assertEquals("fresh", res2)
    }
}
