package com.allnotify.app.data

import android.app.Application
import androidx.test.core.app.ApplicationProvider
import androidx.work.ListenableWorker
import androidx.work.testing.TestListenableWorkerBuilder
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = Application::class)
class RetentionWorkerTest {

    @Test
    fun workerCompletesCleanlyUnderTestListenableWorkerBuilder() = runBlocking {
        val context = ApplicationProvider.getApplicationContext<Application>()
        val worker = TestListenableWorkerBuilder<RetentionWorker>(context).build()
        val result = worker.doWork()
        assertEquals(ListenableWorker.Result.success(), result)
    }
}
