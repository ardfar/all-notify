package com.allnotify.app.data

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import com.allnotify.app.AllNotifyApp
import java.util.concurrent.TimeUnit

class RetentionWorker(
    appContext: Context,
    params: WorkerParameters
) : CoroutineWorker(appContext, params) {

    override suspend fun doWork(): Result {
        val app = applicationContext as? AllNotifyApp ?: return Result.success()
        app.database.pruneRetention(app.blobCache)
        return Result.success()
    }

    companion object {
        private const val WORK_NAME = "all_notify_daily_retention"

        fun schedule(context: Context) {
            val req = PeriodicWorkRequestBuilder<RetentionWorker>(24, TimeUnit.HOURS).build()
            WorkManager.getInstance(context).enqueueUniquePeriodicWork(
                WORK_NAME,
                ExistingPeriodicWorkPolicy.KEEP,
                req
            )
        }
    }
}
