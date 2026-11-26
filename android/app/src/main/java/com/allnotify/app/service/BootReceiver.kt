package com.allnotify.app.service

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import com.allnotify.app.AllNotifyApp

class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent?) {
        val action = intent?.action ?: return
        if (action != Intent.ACTION_BOOT_COMPLETED && action != Intent.ACTION_MY_PACKAGE_REPLACED) return
        val app = context.applicationContext as? AllNotifyApp ?: return
        if (app.currentConfig() != null) {
            app.ensureRelayRunning()
        }
    }
}
