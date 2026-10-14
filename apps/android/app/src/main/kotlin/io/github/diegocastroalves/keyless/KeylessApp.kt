package io.github.diegocastroalves.keyless

import android.app.Application
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter

class KeylessApp : Application() {
    override fun onCreate() {
        super.onCreate()
        Keyless.init(this)
        // Locks when the screen turns off (a setting, on by default).
        registerReceiver(object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {
                if (Keyless.lockOnScreenOff) Keyless.lock()
            }
        }, IntentFilter(Intent.ACTION_SCREEN_OFF))
    }
}
