package io.github.diegocastroalves.keyless

import android.app.Application

class KeylessApp : Application() {
    override fun onCreate() {
        super.onCreate()
        Keyless.init(this)
    }
}
