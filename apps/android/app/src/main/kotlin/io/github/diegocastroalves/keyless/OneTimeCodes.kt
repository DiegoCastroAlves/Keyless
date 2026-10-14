package io.github.diegocastroalves.keyless

import android.app.AlarmManager
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.BroadcastReceiver
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.PersistableBundle
import android.os.SystemClock
import android.widget.Toast

/**
 * Secrets on the clipboard: marked sensitive (keyboards and the clipboard
 * preview hide them) and cleared after 90 seconds. Apps in the background
 * cannot see the clipboard, so then it is cleared unless another app's
 * clip is known to be there; an alarm clears it if Keyless is not running
 * by then.
 */
object SecretClipboard {
    const val LABEL = "keyless"
    private const val CLEAR_MS = 90_000L
    private val handler = Handler(Looper.getMainLooper())
    private val token = Any()

    fun copy(context: Context, value: String) {
        val app = context.applicationContext
        val clipboard = app.getSystemService(ClipboardManager::class.java) ?: return
        val clip = ClipData.newPlainText(LABEL, value)
        // ClipDescription.EXTRA_IS_SENSITIVE (Android 13), which some keyboards read earlier too.
        clip.description.extras = PersistableBundle().apply { putBoolean("android.content.extra.IS_SENSITIVE", true) }
        clipboard.setPrimaryClip(clip)
        handler.removeCallbacksAndMessages(token)
        handler.postAtTime({ clear(app) }, token, SystemClock.uptimeMillis() + CLEAR_MS)
        try {
            app.getSystemService(AlarmManager::class.java)?.set(AlarmManager.ELAPSED_REALTIME, SystemClock.elapsedRealtime() + CLEAR_MS, alarm(app))
        } catch (e: Exception) {
            // The handler is enough while Keyless runs.
        }
    }

    private fun alarm(context: Context): PendingIntent =
        PendingIntent.getBroadcast(context, 6001, Intent(context, ClipboardClearReceiver::class.java), PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)

    fun clear(context: Context) {
        handler.removeCallbacksAndMessages(token)
        try {
            context.getSystemService(AlarmManager::class.java)?.cancel(alarm(context))
        } catch (e: Exception) {
            // Nothing scheduled.
        }
        val clipboard = context.getSystemService(ClipboardManager::class.java) ?: return
        try {
            val description = clipboard.primaryClipDescription
            if (description != null && description.label != LABEL) return
            clipboard.clearPrimaryClip()
        } catch (e: Exception) {
            // Not allowed now.
        }
    }
}

/** The alarm that clears the clipboard. */
class ClipboardClearReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        SecretClipboard.clear(context)
    }
}

/** A login's one-time code, copied after Keyless filled the login. */
object OneTimeCodes {
    private const val CHANNEL = "one_time_codes"
    const val NOTIFICATION = 7001

    /**
     * Copies the current code for `uri` (otpauth://) and says so: a
     * notification when allowed, a toast otherwise. Called from a screen in
     * front, it starts ClipboardClearService, which keeps Keyless running
     * until the code is cleared.
     */
    fun copy(context: Context, title: String, uri: String): Boolean {
        val code = try {
            Keyless.totp(uri).getString("code")
        } catch (e: Exception) {
            return false
        }
        SecretClipboard.copy(context, code)
        val app = context.applicationContext
        val kept = try {
            app.startForegroundService(Intent(app, ClipboardClearService::class.java).putExtra(ClipboardClearService.EXTRA_TITLE, title))
            true
        } catch (e: Exception) {
            false
        }
        val shown = notificationsAllowed(app) && (kept || notify(app, title))
        if (!shown) Toast.makeText(app, R.string.totp_copied_toast, Toast.LENGTH_SHORT).show()
        return true
    }

    fun notificationsAllowed(context: Context): Boolean = context.getSystemService(NotificationManager::class.java)?.areNotificationsEnabled() == true

    /** "Code copied", gone when the code is. */
    fun notification(context: Context, title: String): Notification {
        context.getSystemService(NotificationManager::class.java)
            ?.createNotificationChannel(NotificationChannel(CHANNEL, context.getString(R.string.totp_channel), NotificationManager.IMPORTANCE_LOW))
        val builder = Notification.Builder(context, CHANNEL)
            .setSmallIcon(R.drawable.ic_notification_code)
            .setContentTitle(context.getString(R.string.totp_copied_title))
            .setContentText(context.getString(R.string.totp_copied_body, title))
            .setTimeoutAfter(90_000)
            .setOnlyAlertOnce(true)
            .setVisibility(Notification.VISIBILITY_PRIVATE)
        // Shown right away, not after the 10 seconds Android waits for a service's notification.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) builder.setForegroundServiceBehavior(Notification.FOREGROUND_SERVICE_IMMEDIATE)
        return builder.build()
    }

    private fun notify(context: Context, title: String): Boolean {
        val manager = context.getSystemService(NotificationManager::class.java) ?: return false
        return try {
            manager.notify(NOTIFICATION, notification(context, title))
            true
        } catch (e: SecurityException) {
            false
        }
    }
}

/**
 * Keeps Keyless running (a short foreground service, with the "Code
 * copied" notification) while a copied code waits 90 seconds to be
 * cleared: an app in the background is frozen, and its timers with it.
 */
class ClipboardClearService : Service() {
    private val handler = Handler(Looper.getMainLooper())
    private val done = Runnable { finish() }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val notification = OneTimeCodes.notification(this, intent?.getStringExtra(EXTRA_TITLE) ?: "")
        try {
            if (Build.VERSION.SDK_INT >= 34) {
                startForeground(OneTimeCodes.NOTIFICATION, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SHORT_SERVICE)
            } else {
                startForeground(OneTimeCodes.NOTIFICATION, notification)
            }
        } catch (e: Exception) {
            // Not allowed now: the alarm clears the code.
            stopSelf()
            return START_NOT_STICKY
        }
        handler.removeCallbacks(done)
        handler.postDelayed(done, 90_000)
        return START_NOT_STICKY
    }

    private fun finish() {
        handler.removeCallbacks(done)
        SecretClipboard.clear(this)
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    // A short service's time is up (about 3 minutes; Android 14 and later).
    override fun onTimeout(startId: Int) {
        finish()
    }

    override fun onDestroy() {
        handler.removeCallbacks(done)
        super.onDestroy()
    }

    companion object {
        const val EXTRA_TITLE = "title"
    }
}
