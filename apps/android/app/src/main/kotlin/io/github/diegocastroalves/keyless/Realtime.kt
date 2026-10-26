package io.github.diegocastroalves.keyless

import android.os.SystemClock
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import org.json.JSONObject
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

/**
 * Sync signals, as the desktop's realtime.rs: while the app is open and
 * unlocked, a WebSocket to Supabase Realtime joined to the account's private
 * topic, "user:<id>". The server sends "sync" there when an item, a vault or
 * its members change on another device (supabase/migrations/
 * 20261026000000_sync_signals.sql), and the app syncs. A signal carries
 * nothing: what changed comes from the sync, checked as always. Only the
 * account's own session can join the topic.
 */
object Realtime {
    /** Realtime drops a connection without a heartbeat for 30 s. */
    private const val HEARTBEAT = 25_000L
    /** A heartbeat unanswered for this long: the connection is gone. */
    private const val NO_ANSWER = 15_000L
    /** Seconds between failed connections, then the last one over and over. */
    private val BACKOFF = longArrayOf(1, 2, 5, 10, 30, 60)
    private const val CLOSED = "\u0000closed"

    private val client by lazy { OkHttpClient.Builder().connectTimeout(15, TimeUnit.SECONDS).readTimeout(0, TimeUnit.SECONDS).build() }

    /** Joined to the topic: signals are arriving. */
    @Volatile var listening = false
        private set
    /** Each start and stop; a connection of an older one ends. */
    @Volatile private var generation = 0
    private var running = false
    private var socket: WebSocket? = null
    @Volatile private var onSignal: () -> Unit = {}

    /** Listens until `stop`; `signal` runs, on a background thread, for each signal and on joining (changes made meanwhile). */
    @Synchronized
    fun start(signal: () -> Unit) {
        onSignal = signal
        if (running || Server.REALTIME == null) return
        running = true
        val mine = ++generation
        thread(name = "keyless-realtime") { run(mine) }
    }

    @Synchronized
    fun stop() {
        running = false
        generation++
        socket?.close(1000, null)
        socket = null
        listening = false
    }

    private fun current(mine: Int): Boolean = generation == mine

    private fun unlocked(): Boolean = try {
        Keyless.status().optBoolean("unlocked")
    } catch (e: Exception) {
        false
    }

    private fun run(mine: Int) {
        var failures = 0
        while (current(mine)) {
            if (!unlocked()) {
                failures = 0
                SystemClock.sleep(1_000)
                continue
            }
            val failed = try {
                listen(mine)
                false
            } catch (e: Exception) {
                true
            }
            listening = false
            if (!failed) {
                failures = 0
                continue
            }
            val wait = BACKOFF[failures.coerceAtMost(BACKOFF.size - 1)]
            failures++
            // Stopped while waiting: ends at the next check.
            for (i in 0 until wait) {
                if (!current(mine)) return
                SystemClock.sleep(1_000)
            }
        }
    }

    private fun frame(topic: String, event: String, payload: JSONObject, ref: Long): String =
        JSONObject().put("topic", topic).put("event", event).put("payload", payload).put("ref", ref.toString()).put("join_ref", "1").toString()

    /** Listens until stopped or locked (returns) or the connection fails (throws). */
    private fun listen(mine: Int) {
        var token = Keyless.token()
        val userId = Keyless.status().optString("userId")
        if (userId.isEmpty()) throw KeylessException("signed_out")
        val inbox = LinkedBlockingQueue<String>()
        val ws = client.newWebSocket(Request.Builder().url(Server.REALTIME ?: return).build(), object : WebSocketListener() {
            override fun onMessage(webSocket: WebSocket, text: String) {
                inbox.put(text)
            }

            override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
                inbox.put(CLOSED)
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                inbox.put(CLOSED)
            }
        })
        synchronized(this) {
            if (!current(mine)) {
                ws.cancel()
                return
            }
            socket = ws
        }
        try {
            val topic = "realtime:user:$userId"
            val config = JSONObject()
                .put("broadcast", JSONObject().put("ack", false).put("self", false))
                .put("presence", JSONObject().put("enabled", false))
                .put("private", true)
            ws.send(frame(topic, "phx_join", JSONObject().put("config", config).put("access_token", token), 1))
            var ref = 1L
            var waiting: String? = null
            var waitingSince = 0L
            var nextHeartbeat = SystemClock.elapsedRealtime() + HEARTBEAT
            while (true) {
                val text = inbox.poll(1, TimeUnit.SECONDS)
                if (!current(mine) || !unlocked()) return
                if (text == CLOSED) throw KeylessException("offline")
                if (text != null) {
                    val message = try {
                        JSONObject(text)
                    } catch (e: Exception) {
                        continue
                    }
                    val event = message.optString("event")
                    val atTopic = message.optString("topic") == topic
                    val payload = message.optJSONObject("payload") ?: JSONObject()
                    when {
                        event == "phx_reply" && message.optString("ref") == "1" -> {
                            if (payload.optString("status") != "ok") throw KeylessException("offline", "join refused")
                            listening = true
                            onSignal()
                        }
                        event == "phx_reply" -> if (message.optString("ref") == waiting) waiting = null
                        event == "broadcast" && atTopic && payload.optString("event") == "sync" -> onSignal()
                        (event == "phx_close" || event == "phx_error") && atTopic -> throw KeylessException("offline", event)
                        event == "system" && atTopic && payload.optString("status") == "error" -> throw KeylessException("offline", payload.optString("message"))
                    }
                }
                val now = SystemClock.elapsedRealtime()
                if (waiting != null && now - waitingSince > NO_ANSWER) throw KeylessException("offline", "no answer")
                if (now < nextHeartbeat) continue
                nextHeartbeat = now + HEARTBEAT
                ref++
                ws.send(frame("phoenix", "heartbeat", JSONObject(), ref))
                waiting = ref.toString()
                waitingSince = now
                // A refreshed session: Realtime closes the channel when the token it has expires.
                val fresh = Keyless.token()
                if (Keyless.status().optString("userId") != userId) throw KeylessException("signed_out")
                if (fresh != token) {
                    token = fresh
                    ref++
                    ws.send(frame(topic, "access_token", JSONObject().put("access_token", token), ref))
                }
            }
        } finally {
            ws.close(1000, null)
            synchronized(this) { if (socket === ws) socket = null }
        }
    }
}
