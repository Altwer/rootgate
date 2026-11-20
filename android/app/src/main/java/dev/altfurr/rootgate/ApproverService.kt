package dev.altfurr.rootgate

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.IBinder
import dev.altfurr.rootgate.ui.MainActivity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.BufferedInputStream
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket

/**
 * Keeps one TCP connection to rootgated (over Tailscale), answers pings, and turns
 * incoming requests into notifications. It never approves anything by itself.
 */
class ApproverService : Service() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var job: Job? = null
    @Volatile private var socket: Socket? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        channels(this)
        startForeground(
            FG_ID,
            Notification.Builder(this, CH_SERVICE)
                .setSmallIcon(R.drawable.ic_notify)
                .setContentTitle("RootGate is listening")
                .setContentIntent(openApp(this, null))
                .setOngoing(true)
                .build(),
            ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE,
        )
        if (intent?.action == ACTION_RECONNECT) {
            // Settings changed: drop the connection and restart the loop now, even if
            // it is sleeping in a retry back-off.
            job?.cancel()
            job = null
            try { socket?.close() } catch (_: IOException) {}
        }
        if (job?.isActive != true) job = scope.launch { loop() }
        return START_STICKY
    }

    override fun onDestroy() {
        scope.cancel()
        try { socket?.close() } catch (_: IOException) {}
        Hub.detach()
        Hub.setStatus(Hub.Status.Stopped)
        super.onDestroy()
    }

    private suspend fun loop() {
        var backoff = 2_000L
        while (scope.isActive) {
            val host = Settings.host(this)
            val port = Settings.port(this)
            if (host.isBlank()) {
                Hub.setStatus(Hub.Status.Down("Enter the computer's Tailscale IP in Settings", backoff / 1000))
                delay(backoff)
                backoff = (backoff * 2).coerceAtMost(30_000L)
                continue
            }
            Hub.setStatus(Hub.Status.Connecting("$host:$port"))
            var mine: java.io.OutputStream? = null
            if (!DeviceSafety.vpnUp(this)) {
                // Without Tailscale, 100.x may route to someone else's network.
                Hub.setStatus(Hub.Status.Down("Tailscale (VPN) is off", backoff / 1000))
                delay(backoff)
                backoff = (backoff * 2).coerceAtMost(30_000L)
                continue
            }
            var trusted = false
            var stop = false
            try {
                Socket().use { s ->
                    socket = s
                    s.connect(InetSocketAddress(host, port), 8_000)
                    s.tcpNoDelay = true
                    s.keepAlive = true
                    // Daemon pings every 30 s; 100 s of silence means the link is dead.
                    s.soTimeout = 100_000
                    mine = s.getOutputStream()
                    Hub.attach(mine!!)
                    val input = BufferedInputStream(s.getInputStream())
                    var greeted = false
                    // We speak first: a fresh challenge only the real daemon can sign.
                    val challenge = java.util.Base64.getEncoder().encodeToString(
                        ByteArray(32).also { java.security.SecureRandom().nextBytes(it) },
                    )
                    if (!Hub.send(Protocol.hello(challenge))) throw IOException("could not send hello")
                    while (true) {
                        val line = Protocol.readLine(input) ?: break
                        val msg = try {
                            Protocol.parse(line)
                        } catch (e: Exception) {
                            Hub.note("Ignored malformed message from daemon")
                            continue
                        }
                        if (!greeted && msg !is FromDaemon.Hello) throw IOException("no hello from daemon")
                        when (msg) {
                            is FromDaemon.Hello -> {
                                if (msg.proto != PROTO_VERSION) throw IOException("daemon speaks protocol ${msg.proto}, app speaks $PROTO_VERSION")
                                if (!DaemonAuth.verify(msg.daemonKey, Canonical.helloBytes(challenge, msg.host, msg.daemonKey), msg.sig)) {
                                    throw IOException("daemon failed the challenge")
                                }
                                greeted = true
                                val fp = Canonical.fingerprint(msg.daemonKey)
                                val pinned = Settings.pinnedKey(this)
                                when {
                                    pinned == null -> {
                                        // Ask the user to compare fingerprints; ignore requests until then.
                                        Hub.setStatus(Hub.Status.Untrusted(msg.host, msg.daemonKey, fp))
                                    }
                                    pinned != msg.daemonKey -> {
                                        Hub.setStatus(Hub.Status.KeyMismatch(msg.host, fp))
                                        stop = true
                                        break
                                    }
                                    else -> {
                                        trusted = true
                                        backoff = 2_000L
                                        Hub.setStatus(Hub.Status.Connected(msg.host, fp))
                                    }
                                }
                            }
                            is FromDaemon.Req -> {
                                val key = Settings.pinnedKey(this)
                                if (trusted && key != null &&
                                    DaemonAuth.verify(key, Canonical.daemonRequestBytes(msg.request, msg.warnings), msg.dsig)
                                ) {
                                    onRequest(msg)
                                } else if (trusted) {
                                    Hub.note("Dropped a request that was not signed by your computer")
                                }
                            }
                            is FromDaemon.Cancel -> {
                                Hub.find(msg.id)?.let { History.record(this, it.req, msg.reason) }
                                Hub.remove(msg.id)
                                nm(this).cancel(notifId(msg.id))
                            }
                            is FromDaemon.Error -> Hub.note(msg.message)
                            FromDaemon.Ping -> Hub.send(Protocol.PONG)
                        }
                    }
                }
                Hub.detach(mine)
                if (stop) {
                    // Key mismatch: do not keep reconnecting to a possible impostor.
                    job = null
                    return
                }
                if (Hub.status.value is Hub.Status.Untrusted) {
                    delay(backoff)
                    continue
                }
                Hub.setStatus(Hub.Status.Down("daemon closed the connection", backoff / 1000))
            } catch (e: Exception) {
                Hub.detach(mine)
                Hub.setStatus(Hub.Status.Down(e.message ?: e.javaClass.simpleName, backoff / 1000))
            } finally {
                socket = null
                nm(this).cancelAll()
                startForegroundAgain()
            }
            delay(backoff)
            backoff = (backoff * 2).coerceAtMost(30_000L)
        }
    }

    /** cancelAll() also removes the ongoing notification on some devices; restore it. */
    private fun startForegroundAgain() {
        nm(this).notify(
            FG_ID,
            Notification.Builder(this, CH_SERVICE)
                .setSmallIcon(R.drawable.ic_notify)
                .setContentTitle("RootGate is listening")
                .setContentIntent(openApp(this, null))
                .setOngoing(true)
                .build(),
        )
    }

    private fun onRequest(msg: FromDaemon.Req) {
        val r = msg.request
        val local = try { Canonical.code(r) } catch (e: Exception) { "??????" }
        Hub.upsert(Hub.Pending(r, msg.code, local, msg.warnings))
        // Lock screen shows only that something is pending, never the command.
        val public = Notification.Builder(this, CH_REQUESTS)
            .setSmallIcon(R.drawable.ic_notify)
            .setContentTitle("Root request pending")
            .build()
        val n = Notification.Builder(this, CH_REQUESTS)
            .setSmallIcon(R.drawable.ic_notify)
            .setContentTitle("Root request ${msg.code} from ${r.user}@${r.host}")
            .setContentText((if (msg.warnings.isNotEmpty()) "⚠ " else "") + r.argv.joinToString(" ").take(200))
            .setCategory(Notification.CATEGORY_MESSAGE)
            .setVisibility(Notification.VISIBILITY_PRIVATE)
            .setPublicVersion(public)
            .setContentIntent(openApp(this, r.id))
            .setAutoCancel(true)
            .setTimeoutAfter(((r.expires - System.currentTimeMillis() / 1000).coerceAtLeast(5)) * 1000)
            .build()
        nm(this).notify(notifId(r.id), n)
    }

    companion object {
        const val ACTION_RECONNECT = "dev.altfurr.rootgate.RECONNECT"
        const val EXTRA_ID = "request_id"
        private const val FG_ID = 1
        private const val CH_SERVICE = "service"
        private const val CH_REQUESTS = "requests"

        fun start(c: Context, reconnect: Boolean = false) {
            val i = Intent(c, ApproverService::class.java)
            if (reconnect) i.action = ACTION_RECONNECT
            c.startForegroundService(i)
        }

        fun stop(c: Context) {
            c.stopService(Intent(c, ApproverService::class.java))
        }

        private fun nm(c: Context) = c.getSystemService(NotificationManager::class.java)

        // A real counter per request id: no hash collisions between requests.
        private val ids = java.util.concurrent.ConcurrentHashMap<String, Int>()
        private val nextId = java.util.concurrent.atomic.AtomicInteger(1000)
        private fun notifId(id: String): Int = ids.getOrPut(id) { nextId.getAndIncrement() }

        fun channels(c: Context) {
            nm(c).createNotificationChannel(
                NotificationChannel(CH_SERVICE, "Connection", NotificationManager.IMPORTANCE_MIN),
            )
            nm(c).createNotificationChannel(
                NotificationChannel(CH_REQUESTS, "Root requests", NotificationManager.IMPORTANCE_HIGH).apply {
                    lockscreenVisibility = Notification.VISIBILITY_PRIVATE
                },
            )
        }

        private fun openApp(c: Context, id: String?): PendingIntent {
            val i = Intent(c, MainActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP)
            if (id != null) i.putExtra(EXTRA_ID, id)
            return PendingIntent.getActivity(
                c,
                id?.hashCode() ?: 0,
                i,
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
            )
        }
    }
}
