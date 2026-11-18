package dev.altfurr.rootgate

import android.content.Context
import android.content.pm.ApplicationInfo
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update
import java.io.OutputStream
import android.provider.Settings as AndroidSettings

/** In-memory state shared by the connection service and the UI. Nothing is persisted. */
object Hub {
    data class Pending(
        val req: Request,
        val daemonCode: String,
        val localCode: String,
        val warnings: List<String>,
    )

    sealed interface Status {
        data object Stopped : Status
        data class Connecting(val target: String) : Status
        data class Connected(val host: String, val fingerprint: String) : Status
        data class Down(val reason: String, val retryInSecs: Long) : Status
        /** First contact: the daemon proved it owns this key; the user must confirm it. */
        data class Untrusted(val host: String, val key: String, val fingerprint: String) : Status
        /** A daemon with a DIFFERENT key answered. Possible impostor. */
        data class KeyMismatch(val host: String, val fingerprint: String) : Status
    }

    private val _pending = MutableStateFlow<List<Pending>>(emptyList())
    val pending: StateFlow<List<Pending>> = _pending

    private val _status = MutableStateFlow<Status>(Status.Stopped)
    val status: StateFlow<Status> = _status

    /** Messages from the daemon (e.g. "invalid signature"), newest first, max 10. */
    private val _notes = MutableStateFlow<List<String>>(emptyList())
    val notes: StateFlow<List<String>> = _notes

    private val lock = Any()
    private var out: OutputStream? = null

    fun setStatus(s: Status) { _status.value = s }

    fun note(msg: String) = _notes.update { (listOf(msg) + it).take(10) }

    fun attach(o: OutputStream) = synchronized(lock) { out = o }

    /**
     * Forget the connection. With [only], only if it is still the current one, so a
     * dying old connection can't detach a freshly opened new one.
     */
    fun detach(only: OutputStream? = null) {
        synchronized(lock) {
            if (only != null && out !== only) return
            out = null
        }
        // The daemon re-sends everything still pending when we reconnect.
        _pending.value = emptyList()
    }

    /** Socket writes are not allowed on the main thread; all UI sends go through here. */
    private val io = java.util.concurrent.Executors.newSingleThreadExecutor()
    private val main = android.os.Handler(android.os.Looper.getMainLooper())

    fun sendAsync(line: String, done: (Boolean) -> Unit) {
        io.execute {
            val ok = send(line)
            main.post { done(ok) }
        }
    }

    fun upsert(p: Pending) = _pending.update { list -> list.filter { it.req.id != p.req.id } + p }

    fun remove(id: String) = _pending.update { list -> list.filter { it.req.id != id } }

    fun find(id: String): Pending? = _pending.value.firstOrNull { it.req.id == id }

    /** Send one JSON line. Returns false if not connected or the write failed. */
    fun send(line: String): Boolean = synchronized(lock) {
        val o = out ?: return false
        try {
            o.write((line + "\n").toByteArray(Charsets.UTF_8))
            o.flush()
            true
        } catch (e: Exception) {
            false
        }
    }
}

/** Where the daemon is, and which daemon key we trust. */
object Settings {
    private const val PREFS = "rootgate"
    const val DEFAULT_HOST = ""
    /** Below 1024: only root can listen there on the computer. */
    const val DEFAULT_PORT = 789

    private fun prefs(c: Context) = c.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    fun host(c: Context): String = prefs(c).getString("host", DEFAULT_HOST) ?: DEFAULT_HOST

    fun port(c: Context): Int = prefs(c).getInt("port2", DEFAULT_PORT)

    fun save(c: Context, host: String, port: Int) {
        prefs(c).edit().putString("host", host.trim()).putInt("port2", port).apply()
    }

    fun pinnedKey(c: Context): String? = prefs(c).getString("daemon_key", null)

    fun pin(c: Context, key: String) {
        prefs(c).edit().putString("daemon_key", key).apply()
    }

    fun forgetPin(c: Context) {
        prefs(c).edit().remove("daemon_key").apply()
    }
}

/** Conditions under which another device could tamper with this app. */
object DeviceSafety {
    /** Reasons approving is unsafe right now. Empty = OK. */
    fun problems(c: Context): List<String> {
        val p = mutableListOf<String>()
        val cr = c.contentResolver
        if (AndroidSettings.Global.getInt(cr, AndroidSettings.Global.ADB_ENABLED, 0) == 1) {
            p += "USB debugging is ON: a connected computer could tamper with this app. Turn it off in Developer options."
        }
        if (AndroidSettings.Global.getInt(cr, "adb_wifi_enabled", 0) == 1) {
            p += "Wireless debugging is ON. Turn it off in Developer options."
        }
        if (c.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0) {
            p += "This is a DEBUG build: other programs can inject code into it. Install the signed release build."
        }
        return p
    }

    /** Tailscale on Android is a VPN; without it 100.x addresses may reach a stranger. */
    fun vpnUp(c: Context): Boolean {
        val cm = c.getSystemService(ConnectivityManager::class.java)
        @Suppress("DEPRECATION") // allNetworks is the simplest way to see a split-tunnel VPN
        return cm.allNetworks.any { n ->
            cm.getNetworkCapabilities(n)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
        }
    }
}
