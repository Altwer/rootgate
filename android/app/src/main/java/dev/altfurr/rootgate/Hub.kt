package dev.altfurr.rootgate

import android.content.Context
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update
import java.io.OutputStream

/** In-memory state shared by the connection service and the UI. Nothing is persisted. */
object Hub {
    data class Pending(val req: Request, val daemonCode: String, val localCode: String)

    sealed interface Status {
        data object Stopped : Status
        data class Connecting(val target: String) : Status
        data class Connected(val host: String) : Status
        data class Down(val reason: String, val retryInSecs: Long) : Status
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

/** Where the daemon is. Defaults: none, set in Settings. */
object Settings {
    private const val PREFS = "rootgate"
    const val DEFAULT_HOST = ""
    const val DEFAULT_PORT = 7878

    fun host(c: Context): String =
        c.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString("host", DEFAULT_HOST) ?: DEFAULT_HOST

    fun port(c: Context): Int =
        c.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getInt("port", DEFAULT_PORT)

    fun save(c: Context, host: String, port: Int) {
        c.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putString("host", host.trim()).putInt("port", port).apply()
    }
}
