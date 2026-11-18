package dev.altfurr.rootgate

import android.content.Context
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.Json

/**
 * Access log: what the daemon reported for each request this phone saw.
 * Stored only in app-private storage (backups are disabled), last 100 entries.
 */
object History {
    @Serializable
    data class Entry(
        val id: String,
        val argv: List<String>,
        val user: String,
        val host: String,
        val time: Long,
        /** approved | denied | expired | withdrawn */
        val status: String,
    )

    private const val KEY = "history_v1"
    private const val MAX = 100
    private val json = Json { ignoreUnknownKeys = true }
    private val _entries = MutableStateFlow<List<Entry>>(emptyList())
    val entries: StateFlow<List<Entry>> = _entries
    @Volatile private var loaded = false

    fun load(c: Context) {
        if (loaded) return
        loaded = true
        val raw = c.getSharedPreferences("rootgate", Context.MODE_PRIVATE).getString(KEY, null) ?: return
        _entries.value = runCatching { json.decodeFromString(ListSerializer(Entry.serializer()), raw) }.getOrDefault(emptyList())
    }

    fun record(c: Context, req: Request, reason: String) {
        load(c)
        val status = when (reason) {
            "approved" -> "approved"
            "denied" -> "denied"
            "expired" -> "expired"
            else -> "withdrawn"
        }
        val e = Entry(req.id, req.argv, req.user, req.host, System.currentTimeMillis() / 1000, status)
        val list = (listOf(e) + _entries.value.filter { it.id != req.id }).take(MAX)
        _entries.value = list
        c.getSharedPreferences("rootgate", Context.MODE_PRIVATE).edit()
            .putString(KEY, json.encodeToString(ListSerializer(Entry.serializer()), list)).apply()
    }

    fun clear(c: Context) {
        _entries.value = emptyList()
        c.getSharedPreferences("rootgate", Context.MODE_PRIVATE).edit().remove(KEY).apply()
    }
}
