package dev.altfurr.rootgate

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.io.IOException
import java.io.InputStream
import java.security.MessageDigest

const val PROTO_VERSION = 1
const val MAX_LINE = 64 * 1024

/** A root request exactly as the daemon sent it. What we show is what we sign. */
@Serializable
data class Request(
    val id: String,
    val nonce: String,
    val created: Long,
    val expires: Long,
    val uid: Long,
    val user: String,
    val host: String,
    val argv: List<String>,
    val why: String,
)

@Serializable
sealed class FromDaemon {
    @Serializable @SerialName("hello")
    data class Hello(val host: String, val proto: Int) : FromDaemon()

    @Serializable @SerialName("request")
    data class Req(val request: Request, val code: String) : FromDaemon()

    @Serializable @SerialName("cancel")
    data class Cancel(val id: String, val reason: String) : FromDaemon()

    @Serializable @SerialName("error")
    data class Error(val id: String? = null, val message: String) : FromDaemon()

    @Serializable @SerialName("ping")
    data object Ping : FromDaemon()
}

object Protocol {
    /** Strict: unknown fields or wrong types are an error, not silently ignored. */
    val json = Json {
        ignoreUnknownKeys = false
        isLenient = false
        coerceInputValues = false
        classDiscriminator = "type"
    }

    fun parse(line: String): FromDaemon = json.decodeFromString(FromDaemon.serializer(), line)

    fun decision(id: String, approve: Boolean, sigB64: String?): String =
        buildJsonObject {
            put("type", JsonPrimitive("decision"))
            put("id", JsonPrimitive(id))
            put("approve", JsonPrimitive(approve))
            put("sig", sigB64?.let { JsonPrimitive(it) } ?: JsonNull)
        }.toString()

    val PONG: String = buildJsonObject { put("type", JsonPrimitive("pong")) }.toString()

    /** One '\n'-terminated UTF-8 line of at most [max] bytes; null on clean EOF. */
    fun readLine(input: InputStream, max: Int = MAX_LINE): String? {
        val buf = ByteArrayOutputStream(256)
        while (true) {
            val b = input.read()
            if (b == -1) {
                if (buf.size() == 0) return null
                throw IOException("connection closed mid-line")
            }
            if (b == '\n'.code) break
            if (buf.size() >= max) throw IOException("line too long")
            buf.write(b)
        }
        val bytes = buf.toByteArray()
        val decoder = Charsets.UTF_8.newDecoder()
            .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
            .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
        return try {
            decoder.decode(java.nio.ByteBuffer.wrap(bytes)).toString()
        } catch (e: java.nio.charset.CharacterCodingException) {
            throw IOException("line is not UTF-8")
        }
    }
}

/** Must produce byte-for-byte what rootgate's `Request::canonical_bytes()` does. */
object Canonical {
    private val MAGIC = "ROOTGATE-V1\n".toByteArray(Charsets.UTF_8)
    private const val ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

    fun bytes(r: Request): ByteArray {
        require(r.uid in 0..0xFFFF_FFFFL) { "uid out of range" }
        require(r.created >= 0 && r.expires >= 0) { "negative time" }
        val out = ByteArrayOutputStream(256)
        val d = DataOutputStream(out) // big-endian
        d.write(MAGIC)
        str(d, r.id)
        str(d, r.nonce)
        d.writeLong(r.created)
        d.writeLong(r.expires)
        d.writeInt(r.uid.toInt())
        str(d, r.user)
        str(d, r.host)
        d.writeInt(r.argv.size)
        r.argv.forEach { str(d, it) }
        str(d, r.why)
        d.flush()
        return out.toByteArray()
    }

    private fun str(d: DataOutputStream, s: String) {
        val b = s.toByteArray(Charsets.UTF_8)
        d.writeInt(b.size)
        d.write(b)
    }

    fun sha256(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(b)

    fun code(r: Request): String {
        val h = sha256(bytes(r))
        val v = ((h[0].toLong() and 0xff) shl 24) or ((h[1].toLong() and 0xff) shl 16) or
            ((h[2].toLong() and 0xff) shl 8) or (h[3].toLong() and 0xff)
        return (0 until 6).map { ALPHABET[((v shr (27 - 5 * it)) and 31).toInt()] }.joinToString("")
    }
}

/** Reasons the phone refuses to offer "Approve" (it can always deny). */
object Checks {
    /** Same set as the daemon, plus every other invisible/format/private-use char. */
    fun isSuspicious(cp: Int, allowNewline: Boolean): Boolean {
        if (cp == '\n'.code && allowNewline) return false
        return when (Character.getType(cp).toByte()) {
            Character.CONTROL, Character.FORMAT, Character.PRIVATE_USE, Character.SURROGATE,
            Character.UNASSIGNED, Character.LINE_SEPARATOR, Character.PARAGRAPH_SEPARATOR -> true
            else -> cp == 0x00AD || cp == 0x061C || cp == 0x180E ||
                cp in 0x200B..0x200F || cp in 0x2028..0x202E || cp in 0x2060..0x2064 ||
                cp in 0x2066..0x2069 || cp == 0xFEFF || cp in 0xFFF9..0xFFFB
        }
    }

    fun firstSuspicious(s: String, allowNewline: Boolean): Int? =
        s.codePoints().toArray().firstOrNull { isSuspicious(it, allowNewline) }

    fun hasNonAscii(s: String): Boolean = s.any { it.code > 0x7E }

    /** Problems that block approval. Empty list = OK to approve. */
    fun problems(r: Request, daemonCode: String, nowSecs: Long): List<String> {
        val p = mutableListOf<String>()
        if (Canonical.code(r) != daemonCode) p += "Code mismatch: the request was altered on the way."
        if (r.argv.isEmpty()) p += "Empty command."
        else if (!r.argv[0].startsWith("/")) p += "Program is not an absolute path."
        r.argv.forEachIndexed { i, a ->
            firstSuspicious(a, false)?.let { p += "argv[$i] contains hidden character U+%04X.".format(it) }
        }
        firstSuspicious(r.why, true)?.let { p += "Reason contains hidden character U+%04X.".format(it) }
        firstSuspicious(r.user + r.host, false)?.let { p += "User/host contains hidden character U+%04X.".format(it) }
        if (r.expires <= nowSecs) p += "Expired."
        return p
    }
}
