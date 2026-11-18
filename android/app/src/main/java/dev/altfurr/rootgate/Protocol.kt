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
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.PublicKey
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

const val PROTO_VERSION = 2
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
    /** Answer to our challenge, signed with the daemon's identity key. */
    @Serializable @SerialName("hello")
    data class Hello(
        val host: String,
        val proto: Int,
        @SerialName("daemon_key") val daemonKey: String,
        val sig: String,
    ) : FromDaemon()

    @Serializable @SerialName("request")
    data class Req(
        val request: Request,
        val code: String,
        val warnings: List<String>,
        val dsig: String,
    ) : FromDaemon()

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

    fun hello(challengeB64: String): String =
        buildJsonObject {
            put("type", JsonPrimitive("hello"))
            put("challenge", JsonPrimitive(challengeB64))
        }.toString()

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
        val decoder = Charsets.UTF_8.newDecoder()
            .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
            .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
        return try {
            decoder.decode(java.nio.ByteBuffer.wrap(buf.toByteArray())).toString()
        } catch (e: java.nio.charset.CharacterCodingException) {
            throw IOException("line is not UTF-8")
        }
    }
}

/** Must produce byte-for-byte what rootgate's proto.rs does. */
object Canonical {
    private val MAGIC = "ROOTGATE-V1\n".toByteArray(Charsets.UTF_8)
    private val HELLO_MAGIC = "ROOTGATE-HELLO-V2\n".toByteArray(Charsets.UTF_8)
    private val DREQ_MAGIC = "ROOTGATE-DREQ-V2\n".toByteArray(Charsets.UTF_8)
    private const val ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

    private inline fun build(f: (DataOutputStream) -> Unit): ByteArray {
        val out = ByteArrayOutputStream(256)
        val d = DataOutputStream(out) // big-endian
        f(d)
        d.flush()
        return out.toByteArray()
    }

    /** What the phone signs to approve. */
    fun bytes(r: Request): ByteArray {
        require(r.uid in 0..0xFFFF_FFFFL) { "uid out of range" }
        require(r.created >= 0 && r.expires >= 0) { "negative time" }
        return build { d ->
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
        }
    }

    /** What the daemon signs to answer our challenge. */
    fun helloBytes(challenge: String, host: String, daemonKey: String): ByteArray = build { d ->
        d.write(HELLO_MAGIC)
        str(d, challenge)
        str(d, host)
        str(d, daemonKey)
    }

    /** What the daemon signs for every request (request + its warnings). */
    fun daemonRequestBytes(r: Request, warnings: List<String>): ByteArray {
        val c = bytes(r)
        return build { d ->
            d.write(DREQ_MAGIC)
            d.writeInt(c.size)
            d.write(c)
            d.writeInt(warnings.size)
            warnings.forEach { str(d, it) }
        }
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

    /** "AB:CD:..." of SHA-256(SPKI), first 8 bytes; same as rootgated logs. */
    fun fingerprint(spkiB64: String): String =
        sha256(Base64.getDecoder().decode(spkiB64)).take(8).joinToString(":") { "%02X".format(it) }
}

/** Verifying the daemon's signatures (P-256, SHA256withECDSA, DER). */
object DaemonAuth {
    fun publicKey(spkiB64: String): PublicKey =
        KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(Base64.getDecoder().decode(spkiB64)))

    fun verify(spkiB64: String, msg: ByteArray, sigB64: String): Boolean = try {
        Signature.getInstance("SHA256withECDSA").run {
            initVerify(publicKey(spkiB64))
            update(msg)
            verify(Base64.getDecoder().decode(sigB64))
        }
    } catch (e: Exception) {
        false
    }
}

/** Reasons the phone refuses to offer "Approve" (it can always deny). */
object Checks {
    /** The daemon's set, plus every other invisible/format/private-use char. */
    fun isSuspicious(cp: Int, allowNewline: Boolean): Boolean {
        if (cp == '\n'.code && allowNewline) return false
        return when (Character.getType(cp).toByte()) {
            Character.CONTROL, Character.FORMAT, Character.PRIVATE_USE, Character.SURROGATE,
            Character.UNASSIGNED, Character.LINE_SEPARATOR, Character.PARAGRAPH_SEPARATOR,
            Character.NON_SPACING_MARK, Character.ENCLOSING_MARK, Character.COMBINING_SPACING_MARK -> true
            Character.SPACE_SEPARATOR -> cp != ' '.code
            else -> cp == 0x00AD || cp == 0x061C || cp == 0x180E || cp == 0x3164 || cp == 0xFFA0 ||
                cp == 0x2800 || cp == 0x115F || cp == 0x1160 || cp == 0x17B4 || cp == 0x17B5 ||
                cp in 0x200B..0x200F || cp in 0x2028..0x202E || cp in 0x2060..0x2064 ||
                cp in 0x2066..0x2069 || cp == 0xFEFF || cp in 0xFFF9..0xFFFB ||
                cp in 0xFE00..0xFE0F || cp in 0xE0000..0xE007F || cp in 0xE0100..0xE01EF
        }
    }

    fun firstSuspicious(s: String, allowNewline: Boolean): Int? =
        s.codePoints().toArray().firstOrNull { isSuspicious(it, allowNewline) }

    fun firstNonAscii(s: String): Int? = s.codePoints().toArray().firstOrNull { it !in 0x20..0x7E }

    fun hasNonAscii(s: String): Boolean = firstNonAscii(s) != null

    /** Problems that block approval. Empty list = OK to approve. */
    fun problems(r: Request, daemonCode: String, nowSecs: Long): List<String> {
        val p = mutableListOf<String>()
        if (Canonical.code(r) != daemonCode) p += "Code mismatch: the request was altered on the way."
        if (r.argv.isEmpty()) p += "Empty command."
        else if (!r.argv[0].startsWith("/")) p += "Program is not an absolute path."
        r.argv.forEachIndexed { i, a ->
            firstNonAscii(a)?.let { p += "argv[$i] contains non-ASCII character U+%04X.".format(it) }
        }
        firstSuspicious(r.why, true)?.let { p += "Reason contains hidden character U+%04X.".format(it) }
        firstSuspicious(r.user + r.host, false)?.let { p += "User/host contains hidden character U+%04X.".format(it) }
        if (r.expires <= nowSecs) p += "Expired."
        return p
    }
}
