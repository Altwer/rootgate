package dev.altfurr.rootgate

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.File
import java.io.IOException
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64

class ProtocolTest {
    private val sample = Request(
        id = "00112233445566778899aabbccddeeff",
        nonce = "bm9uY2U=",
        created = 1000,
        expires = 1120,
        uid = 1000,
        user = "alice",
        host = "laptop",
        argv = listOf("/usr/sbin/ufw", "status"),
        why = "check firewall",
    )

    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }

    @Test
    fun canonicalMatchesRustKnownAnswer() {
        val bytes = Canonical.bytes(sample)
        assertEquals(148, bytes.size)
        // Same value pinned in rootgate/src/proto.rs and checked with Python.
        assertEquals("01456f2b5905c964399d2d52ad5a40db00347009233e83e0a32630de68170037", hex(Canonical.sha256(bytes)))
        assertEquals("AFCY8L", Canonical.code(sample))
    }

    @Test
    fun canonicalIsUnambiguous() {
        val a = Canonical.bytes(sample)
        assertFalse(a.contentEquals(Canonical.bytes(sample.copy(argv = listOf("/usr/sbin/uf", "wstatus")))))
        assertFalse(a.contentEquals(Canonical.bytes(sample.copy(argv = listOf("/usr/sbin/ufw"), why = "status"))))
        assertNotEquals(Canonical.code(sample), Canonical.code(sample.copy(argv = listOf("/usr/sbin/ufw", "disable"))))
        // Multi-byte UTF-8 lengths are byte counts, not char counts.
        val cz = sample.copy(why = "čeština")
        assertEquals(148 - 14 + "čeština".toByteArray().size, Canonical.bytes(cz).size)
    }

    @Test
    fun largeUidIsEncodedUnsigned() {
        // 4294967294 must encode as FF FF FF FE like Rust's u32.
        val b = Canonical.bytes(sample.copy(uid = 4294967294L))
        val off = 12 + 36 + 12 + 8 + 8
        assertEquals(listOf(0xFF, 0xFF, 0xFF, 0xFE), (0 until 4).map { b[off + it].toInt() and 0xff })
        assertThrows(IllegalArgumentException::class.java) { Canonical.bytes(sample.copy(uid = -1)) }
        assertThrows(IllegalArgumentException::class.java) { Canonical.bytes(sample.copy(uid = 1L shl 32)) }
    }

    @Test
    fun parsesExactlyWhatRustSends() {
        // Lines as serialized by serde in rootgate's proto.rs.
        assertEquals(FromDaemon.Hello("laptop", 1), Protocol.parse("""{"type":"hello","host":"laptop","proto":1}"""))
        assertEquals(FromDaemon.Ping, Protocol.parse("""{"type":"ping"}"""))
        assertEquals(FromDaemon.Cancel("x", "approved"), Protocol.parse("""{"type":"cancel","id":"x","reason":"approved"}"""))
        assertEquals(FromDaemon.Error(null, "bad"), Protocol.parse("""{"type":"error","id":null,"message":"bad"}"""))
        val line = """{"type":"request","request":{"id":"00112233445566778899aabbccddeeff","nonce":"bm9uY2U=","created":1000,"expires":1120,"uid":1000,"user":"alice","host":"laptop","argv":["/usr/sbin/ufw","status"],"why":"check firewall"},"code":"AFCY8L"}"""
        val m = Protocol.parse(line) as FromDaemon.Req
        assertEquals(sample, m.request)
        assertEquals(Canonical.code(m.request), m.code)
    }

    @Test
    fun strictParsingRejectsJunk() {
        val bad = listOf(
            """{"type":"request","request":{"id":"x"},"code":"A"}""", // missing fields
            // (A quoted number like "1" is accepted by kotlinx for Int fields; harmless:
            // the signed bytes come from the parsed value, which is identical.)
            """{"type":"hello","host":"h","proto":"one"}""", // wrong type
            """{"type":"cancel","id":5,"reason":"x"}""", // number where string expected
            """{"type":"hello","host":"h","proto":1,"evil":true}""", // unknown field
            """{"type":"nope"}""",
            """not json""",
        )
        bad.forEach { s -> assertThrows("should reject: $s", Exception::class.java) { Protocol.parse(s) } }
    }

    @Test
    fun decisionJson() {
        assertEquals("""{"type":"decision","id":"a","approve":true,"sig":"AQ=="}""", Protocol.decision("a", true, "AQ=="))
        assertEquals("""{"type":"decision","id":"a","approve":false,"sig":null}""", Protocol.decision("a", false, null))
        assertEquals("""{"type":"pong"}""", Protocol.PONG)
    }

    @Test
    fun boundedLineReader() {
        val ok = ByteArrayInputStream("hello\nwörld\n".toByteArray())
        assertEquals("hello", Protocol.readLine(ok))
        assertEquals("wörld", Protocol.readLine(ok))
        assertNull(Protocol.readLine(ok))
        assertThrows(IOException::class.java) { Protocol.readLine(ByteArrayInputStream(ByteArray(100) { 'a'.code.toByte() }), 10) }
        assertThrows(IOException::class.java) { Protocol.readLine(ByteArrayInputStream(byteArrayOf(0xff.toByte(), '\n'.code.toByte()))) }
        assertThrows(IOException::class.java) { Protocol.readLine(ByteArrayInputStream("partial".toByteArray())) }
    }

    @Test
    fun checksBlockTricks() {
        val now = 1050L
        assertTrue(Checks.problems(sample, "AFCY8L", now).isEmpty())
        assertTrue(Checks.problems(sample, "AAAAAA", now).any { it.contains("mismatch") })
        assertTrue(Checks.problems(sample, "AFCY8L", 2000).any { it.contains("Expired") })
        val rlo = sample.copy(argv = listOf("/usr/bin/echo", "safe‮fdp"))
        assertTrue(Checks.problems(rlo, Canonical.code(rlo), now).any { it.contains("U+202E") })
        val zw = sample.copy(argv = listOf("/usr/bin/echo", "a​b"))
        assertTrue(Checks.problems(zw, Canonical.code(zw), now).isNotEmpty())
        val esc = sample.copy(why = "x[2J")
        assertTrue(Checks.problems(esc, Canonical.code(esc), now).isNotEmpty())
        val tag = sample.copy(argv = listOf("/usr/bin/echo", "󠁁")) // U+E0041 TAG LATIN A (format)
        assertTrue(Checks.problems(tag, Canonical.code(tag), now).isNotEmpty())
        val rel = sample.copy(argv = listOf("ufw", "status"))
        assertTrue(Checks.problems(rel, Canonical.code(rel), now).isNotEmpty())
        val multiline = sample.copy(why = "line one\nline two")
        assertTrue(Checks.problems(multiline, Canonical.code(multiline), now).isEmpty())
        assertTrue(Checks.hasNonAscii("1ОО.0.0.1")) // Cyrillic O
        assertFalse(Checks.hasNonAscii("100.0.0.1"))
    }

    /**
     * Signs the known-answer request with SHA256withECDSA (what the Keystore does)
     * and writes a vector the Rust verifier checks (rootgate/tests/cross_verify.rs).
     */
    @Test
    fun writeCrossLanguageVector() {
        val kpg = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }
        val kp = kpg.generateKeyPair()
        val sig = Signature.getInstance("SHA256withECDSA").run {
            initSign(kp.private)
            update(Canonical.bytes(sample))
            sign()
        }
        val enc = Base64.getEncoder()
        File("build/rootgate-cross-vector.txt").apply {
            parentFile?.mkdirs()
            writeText(enc.encodeToString(kp.public.encoded) + "\n" + enc.encodeToString(sig) + "\n")
        }
    }
}
