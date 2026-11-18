package dev.altfurr.rootgate.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import dev.altfurr.rootgate.ApproverService
import dev.altfurr.rootgate.Checks
import dev.altfurr.rootgate.Hub
import dev.altfurr.rootgate.Keys
import dev.altfurr.rootgate.Power
import androidx.compose.material3.Switch
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import dev.altfurr.rootgate.Settings
import kotlinx.coroutines.delay

private val Danger = Color(0xFFFF6B6B)
private val Ok = Color(0xFF4FD1A5)
private val Warn = Color(0xFFFFC857)
private val Mono = FontFamily.Monospace

@Composable
fun App(act: MainActivity) {
    // Ignore touches while another app's window covers ours (tapjacking).
    LocalView.current.filterTouchesWhenObscured = true
    MaterialTheme(colorScheme = darkColorScheme(primary = Ok, error = Danger)) {
        Surface(Modifier.fillMaxSize()) {
            val pending by Hub.pending.collectAsStateWithLifecycle()
            val openId by act.openId
            val open = pending.firstOrNull { it.req.id == openId }
            Column(Modifier.safeDrawingPadding().padding(16.dp)) {
                if (openId != null && open != null) {
                    BackHandler { act.openId.value = null }
                    Detail(act, open) { act.openId.value = null }
                } else {
                    Home(act) { act.openId.value = it }
                }
            }
        }
    }
}

@Composable
private fun Home(act: MainActivity, onOpen: (String) -> Unit) {
    val pending by Hub.pending.collectAsStateWithLifecycle()
    val status by Hub.status.collectAsStateWithLifecycle()
    val notes by Hub.notes.collectAsStateWithLifecycle()
    Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text("RootGate", fontSize = 28.sp, fontWeight = FontWeight.Bold)
        StatusLine(status)
        Text("Pending requests", fontWeight = FontWeight.SemiBold)
        if (pending.isEmpty()) Text("Nothing waiting.", color = Color.Gray)
        pending.forEach { p ->
            Card(Modifier.fillMaxWidth().clickable { onOpen(p.req.id) }) {
                Column(Modifier.padding(12.dp)) {
                    Text("${p.daemonCode}  ${p.req.user}@${p.req.host}", fontWeight = FontWeight.Bold, fontFamily = Mono)
                    Text(p.req.argv.joinToString(" "), fontFamily = Mono, fontSize = 13.sp, maxLines = 2)
                }
            }
        }
        if (notes.isNotEmpty()) {
            Text("From the computer", fontWeight = FontWeight.SemiBold)
            notes.forEach { Text("• $it", fontSize = 13.sp, color = Warn) }
        }
        Spacer(Modifier.height(8.dp))
        Background(act)
        Setup(act)
    }
}

@Composable
private fun StatusLine(s: Hub.Status) {
    val (txt, col) = when (s) {
        Hub.Status.Stopped -> "Stopped" to Color.Gray
        is Hub.Status.Connecting -> "Connecting to ${s.target}…" to Warn
        is Hub.Status.Connected -> "Connected to ${s.host}" to Ok
        is Hub.Status.Down -> "Offline: ${s.reason} (retry in ${s.retryInSecs}s)" to Danger
    }
    Text(txt, color = col)
}

@Composable
private fun Setup(act: MainActivity) {
    var host by remember { mutableStateOf(Settings.host(act)) }
    var port by remember { mutableStateOf(Settings.port(act).toString()) }
    var hasKey by remember { mutableStateOf(Keys.exists()) }
    var msg by remember { mutableStateOf<String?>(null) }
    var confirmDelete by remember { mutableStateOf(false) }

    Text("Setup", fontWeight = FontWeight.SemiBold)
    OutlinedTextField(host, { host = it }, label = { Text("Computer (Tailscale IP)") }, singleLine = true, modifier = Modifier.fillMaxWidth())
    OutlinedTextField(
        port, { port = it.filter(Char::isDigit).take(5) },
        label = { Text("Port") }, singleLine = true,
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
        modifier = Modifier.fillMaxWidth(),
    )
    OutlinedButton(onClick = {
        val p = port.toIntOrNull()
        if (host.isBlank() || p == null || p !in 1..65535) {
            msg = "Invalid host or port"
        } else {
            Settings.save(act, host, p)
            ApproverService.start(act, reconnect = true)
            msg = "Saved, reconnecting"
        }
    }) { Text("Save & reconnect") }

    Spacer(Modifier.height(8.dp))
    Text("Approval key", fontWeight = FontWeight.SemiBold)
    if (!hasKey) {
        Text("Create the key that approves root commands. It never leaves this phone; every use needs your fingerprint or PIN.", fontSize = 13.sp)
        Button(onClick = {
            msg = try {
                val sb = Keys.generate()
                hasKey = true
                if (sb) "Key created in StrongBox" else "Key created in secure hardware"
            } catch (e: Exception) {
                "Could not create key: ${e.message}. Is a screen lock set?"
            }
        }) { Text("Create approval key") }
    } else {
        val pub = remember(hasKey) { runCatching { Keys.publicKeyB64() }.getOrNull() ?: "?" }
        val fp = remember(hasKey) { runCatching { Keys.fingerprint() }.getOrNull() ?: "?" }
        val level = remember(hasKey) { runCatching { Keys.securityLevel() }.getOrNull() ?: "?" }
        Text("Stored in: $level", fontSize = 13.sp, color = if (level.startsWith("SOFTWARE")) Danger else Ok)
        Text("Fingerprint: $fp", fontFamily = Mono, fontSize = 13.sp)
        Text("Public key (paste into approver_pubkeys in /etc/rootgate/config.json):", fontSize = 13.sp)
        Text(pub, fontFamily = Mono, fontSize = 11.sp, modifier = Modifier.border(1.dp, Color.Gray, RoundedCornerShape(6.dp)).padding(8.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(onClick = {
                val cm = act.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                cm.setPrimaryClip(ClipData.newPlainText("rootgate public key", pub))
                msg = "Public key copied (it is not secret)"
            }) { Text("Copy public key") }
            if (!confirmDelete) {
                TextButton(onClick = { confirmDelete = true }) { Text("Delete key", color = Danger) }
            } else {
                TextButton(onClick = {
                    Keys.delete()
                    hasKey = false
                    confirmDelete = false
                    msg = "Key deleted. Remove the old public key from the computer's config too."
                }) { Text("Really delete", color = Danger) }
            }
        }
    }
    msg?.let { Text(it, fontSize = 13.sp, color = Warn) }
}

@Composable
private fun Detail(act: MainActivity, p: Hub.Pending, onClose: () -> Unit) {
    val r = p.req
    var now by remember { mutableLongStateOf(System.currentTimeMillis() / 1000) }
    var armed by remember(r.id) { mutableStateOf(false) }
    var result by remember(r.id) { mutableStateOf<String?>(null) }
    var busy by remember(r.id) { mutableStateOf(false) }
    LaunchedEffect(r.id) {
        // Approve unlocks only after a moment on screen: no blind double-taps.
        delay(1500)
        armed = true
    }
    LaunchedEffect(r.id) {
        while (true) {
            now = System.currentTimeMillis() / 1000
            delay(500)
        }
    }
    val problems = Checks.problems(r, p.daemonCode, now)
    val left = (r.expires - now).coerceAtLeast(0)

    Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        TextButton(onClick = onClose) { Text("← Back") }
        Text("Run as ROOT on ${r.host}?", fontSize = 22.sp, fontWeight = FontWeight.Bold)
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(p.daemonCode, fontSize = 34.sp, fontFamily = Mono, fontWeight = FontWeight.Bold, letterSpacing = 4.sp)
            Spacer(Modifier.width(12.dp))
            Text("must match the code\nin the terminal", fontSize = 12.sp, color = Color.Gray)
        }
        Text("Requested by ${r.user} (uid ${r.uid}) · expires in ${left}s", fontSize = 13.sp, color = if (left < 20) Warn else Color.Gray)

        Text("Exact command (no shell; each box is one argument):", fontSize = 13.sp, fontWeight = FontWeight.SemiBold)
        r.argv.forEachIndexed { i, a ->
            Row(verticalAlignment = Alignment.Top) {
                Text("[$i]", fontFamily = Mono, fontSize = 12.sp, color = Color.Gray, modifier = Modifier.width(36.dp))
                Column(Modifier.weight(1f)) {
                    Text(
                        a.ifEmpty { "(empty)" },
                        fontFamily = Mono,
                        fontSize = 15.sp,
                        fontWeight = if (i == 0) FontWeight.Bold else FontWeight.Normal,
                        modifier = Modifier.fillMaxWidth()
                            .background(Color(0xFF15202B), RoundedCornerShape(6.dp))
                            .padding(8.dp),
                    )
                    if (Checks.hasNonAscii(a)) Text("contains non-ASCII characters, read carefully", fontSize = 11.sp, color = Warn)
                }
            }
        }

        Text("Reason given by the requester (NOT verified):", fontSize = 13.sp, fontWeight = FontWeight.SemiBold, color = Warn)
        Text(r.why, modifier = Modifier.fillMaxWidth().border(1.dp, Warn, RoundedCornerShape(6.dp)).padding(8.dp))

        if (problems.isNotEmpty()) {
            Column(Modifier.fillMaxWidth().border(2.dp, Danger, RoundedCornerShape(6.dp)).padding(8.dp)) {
                Text("Cannot approve:", color = Danger, fontWeight = FontWeight.Bold)
                problems.forEach { Text("• $it", color = Danger, fontSize = 13.sp) }
            }
        }

        Row(horizontalArrangement = Arrangement.spacedBy(12.dp), modifier = Modifier.fillMaxWidth()) {
            OutlinedButton(
                onClick = {
                    act.deny(r.id) { ok -> result = if (ok) "Denied" else "Not connected" }
                },
                modifier = Modifier.weight(1f).height(56.dp),
            ) { Text("Deny", color = Danger, fontSize = 18.sp) }
            Button(
                onClick = {
                    busy = true
                    act.approve(p) { err ->
                        busy = false
                        result = err ?: "Approved, running…"
                    }
                },
                enabled = armed && !busy && problems.isEmpty(),
                colors = ButtonDefaults.buttonColors(containerColor = Ok, contentColor = Color.Black),
                modifier = Modifier.weight(1f).height(56.dp),
            ) { Text("Approve", fontSize = 18.sp) }
        }
        result?.let { Text(it, color = if (it.startsWith("Approved") || it == "Denied") Ok else Danger) }
    }
}

@Composable
private fun Background(act: MainActivity) {
    var free by remember { mutableStateOf(Power.isUnrestricted(act)) }
    var boot by remember { mutableStateOf(Power.startAtBoot(act)) }
    // Re-check when coming back from the system dialog / settings.
    LifecycleEventEffect(Lifecycle.Event.ON_RESUME) { free = Power.isUnrestricted(act) }

    Text("Background", fontWeight = FontWeight.SemiBold)
    if (free) {
        Text("Battery optimization: off. RootGate can stay connected.", fontSize = 13.sp, color = Ok)
    } else {
        Text(
            "Battery optimization is ON: Samsung may cut the connection and requests will not arrive.",
            fontSize = 13.sp,
            color = Danger,
        )
        Button(onClick = { Power.requestUnrestricted(act) }) { Text("Allow running in background") }
    }
    Text(
        "Samsung also has its own list: App info > Battery > Unrestricted, and RootGate must not be in Settings > Battery > Background usage limits > Sleeping apps.",
        fontSize = 12.sp,
        color = Color.Gray,
    )
    TextButton(onClick = { Power.openAppSettings(act) }) { Text("Open App info") }
    Row(verticalAlignment = Alignment.CenterVertically) {
        Switch(checked = boot, onCheckedChange = { boot = it; Power.setStartAtBoot(act, it) })
        Spacer(Modifier.width(8.dp))
        Text("Start after reboot", fontSize = 14.sp)
    }
}
