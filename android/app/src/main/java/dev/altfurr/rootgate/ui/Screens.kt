package dev.altfurr.rootgate.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import androidx.activity.compose.BackHandler
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Check
import androidx.compose.material.icons.outlined.Close
import androidx.compose.material.icons.outlined.Dns
import androidx.compose.material.icons.outlined.Fingerprint
import androidx.compose.material.icons.outlined.GppBad
import androidx.compose.material.icons.outlined.GppGood
import androidx.compose.material.icons.outlined.GppMaybe
import androidx.compose.material.icons.outlined.History
import androidx.compose.material.icons.outlined.Home
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.Person
import androidx.compose.material.icons.outlined.Schedule
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material.icons.outlined.Terminal
import androidx.compose.material.icons.outlined.Warning
import androidx.compose.material.icons.automirrored.outlined.ArrowBack
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
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
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.blur
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import dev.altfurr.rootgate.ApproverService
import dev.altfurr.rootgate.BuildConfig
import dev.altfurr.rootgate.Canonical
import dev.altfurr.rootgate.Checks
import dev.altfurr.rootgate.DeviceSafety
import dev.altfurr.rootgate.History
import dev.altfurr.rootgate.Hub
import dev.altfurr.rootgate.Keys
import dev.altfurr.rootgate.Power
import dev.altfurr.rootgate.Request
import dev.altfurr.rootgate.Settings
import kotlinx.coroutines.delay

/** Palette from the design (Tailwind slate / emerald / rose / cyan). */
private object RG {
    val Bg = Color(0xFF020617) // slate-950
    val Card = Color(0xFF0F172A) // slate-900
    val Line = Color(0xFF1E293B) // slate-800
    val Text = Color(0xFFE2E8F0) // slate-200
    val Text2 = Color(0xFFCBD5E1) // slate-300
    val Muted = Color(0xFF94A3B8) // slate-400
    val Faint = Color(0xFF64748B) // slate-500
    val Ok = Color(0xFF10B981) // emerald-500
    val OkText = Color(0xFF34D399) // emerald-400
    val Bad = Color(0xFFF43F5E) // rose-500
    val BadText = Color(0xFFFB7185) // rose-400
    val Accent = Color(0xFF06B6D4) // cyan-500
    val Accent2 = Color(0xFF22D3EE) // cyan-400
    val Warn = Color(0xFFF59E0B) // amber-500
    val Code = Color(0x99000000) // black/60
}

private val Mono = FontFamily.Monospace

private enum class Tab { Home, History, Settings }

@Composable
fun App(act: MainActivity) {
    // Ignore touches while another app's window covers ours (tapjacking).
    LocalView.current.filterTouchesWhenObscured = true
    var tab by remember { mutableStateOf(Tab.Home) }
    val pending by Hub.pending.collectAsStateWithLifecycle()
    MaterialTheme(colorScheme = darkColorScheme(primary = RG.Accent, background = RG.Bg, surface = RG.Bg, error = RG.Bad)) {
        Box(Modifier.fillMaxSize().background(RG.Bg)) {
            // Subtle cyan glow at the top, as in the design.
            Box(
                Modifier.fillMaxWidth().height(320.dp).blur(100.dp)
                    .background(Brush.verticalGradient(listOf(Color(0x1A164E63), Color.Transparent))),
            )
            Column(Modifier.fillMaxSize().statusBarsPadding().navigationBarsPadding()) {
                Header(active = pending.isNotEmpty(), onSettings = { tab = if (tab == Tab.Settings) Tab.Home else Tab.Settings })
                Box(Modifier.weight(1f).fillMaxWidth()) {
                    when (tab) {
                        Tab.Home -> HomeScreen(act)
                        Tab.History -> HistoryScreen(act)
                        Tab.Settings -> {
                            BackHandler { tab = Tab.Home }
                            SettingsScreen(act) { tab = Tab.Home }
                        }
                    }
                }
                BottomNav(tab, alert = pending.isNotEmpty() && tab != Tab.Home) { tab = it }
            }
        }
    }
}

// ------------------------------------------------------------------ chrome

@Composable
private fun Header(active: Boolean, onSettings: () -> Unit) {
    Column {
        Row(
            Modifier.fillMaxWidth().padding(start = 24.dp, end = 16.dp, top = 16.dp, bottom = 14.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Box(Modifier.clip(RoundedCornerShape(8.dp)).background(RG.Accent).padding(6.dp)) {
                Icon(Icons.Outlined.Terminal, null, tint = Color.Black, modifier = Modifier.size(16.dp))
            }
            Spacer(Modifier.width(8.dp))
            Text("RootGate", color = Color.White, fontWeight = FontWeight.Bold, fontSize = 18.sp)
            if (BuildConfig.DEBUG) {
                Spacer(Modifier.width(6.dp))
                Pill("DEV", RG.Warn)
            }
            Spacer(Modifier.weight(1f))
            if (active) {
                val t = rememberInfiniteTransition(label = "active")
                val a by t.animateFloat(0.45f, 1f, infiniteRepeatable(tween(900), RepeatMode.Reverse), label = "a")
                Row(
                    Modifier.alpha(a).clip(CircleShape).background(RG.Bad.copy(alpha = 0.1f)).padding(horizontal = 8.dp, vertical = 4.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Icon(Icons.Outlined.Warning, null, tint = RG.Bad, modifier = Modifier.size(12.dp))
                    Spacer(Modifier.width(4.dp))
                    Text("ACTIVE", color = RG.Bad, fontSize = 10.sp, fontWeight = FontWeight.Bold, letterSpacing = 1.sp)
                }
                Spacer(Modifier.width(12.dp))
            }
            Icon(
                Icons.Outlined.Settings, "Settings", tint = RG.Muted,
                modifier = Modifier.clip(CircleShape).clickable(onClick = onSettings).padding(4.dp).size(22.dp),
            )
        }
        Box(Modifier.fillMaxWidth().height(1.dp).background(RG.Line.copy(alpha = 0.5f)))
    }
}

@Composable
private fun BottomNav(tab: Tab, alert: Boolean, onTab: (Tab) -> Unit) {
    Column {
        Box(Modifier.fillMaxWidth().height(1.dp).background(RG.Line.copy(alpha = 0.8f)))
        Row(
            Modifier.fillMaxWidth().background(RG.Bg.copy(alpha = 0.9f)).padding(top = 8.dp, bottom = 10.dp),
            horizontalArrangement = Arrangement.SpaceAround,
        ) {
            NavItem(Icons.Outlined.Home, "Home", tab == Tab.Home, alert) { onTab(Tab.Home) }
            NavItem(Icons.Outlined.History, "History", tab == Tab.History, false) { onTab(Tab.History) }
        }
    }
}

@Composable
private fun NavItem(icon: ImageVector, label: String, selected: Boolean, dot: Boolean, onClick: () -> Unit) {
    val c = if (selected) RG.Accent2 else RG.Faint
    Column(
        Modifier.clip(RoundedCornerShape(12.dp)).clickable(onClick = onClick).padding(horizontal = 20.dp, vertical = 6.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Box {
            Icon(icon, label, tint = c, modifier = Modifier.size(22.dp))
            if (dot) {
                Box(
                    Modifier.align(Alignment.TopEnd).size(10.dp).clip(CircleShape).background(RG.Bg).padding(2.dp)
                        .clip(CircleShape).background(RG.Bad),
                )
            }
        }
        Spacer(Modifier.height(4.dp))
        Text(label, color = c, fontSize = 10.sp, fontWeight = FontWeight.Medium)
    }
}

@Composable
private fun Pill(text: String, color: Color) {
    Text(
        text, color = color, fontSize = 10.sp, fontWeight = FontWeight.Bold, letterSpacing = 1.sp,
        modifier = Modifier.clip(CircleShape).background(color.copy(alpha = 0.12f)).padding(horizontal = 8.dp, vertical = 3.dp),
    )
}

@Composable
private fun Label(icon: ImageVector, text: String, color: Color = RG.Muted) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Icon(icon, null, tint = color, modifier = Modifier.size(14.dp))
        Spacer(Modifier.width(8.dp))
        Text(text.uppercase(), color = color, fontSize = 11.sp, fontWeight = FontWeight.SemiBold, letterSpacing = 1.sp)
    }
}

@Composable
private fun CardBox(modifier: Modifier = Modifier, border: Color = RG.Line, content: @Composable () -> Unit) {
    Column(
        modifier.fillMaxWidth().clip(RoundedCornerShape(16.dp)).background(RG.Card).border(1.dp, border, RoundedCornerShape(16.dp)).padding(18.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) { content() }
}

// -------------------------------------------------------------------- home

@Composable
private fun HomeScreen(act: MainActivity) {
    val pending by Hub.pending.collectAsStateWithLifecycle()
    val status by Hub.status.collectAsStateWithLifecycle()
    val openId by act.openId
    val current = pending.firstOrNull { it.req.id == openId } ?: pending.firstOrNull()
    if (current != null) {
        RequestScreen(act, current, index = pending.indexOf(current), total = pending.size) { next ->
            act.openId.value = next
        }
    } else {
        EmptyState(act, status)
    }
}

@Composable
private fun EmptyState(act: MainActivity, status: Hub.Status) {
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        SafetyBanner(act)
        Trust(act, status)
        Spacer(Modifier.height(24.dp))
        val (icon, color, title, sub) = when (status) {
            is Hub.Status.Connected -> Quad(Icons.Outlined.GppGood, RG.Ok, "Secure & Listening", "Connected to ${status.host}\nverified ${status.fingerprint}")
            is Hub.Status.Connecting -> Quad(Icons.Outlined.GppMaybe, RG.Warn, "Connecting…", status.target)
            is Hub.Status.Down -> Quad(Icons.Outlined.GppBad, RG.Bad, "Offline", "${status.reason}\nretrying in ${status.retryInSecs}s")
            is Hub.Status.Untrusted -> Quad(Icons.Outlined.GppMaybe, RG.Warn, "New computer", "Compare fingerprints above before trusting it.")
            is Hub.Status.KeyMismatch -> Quad(Icons.Outlined.GppBad, RG.Bad, "Possible impostor", "Not connecting.")
            Hub.Status.Stopped -> Quad(Icons.Outlined.GppMaybe, RG.Faint, "Stopped", "")
        }
        ShieldPulse(icon, color, pulse = status is Hub.Status.Connected)
        Spacer(Modifier.height(24.dp))
        Text(title, color = RG.Text, fontSize = 20.sp, fontWeight = FontWeight.SemiBold)
        Spacer(Modifier.height(8.dp))
        Text(
            if (status is Hub.Status.Connected) "No active root requests.\n$sub" else sub,
            color = RG.Muted, fontSize = 14.sp, textAlign = TextAlign.Center, lineHeight = 20.sp,
        )
        val notes by Hub.notes.collectAsStateWithLifecycle()
        if (notes.isNotEmpty()) {
            Spacer(Modifier.height(24.dp))
            notes.take(3).forEach { Text("• $it", color = RG.Warn, fontSize = 12.sp, textAlign = TextAlign.Center) }
        }
        if (BuildConfig.DEBUG) {
            Spacer(Modifier.height(32.dp))
            Text(
                "Simulate New Request (dev build only)", color = RG.Muted, fontSize = 12.sp,
                modifier = Modifier.clip(RoundedCornerShape(8.dp)).background(RG.Line).clickable { simulate() }.padding(horizontal = 16.dp, vertical = 8.dp),
            )
        }
    }
}

private data class Quad(val icon: ImageVector, val color: Color, val title: String, val sub: String)

@Composable
private fun ShieldPulse(icon: ImageVector, color: Color, pulse: Boolean) {
    val t = rememberInfiniteTransition(label = "ping")
    val p by t.animateFloat(0f, 1f, infiniteRepeatable(tween(1600, easing = LinearEasing)), label = "p")
    Box(contentAlignment = Alignment.Center) {
        if (pulse) {
            Box(
                Modifier.size(112.dp).scale(1f + p * 0.6f).alpha((1f - p) * 0.5f).blur(12.dp)
                    .clip(CircleShape).background(color.copy(alpha = 0.35f)),
            )
        }
        Box(
            Modifier.size(112.dp).clip(CircleShape).background(RG.Card).border(1.dp, RG.Line, CircleShape),
            contentAlignment = Alignment.Center,
        ) { Icon(icon, null, tint = color, modifier = Modifier.size(64.dp)) }
    }
}

/** Dev build only: a local fake request to look at the approval screen. */
private fun simulate() {
    val now = System.currentTimeMillis() / 1000
    val r = Request(
        id = "demo" + now, nonce = "ZGVtbw==", created = now, expires = now + 120, uid = 1000,
        user = "alice", host = "laptop",
        argv = listOf("/usr/sbin/ufw", "allow", "from", "192.0.2.10", "to", "any", "port", "3389", "proto", "tcp"),
        why = "Open RDP for the lab PC you are sitting at (demo).",
    )
    Hub.upsert(Hub.Pending(r, Canonical.code(r), Canonical.code(r), listOf("Demo warning: this is how a warning from the computer looks.")))
}

// ----------------------------------------------------------------- request

@Composable
private fun RequestScreen(act: MainActivity, p: Hub.Pending, index: Int, total: Int, onSelect: (String?) -> Unit) {
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
    val problems = Checks.problems(r, p.daemonCode, now) + DeviceSafety.problems(act)
    val left = (r.expires - now).coerceAtLeast(0)

    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 20.dp, vertical = 20.dp)) {
        // Red banner with the code that must match the terminal.
        Row(
            Modifier.fillMaxWidth().clip(RoundedCornerShape(16.dp)).background(RG.Bad.copy(alpha = 0.1f))
                .border(1.dp, RG.Bad.copy(alpha = 0.2f), RoundedCornerShape(16.dp)).padding(14.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Box(Modifier.clip(CircleShape).background(RG.Bad.copy(alpha = 0.2f)).padding(8.dp)) {
                Icon(Icons.Outlined.GppBad, null, tint = RG.Bad, modifier = Modifier.size(24.dp))
            }
            Spacer(Modifier.width(12.dp))
            Column(Modifier.weight(1f)) {
                Text("ROOT REQUEST", color = RG.Bad, fontWeight = FontWeight.SemiBold, fontSize = 13.sp, letterSpacing = 1.sp)
                Text(
                    if (total > 1) "${index + 1} of $total · code must match terminal" else "Code must match the terminal",
                    color = RG.BadText.copy(alpha = 0.8f), fontSize = 12.sp,
                )
            }
            Text(p.daemonCode, color = Color.White, fontFamily = Mono, fontWeight = FontWeight.Bold, fontSize = 22.sp, letterSpacing = 3.sp)
        }
        if (total > 1) {
            Row(Modifier.fillMaxWidth().padding(top = 8.dp), horizontalArrangement = Arrangement.End) {
                Text(
                    "Next request →", color = RG.Accent2, fontSize = 12.sp,
                    modifier = Modifier.clip(RoundedCornerShape(6.dp)).clickable {
                        val list = Hub.pending.value
                        onSelect(list[(index + 1) % list.size].req.id)
                    }.padding(6.dp),
                )
            }
        }
        Spacer(Modifier.height(20.dp))

        CardBox {
            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Label(Icons.Outlined.Dns, "Machine")
                Text("${r.user}@${r.host}", color = RG.Text, fontSize = 14.sp, fontWeight = FontWeight.Medium)
            }
            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Label(Icons.Outlined.Terminal, "Command · runs as root, no shell")
                // One line per argument: nothing can hide where an argument ends.
                Column(
                    Modifier.fillMaxWidth().clip(RoundedCornerShape(10.dp)).background(RG.Code)
                        .border(1.dp, RG.Line.copy(alpha = 0.5f), RoundedCornerShape(10.dp)).padding(12.dp),
                    verticalArrangement = Arrangement.spacedBy(4.dp),
                ) {
                    r.argv.forEachIndexed { i, a ->
                        Row {
                            Text("$i", color = RG.Faint, fontFamily = Mono, fontSize = 12.sp, modifier = Modifier.widthIn(min = 22.dp))
                            Text(
                                a.ifEmpty { "(empty)" },
                                color = if (i == 0) Color.White else RG.OkText,
                                fontFamily = Mono, fontSize = 14.sp,
                                fontWeight = if (i == 0) FontWeight.Bold else FontWeight.Normal,
                            )
                        }
                    }
                }
            }
            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Label(Icons.Outlined.Warning, "Reason · not verified", RG.Warn)
                Text(r.why, color = RG.Text2, fontSize = 14.sp, lineHeight = 20.sp)
            }
            if (p.warnings.isNotEmpty()) {
                Column(
                    Modifier.fillMaxWidth().clip(RoundedCornerShape(10.dp)).background(RG.Bad.copy(alpha = 0.1f)).padding(10.dp),
                    verticalArrangement = Arrangement.spacedBy(4.dp),
                ) {
                    Label(Icons.Outlined.Warning, "Warnings from your computer", RG.Bad)
                    p.warnings.forEach { Text("• $it", color = RG.BadText, fontSize = 13.sp, lineHeight = 18.sp) }
                }
            }
            Box(Modifier.fillMaxWidth().height(1.dp).background(RG.Line.copy(alpha = 0.5f)))
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.Top) {
                Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text("Requested by", color = RG.Faint, fontSize = 12.sp)
                    Text(
                        "${r.user} (uid ${r.uid})", color = RG.Text2, fontFamily = Mono, fontSize = 13.sp,
                        modifier = Modifier.clip(RoundedCornerShape(4.dp)).background(RG.Line.copy(alpha = 0.5f)).padding(horizontal = 8.dp, vertical = 2.dp),
                    )
                }
                Column(horizontalAlignment = Alignment.End, verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text("Expires in", color = RG.Faint, fontSize = 12.sp)
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Outlined.Schedule, null, tint = RG.Muted, modifier = Modifier.size(14.dp))
                        Spacer(Modifier.width(4.dp))
                        Text("${left}s", color = if (left < 20) RG.Warn else RG.Text2, fontSize = 13.sp, fontFamily = Mono)
                    }
                }
            }
        }

        if (problems.isNotEmpty()) {
            Spacer(Modifier.height(16.dp))
            Column(
                Modifier.fillMaxWidth().clip(RoundedCornerShape(12.dp)).border(1.5.dp, RG.Bad, RoundedCornerShape(12.dp)).padding(12.dp),
                verticalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                Text("Cannot approve", color = RG.Bad, fontWeight = FontWeight.Bold)
                problems.forEach { Text("• $it", color = RG.BadText, fontSize = 13.sp) }
            }
        }

        Spacer(Modifier.height(28.dp))
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.Center, verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Outlined.Lock, null, tint = RG.Muted, modifier = Modifier.size(14.dp))
            Spacer(Modifier.width(8.dp))
            Text("FINGERPRINT TO ALLOW", color = RG.Muted, fontSize = 11.sp, fontWeight = FontWeight.SemiBold, letterSpacing = 2.sp)
        }
        Spacer(Modifier.height(20.dp))
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(40.dp, Alignment.CenterHorizontally)) {
            RoundAction(Icons.Outlined.Close, "Deny", RG.Bad, enabled = !busy) {
                if (r.id.startsWith("demo")) {
                    History.record(act, r, "denied"); Hub.remove(r.id)
                } else {
                    act.deny(r.id) { ok -> result = if (ok) "Denied" else "Not connected" }
                }
            }
            RoundAction(Icons.Outlined.Fingerprint, "Approve", RG.Ok, enabled = armed && !busy && problems.isEmpty()) {
                if (r.id.startsWith("demo")) {
                    History.record(act, r, "approved"); Hub.remove(r.id)
                    return@RoundAction
                }
                busy = true
                act.approve(p) { err ->
                    busy = false
                    result = err ?: "Approved, running…"
                }
            }
        }
        result?.let {
            Spacer(Modifier.height(16.dp))
            Text(
                it, color = if (it.startsWith("Approved") || it == "Denied") RG.OkText else RG.BadText,
                fontSize = 13.sp, textAlign = TextAlign.Center, modifier = Modifier.fillMaxWidth(),
            )
        }
        Spacer(Modifier.height(16.dp))
    }
}

@Composable
private fun RoundAction(icon: ImageVector, label: String, color: Color, enabled: Boolean, onClick: () -> Unit) {
    Column(
        Modifier.alpha(if (enabled) 1f else 0.35f),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Box(
            Modifier.size(80.dp).clip(CircleShape).background(RG.Card).border(2.dp, color.copy(alpha = 0.5f), CircleShape)
                .clickable(enabled = enabled, onClick = onClick),
            contentAlignment = Alignment.Center,
        ) { Icon(icon, label, tint = color, modifier = Modifier.size(40.dp)) }
        Spacer(Modifier.height(8.dp))
        Text(label.uppercase(), color = color, fontSize = 12.sp, fontWeight = FontWeight.SemiBold, letterSpacing = 1.sp)
    }
}

// ----------------------------------------------------------------- history

@Composable
private fun HistoryScreen(act: MainActivity) {
    val entries by History.entries.collectAsStateWithLifecycle()
    var now by remember { mutableLongStateOf(System.currentTimeMillis() / 1000) }
    LaunchedEffect(Unit) {
        while (true) { now = System.currentTimeMillis() / 1000; delay(30_000) }
    }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Row(Modifier.padding(horizontal = 8.dp), verticalAlignment = Alignment.CenterVertically) {
            Text("Access Log", color = Color.White, fontSize = 20.sp, fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f))
            if (entries.isNotEmpty()) {
                Text("Clear", color = RG.Faint, fontSize = 12.sp, modifier = Modifier.clip(RoundedCornerShape(6.dp)).clickable { History.clear(act) }.padding(6.dp))
            }
        }
        if (entries.isEmpty()) {
            Text("Nothing yet. Decisions appear here.", color = RG.Faint, fontSize = 14.sp, modifier = Modifier.padding(horizontal = 8.dp))
        }
        entries.forEach { e ->
            val (icon, color) = when (e.status) {
                "approved" -> Icons.Outlined.Check to RG.Ok
                "denied" -> Icons.Outlined.Close to RG.Bad
                else -> Icons.Outlined.Schedule to RG.Faint
            }
            Row(
                Modifier.fillMaxWidth().clip(RoundedCornerShape(12.dp)).background(RG.Card.copy(alpha = 0.8f))
                    .border(1.dp, RG.Line, RoundedCornerShape(12.dp)).padding(16.dp),
            ) {
                Box(Modifier.padding(top = 2.dp).clip(CircleShape).background(color.copy(alpha = 0.1f)).padding(8.dp)) {
                    Icon(icon, null, tint = color, modifier = Modifier.size(16.dp))
                }
                Spacer(Modifier.width(14.dp))
                Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Row(verticalAlignment = Alignment.Top) {
                        Text(
                            e.argv.joinToString(" "), color = RG.Text2, fontFamily = Mono, fontSize = 12.sp, maxLines = 2,
                            modifier = Modifier.weight(1f).clip(RoundedCornerShape(4.dp)).background(Color(0x4D000000)).padding(4.dp),
                        )
                        Spacer(Modifier.width(8.dp))
                        Text(ago(now - e.time), color = RG.Faint, fontSize = 10.sp)
                    }
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Outlined.Person, null, tint = RG.Faint, modifier = Modifier.size(12.dp))
                        Spacer(Modifier.width(4.dp))
                        Text("${e.user}@${e.host}", color = RG.Faint, fontSize = 12.sp)
                    }
                    Text(e.status.uppercase(), color = color.copy(alpha = 0.7f), fontSize = 10.sp, fontWeight = FontWeight.SemiBold, letterSpacing = 1.sp)
                }
            }
        }
    }
}

private fun ago(s: Long): String = when {
    s < 60 -> "Just now"
    s < 3600 -> "${s / 60} min ago"
    s < 86_400 -> "${s / 3600} h ago"
    s < 172_800 -> "Yesterday"
    else -> "${s / 86_400} days ago"
}

// ---------------------------------------------------------------- settings

@Composable
private fun SettingsScreen(act: MainActivity, onBack: () -> Unit) {
    val status by Hub.status.collectAsStateWithLifecycle()
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(
                Icons.AutoMirrored.Outlined.ArrowBack, "Back", tint = RG.Muted,
                modifier = Modifier.clip(CircleShape).clickable(onClick = onBack).padding(4.dp).size(22.dp),
            )
            Spacer(Modifier.width(8.dp))
            Text("Settings", color = Color.White, fontSize = 20.sp, fontWeight = FontWeight.Bold)
        }
        SafetyBanner(act)
        Trust(act, status)
        Connection(act, status)
        Background(act)
        KeySection(act)
    }
}

@Composable
private fun SectionTitle(icon: ImageVector, text: String) = Label(icon, text, RG.Muted)

@Composable
private fun SmallButton(text: String, color: Color = RG.Accent2, filled: Boolean = false, onClick: () -> Unit) {
    Text(
        text, color = if (filled) Color.Black else color, fontSize = 13.sp, fontWeight = FontWeight.SemiBold,
        modifier = Modifier.clip(RoundedCornerShape(8.dp))
            .then(if (filled) Modifier.background(color) else Modifier.border(1.dp, color.copy(alpha = 0.6f), RoundedCornerShape(8.dp)))
            .clickable(onClick = onClick).padding(horizontal = 14.dp, vertical = 9.dp),
    )
}

@Composable
private fun field(): androidx.compose.material3.TextFieldColors = OutlinedTextFieldDefaults.colors(
    focusedTextColor = RG.Text, unfocusedTextColor = RG.Text, focusedBorderColor = RG.Accent,
    unfocusedBorderColor = RG.Line, focusedLabelColor = RG.Accent2, unfocusedLabelColor = RG.Faint, cursorColor = RG.Accent,
)

@Composable
private fun Connection(act: MainActivity, status: Hub.Status) {
    var host by remember { mutableStateOf(Settings.host(act)) }
    var port by remember { mutableStateOf(Settings.port(act).toString()) }
    var msg by remember { mutableStateOf<String?>(null) }
    CardBox {
        SectionTitle(Icons.Outlined.Dns, "Computer")
        val (txt, col) = when (status) {
            Hub.Status.Stopped -> "Stopped" to RG.Faint
            is Hub.Status.Connecting -> "Connecting to ${status.target}…" to RG.Warn
            is Hub.Status.Connected -> "Connected to ${status.host} · ${status.fingerprint}" to RG.Ok
            is Hub.Status.Down -> "Offline: ${status.reason}" to RG.Bad
            is Hub.Status.Untrusted -> "Waiting for you to trust ${status.host}" to RG.Warn
            is Hub.Status.KeyMismatch -> "Different key from ${status.host}!" to RG.Bad
        }
        Text(txt, color = col, fontSize = 13.sp)
        OutlinedTextField(host, { host = it }, label = { Text("Tailscale IP") }, singleLine = true, colors = field(), modifier = Modifier.fillMaxWidth())
        OutlinedTextField(
            port, { port = it.filter(Char::isDigit).take(5) }, label = { Text("Port") }, singleLine = true, colors = field(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number), modifier = Modifier.fillMaxWidth(),
        )
        SmallButton("Save & reconnect") {
            val p = port.toIntOrNull()
            msg = if (host.isBlank() || p == null || p !in 1..65535) {
                "Invalid host or port"
            } else {
                Settings.save(act, host, p)
                ApproverService.start(act, reconnect = true)
                "Saved, reconnecting"
            }
        }
        msg?.let { Text(it, color = RG.Warn, fontSize = 12.sp) }
    }
}

@Composable
private fun Background(act: MainActivity) {
    var free by remember { mutableStateOf(Power.isUnrestricted(act)) }
    var boot by remember { mutableStateOf(Power.startAtBoot(act)) }
    LifecycleEventEffect(Lifecycle.Event.ON_RESUME) { free = Power.isUnrestricted(act) }
    CardBox {
        SectionTitle(Icons.Outlined.Schedule, "Background")
        if (free) {
            Text("Battery optimization is off. RootGate stays connected.", color = RG.OkText, fontSize = 13.sp)
        } else {
            Text("Battery optimization is ON: Samsung may cut the connection and requests won't arrive.", color = RG.BadText, fontSize = 13.sp)
            SmallButton("Allow running in background", RG.Ok, filled = true) { Power.requestUnrestricted(act) }
        }
        Text(
            "Also: App info > Battery > Unrestricted, and keep RootGate out of Settings > Battery > Background usage limits > Sleeping apps.",
            color = RG.Faint, fontSize = 12.sp, lineHeight = 17.sp,
        )
        SmallButton("Open App info") { Power.openAppSettings(act) }
        Row(verticalAlignment = Alignment.CenterVertically) {
            Switch(
                checked = boot, onCheckedChange = { boot = it; Power.setStartAtBoot(act, it) },
                colors = SwitchDefaults.colors(checkedTrackColor = RG.Accent, checkedThumbColor = Color.White),
            )
            Spacer(Modifier.width(10.dp))
            Text("Start after reboot", color = RG.Text, fontSize = 14.sp)
        }
    }
}

@Composable
private fun KeySection(act: MainActivity) {
    var hasKey by remember { mutableStateOf(Keys.exists()) }
    var msg by remember { mutableStateOf<String?>(null) }
    var confirmDelete by remember { mutableStateOf(false) }
    CardBox {
        SectionTitle(Icons.Outlined.Fingerprint, "Approval key")
        if (!hasKey) {
            Text(
                "Create the key that approves root commands. It never leaves this phone; every use needs your fingerprint.",
                color = RG.Text2, fontSize = 13.sp, lineHeight = 18.sp,
            )
            SmallButton("Create approval key", RG.Ok, filled = true) {
                msg = try {
                    val sb = Keys.generate()
                    hasKey = true
                    if (sb) "Key created in StrongBox" else "Key created in secure hardware"
                } catch (e: Exception) {
                    "Could not create key: ${e.message}. Is a fingerprint enrolled?"
                }
            }
        } else {
            val pub = remember(hasKey) { runCatching { Keys.publicKeyB64() }.getOrNull() ?: "?" }
            val fp = remember(hasKey) { runCatching { Keys.fingerprint() }.getOrNull() ?: "?" }
            val level = remember(hasKey) { runCatching { Keys.securityLevel() }.getOrNull() ?: "?" }
            Text("Stored in: $level", color = if (level.startsWith("SOFTWARE")) RG.BadText else RG.OkText, fontSize = 13.sp)
            Text("Fingerprint  $fp", color = RG.Text, fontFamily = Mono, fontSize = 13.sp)
            Text("Public key (goes into approver_pubkeys on the computer; not secret):", color = RG.Faint, fontSize = 12.sp)
            Text(
                pub, color = RG.OkText, fontFamily = Mono, fontSize = 11.sp,
                modifier = Modifier.fillMaxWidth().clip(RoundedCornerShape(8.dp)).background(RG.Code).padding(10.dp),
            )
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                SmallButton("Copy public key") {
                    val cm = act.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                    cm.setPrimaryClip(ClipData.newPlainText("rootgate public key", pub))
                    msg = "Public key copied"
                }
                if (!confirmDelete) {
                    SmallButton("Delete key", RG.Bad) { confirmDelete = true }
                } else {
                    SmallButton("Really delete", RG.Bad, filled = true) {
                        Keys.delete()
                        hasKey = false
                        confirmDelete = false
                        msg = "Key deleted. Remove the old public key from the computer's config too."
                    }
                }
            }
        }
        msg?.let { Text(it, color = RG.Warn, fontSize = 12.sp) }
    }
}

// ------------------------------------------------------- trust & safety

@Composable
private fun Trust(act: MainActivity, s: Hub.Status) {
    when (s) {
        is Hub.Status.Untrusted -> CardBox(border = RG.Warn.copy(alpha = 0.6f)) {
            Label(Icons.Outlined.GppMaybe, "Is this your computer?", RG.Warn)
            Text("${s.host} proved it owns this key:", color = RG.Text2, fontSize = 13.sp)
            Text(s.fingerprint, color = Color.White, fontFamily = Mono, fontSize = 20.sp, fontWeight = FontWeight.Bold)
            Text(
                "On the computer:  journalctl -u rootgated | grep fingerprint\nTrust only if every character matches.",
                color = RG.Faint, fontSize = 12.sp, fontFamily = Mono, lineHeight = 17.sp,
            )
            SmallButton("Fingerprints match: trust", RG.Ok, filled = true) {
                Settings.pin(act, s.key)
                ApproverService.start(act, reconnect = true)
            }
        }
        is Hub.Status.KeyMismatch -> CardBox(border = RG.Bad) {
            Label(Icons.Outlined.GppBad, "Possible impostor", RG.Bad)
            Text(
                "Something at this address answered with a different key (${s.fingerprint}). " +
                    "Only forget the old key if you reinstalled rootgate on purpose.",
                color = RG.Text2, fontSize = 13.sp, lineHeight = 18.sp,
            )
            SmallButton("I reinstalled it: forget the old key", RG.Bad) {
                Settings.forgetPin(act)
                ApproverService.start(act, reconnect = true)
            }
        }
        else -> {}
    }
}

@Composable
private fun SafetyBanner(act: MainActivity) {
    var problems by remember { mutableStateOf(DeviceSafety.problems(act)) }
    LifecycleEventEffect(Lifecycle.Event.ON_RESUME) { problems = DeviceSafety.problems(act) }
    if (problems.isNotEmpty()) {
        Column(
            Modifier.fillMaxWidth().padding(bottom = 12.dp).clip(RoundedCornerShape(12.dp))
                .background(RG.Bad.copy(alpha = 0.1f)).border(1.dp, RG.Bad.copy(alpha = 0.5f), RoundedCornerShape(12.dp)).padding(12.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Label(Icons.Outlined.GppBad, "Approving is blocked", RG.Bad)
            problems.forEach { Text("• $it", color = RG.BadText, fontSize = 13.sp, lineHeight = 18.sp) }
        }
    }
}
