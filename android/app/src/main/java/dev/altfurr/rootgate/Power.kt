package dev.altfurr.rootgate

import android.annotation.SuppressLint
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.PowerManager
import android.provider.Settings as AndroidSettings

/** Keeping the connection alive on Samsung, which kills background apps aggressively. */
object Power {
    fun isUnrestricted(c: Context): Boolean =
        c.getSystemService(PowerManager::class.java).isIgnoringBatteryOptimizations(c.packageName)

    /** System dialog: "Let RootGate always run in the background?" */
    @SuppressLint("BatteryLife") // Personal app, not for Play: this is exactly the intent.
    fun requestUnrestricted(c: Context) {
        c.startActivity(
            Intent(AndroidSettings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS)
                .setData(Uri.parse("package:${c.packageName}")),
        )
    }

    /** App info page, where Samsung's "Battery: Unrestricted" setting lives. */
    fun openAppSettings(c: Context) {
        c.startActivity(
            Intent(AndroidSettings.ACTION_APPLICATION_DETAILS_SETTINGS)
                .setData(Uri.parse("package:${c.packageName}")),
        )
    }

    private const val PREFS = "rootgate"
    fun startAtBoot(c: Context): Boolean =
        c.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getBoolean("boot", true)

    fun setStartAtBoot(c: Context, on: Boolean) {
        c.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putBoolean("boot", on).apply()
    }
}

/** Starts the connection after reboot or app update (if enabled and a key exists). */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(c: Context, intent: Intent) {
        val ok = intent.action == Intent.ACTION_BOOT_COMPLETED ||
            intent.action == Intent.ACTION_MY_PACKAGE_REPLACED
        if (ok && Power.startAtBoot(c) && runCatching { Keys.exists() }.getOrDefault(false)) {
            ApproverService.start(c)
        }
    }
}
