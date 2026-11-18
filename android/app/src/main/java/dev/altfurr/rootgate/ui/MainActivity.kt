package dev.altfurr.rootgate.ui

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
import androidx.biometric.BiometricPrompt
import androidx.compose.runtime.mutableStateOf
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import dev.altfurr.rootgate.ApproverService
import dev.altfurr.rootgate.Canonical
import dev.altfurr.rootgate.Checks
import dev.altfurr.rootgate.Hub
import dev.altfurr.rootgate.Keys
import dev.altfurr.rootgate.Protocol
import java.util.Base64

class MainActivity : FragmentActivity() {
    /** Request currently opened in the detail screen (from a notification or a tap). */
    val openId = mutableStateOf<String?>(null)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // No screenshots/recents thumbnails of commands; no overlays drawn on top of us.
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        if (Build.VERSION.SDK_INT >= 31) window.setHideOverlayWindows(true)

        if (Build.VERSION.SDK_INT >= 33 &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 1)
        }
        ApproverService.start(this)
        openId.value = intent?.getStringExtra(ApproverService.EXTRA_ID)
        setContent { App(this) }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        intent.getStringExtra(ApproverService.EXTRA_ID)?.let { openId.value = it }
    }

    fun deny(id: String, done: (Boolean) -> Unit) = Hub.sendAsync(Protocol.decision(id, false, null), done)

    /**
     * Ask for fingerprint/PIN; the Keystore only releases a signature after that.
     * We sign the canonical bytes of the exact object shown on screen.
     */
    fun approve(p: Hub.Pending, onResult: (String?) -> Unit) {
        val problems = Checks.problems(p.req, p.daemonCode, System.currentTimeMillis() / 1000)
        if (problems.isNotEmpty()) return onResult(problems.first())
        if (!Keys.exists()) return onResult("No approval key yet. Create one in Setup.")
        val sig = try {
            Keys.signatureForAuth()
        } catch (e: KeyPermanentlyInvalidatedException) {
            return onResult("Key was invalidated (fingerprints changed). Delete it and enrol a new one.")
        } catch (e: Exception) {
            return onResult("Keystore error: ${e.message}")
        }
        val canonical = Canonical.bytes(p.req)
        val prompt = BiometricPrompt(
            this,
            ContextCompat.getMainExecutor(this),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    val s = result.cryptoObject?.signature ?: return onResult("No signature from Keystore")
                    val der = try {
                        s.update(canonical)
                        s.sign()
                    } catch (e: Exception) {
                        return onResult("Signing failed: ${e.message}")
                    }
                    Hub.sendAsync(Protocol.decision(p.req.id, true, Base64.getEncoder().encodeToString(der))) { sent ->
                        onResult(if (sent) null else "Not connected; approval not sent.")
                    }
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    onResult(errString.toString())
                }
            },
        )
        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Run as root: ${p.daemonCode}")
            .setSubtitle("${p.req.user}@${p.req.host}")
            .setDescription(p.req.argv.joinToString(" ").take(300))
            .setAllowedAuthenticators(BIOMETRIC_STRONG or DEVICE_CREDENTIAL)
            .setConfirmationRequired(true)
            .build()
        prompt.authenticate(info, BiometricPrompt.CryptoObject(sig))
    }
}
