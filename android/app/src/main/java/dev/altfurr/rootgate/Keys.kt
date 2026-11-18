package dev.altfurr.rootgate

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64

/**
 * The approval key lives in the Android Keystore (secure hardware). It never leaves
 * the phone, and every single signature needs a fresh fingerprint or device PIN.
 */
object Keys {
    // v2: fingerprint only (a PIN someone has seen can no longer approve).
    private const val ALIAS = "rootgate-approver-v2"
    private const val STORE = "AndroidKeyStore"

    private fun store() = KeyStore.getInstance(STORE).apply { load(null) }

    fun exists(): Boolean = store().containsAlias(ALIAS)

    private fun spec(strongBox: Boolean) =
        KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUserAuthenticationRequired(true)
            // 0 = authenticate for every use; strong biometric only.
            .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
            // A newly added fingerprint (e.g. by a thief who knows the PIN) kills the key.
            .setInvalidatedByBiometricEnrollment(true)
            .setUnlockedDeviceRequired(true)
            .setIsStrongBoxBacked(strongBox)
            .build()

    /** Returns true if the key ended up in StrongBox (a separate secure chip). */
    fun generate(): Boolean {
        val gen = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, STORE)
        return try {
            gen.initialize(spec(strongBox = true))
            gen.generateKeyPair()
            true
        } catch (e: StrongBoxUnavailableException) {
            gen.initialize(spec(strongBox = false))
            gen.generateKeyPair()
            false
        } catch (e: java.security.ProviderException) {
            // Some devices report missing StrongBox this way.
            if (e is StrongBoxUnavailableException || e.cause is StrongBoxUnavailableException || e.message?.contains("StrongBox", true) == true) {
                gen.initialize(spec(strongBox = false))
                gen.generateKeyPair()
                false
            } else {
                throw e
            }
        }
    }

    fun delete() {
        store().deleteEntry(ALIAS)
    }

    /** Base64 X.509 SubjectPublicKeyInfo: paste into the daemon's approver_pubkeys. */
    fun publicKeyB64(): String =
        Base64.getEncoder().encodeToString(store().getCertificate(ALIAS).publicKey.encoded)

    /** Short fingerprint to compare with what you pasted on the computer. */
    fun fingerprint(): String =
        Canonical.sha256(store().getCertificate(ALIAS).publicKey.encoded)
            .take(8).joinToString(":") { "%02X".format(it) }

    /** Human-readable description of where the key lives. */
    fun securityLevel(): String {
        val key = store().getKey(ALIAS, null) as PrivateKey
        val info = KeyFactory.getInstance(key.algorithm, STORE).getKeySpec(key, KeyInfo::class.java)
        return if (Build.VERSION.SDK_INT >= 31) {
            when (info.securityLevel) {
                KeyProperties.SECURITY_LEVEL_STRONGBOX -> "StrongBox (separate secure chip)"
                KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> "Trusted Execution Environment"
                KeyProperties.SECURITY_LEVEL_SOFTWARE -> "SOFTWARE ONLY (weak)"
                else -> "unknown"
            }
        } else {
            @Suppress("DEPRECATION")
            if (info.isInsideSecureHardware) "secure hardware" else "SOFTWARE ONLY (weak)"
        }
    }

    /** A Signature ready to be unlocked by BiometricPrompt (CryptoObject). */
    fun signatureForAuth(): Signature =
        Signature.getInstance("SHA256withECDSA").apply {
            initSign(store().getKey(ALIAS, null) as PrivateKey)
        }
}
