plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.kotlin.serialization)
}

// Same settings file as install.sh: ../rootgate.env (see rootgate.env.example).
val rootgateEnv: Map<String, String> = rootDir.parentFile.resolve("rootgate.env").let { f ->
    if (!f.exists()) emptyMap() else f.readLines()
        .map { it.substringBefore('#').trim() }
        .filter { '=' in it }
        .associate { it.substringBefore('=').trim() to it.substringAfter('=').trim().trim('"') }
}
val computerIp = rootgateEnv["COMPUTER_IP"].orEmpty()
require(computerIp.isEmpty() || Regex("""100\.\d{1,3}\.\d{1,3}\.\d{1,3}""").matches(computerIp)) {
    "COMPUTER_IP in rootgate.env must be a Tailscale 100.x.y.z address"
}

android {
    namespace = "dev.altfurr.rootgate"
    compileSdk = 35

    defaultConfig {
        applicationId = "dev.altfurr.rootgate"
        // 30+: Keystore keys that accept fingerprint OR device PIN per signature.
        minSdk = 30
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"
        // Pre-filled computer address; empty means "enter it in Settings".
        buildConfigField("String", "DEFAULT_HOST", "\"$computerIp\"")
    }

    buildTypes {
        debug {
            // Separate app (own package, own keys): can never approve the real daemon,
            // used only to look at the UI. Screenshots allowed, demo request button.
            applicationIdSuffix = ".dev"
            versionNameSuffix = "-dev"
            resValue("string", "app_name", "RootGate DEV")
        }
        release {
            resValue("string", "app_name", "RootGate")
            isMinifyEnabled = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    buildFeatures {
        compose = true
        buildConfig = true
    }
    testOptions {
        unitTests.isReturnDefaultValues = true
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.material3)
    implementation("androidx.compose.material:material-icons-extended")
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.biometric)
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.kotlinx.coroutines.android)
    testImplementation(libs.junit)
}
