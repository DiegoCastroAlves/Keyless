plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

// The server: Keyless's own, unless a test build points elsewhere
// (-PkeylessServer=http://10.0.2.2:8787 for the fake server in CI).
val server = (project.findProperty("keylessServer") as String?) ?: "https://ednfhgbjtgkrmtnudcjr.supabase.co"
// Where sites' Digital Asset Links come from: the sites themselves, unless a
// test build reads them from the fake server.
val assetLinks = (project.findProperty("keylessAssetLinks") as String?) ?: ""
// Where Sentinel downloads its lists and checks passwords: the public
// services, unless a test build reads them from the fake server.
val sentinel = (project.findProperty("keylessSentinel") as String?) ?: ""

android {
    namespace = "io.github.diegocastroalves.keyless"
    compileSdk = 35

    defaultConfig {
        applicationId = "io.github.diegocastroalves.keyless"
        minSdk = 29
        targetSdk = 35
        versionCode = 2
        versionName = "0.1.10"
        buildConfigField("String", "SERVER", "\"$server\"")
        buildConfigField("String", "ASSET_LINKS", "\"$assetLinks\"")
        buildConfigField("String", "SENTINEL", "\"$sentinel\"")
        // Plain http only for a test build that names an http server.
        manifestPlaceholders["cleartext"] = if (server.startsWith("http://")) "true" else "false"
    }

    buildFeatures {
        buildConfig = true
    }

    // A release key comes from the environment (KEYLESS_ANDROID_KEYSTORE and
    // its password; the alias defaults to "keyless" and the key's password to
    // the keystore's); without one, release builds are signed with the debug
    // key, for testing.
    signingConfigs {
        create("release") {
            val path = System.getenv("KEYLESS_ANDROID_KEYSTORE")
            if (path != null) {
                storeFile = file(path)
                storePassword = System.getenv("KEYLESS_ANDROID_KEYSTORE_PASSWORD")
                keyAlias = System.getenv("KEYLESS_ANDROID_KEY_ALIAS") ?: "keyless"
                keyPassword = System.getenv("KEYLESS_ANDROID_KEY_PASSWORD") ?: storePassword
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            signingConfig = if (System.getenv("KEYLESS_ANDROID_KEYSTORE") != null) signingConfigs.getByName("release") else signingConfigs.getByName("debug")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    packaging {
        jniLibs {
            useLegacyPackaging = false
        }
    }
    lint {
        checkReleaseBuilds = false
    }
}

dependencies {
    // Passkeys through Android's Credential Manager (KeylessCredentialService).
    implementation("androidx.credentials:credentials:1.3.0")
}
