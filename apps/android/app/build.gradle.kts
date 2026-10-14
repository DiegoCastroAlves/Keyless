plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "io.github.diegocastroalves.keyless"
    compileSdk = 35

    defaultConfig {
        applicationId = "io.github.diegocastroalves.keyless"
        minSdk = 29
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.9"
    }

    // A release key comes from the environment (KEYLESS_ANDROID_KEYSTORE and
    // its passwords); without one, release builds are signed with the debug
    // key, for testing.
    signingConfigs {
        create("release") {
            val path = System.getenv("KEYLESS_ANDROID_KEYSTORE")
            if (path != null) {
                storeFile = file(path)
                storePassword = System.getenv("KEYLESS_ANDROID_KEYSTORE_PASSWORD")
                keyAlias = System.getenv("KEYLESS_ANDROID_KEY_ALIAS")
                keyPassword = System.getenv("KEYLESS_ANDROID_KEY_PASSWORD")
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
