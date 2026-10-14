plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

// A login form in another app, for testing Keyless's autofill (CI only).
android {
    namespace = "io.github.diegocastroalves.keyless.formtest"
    compileSdk = 35

    defaultConfig {
        applicationId = "io.github.diegocastroalves.keyless.formtest"
        minSdk = 29
        targetSdk = 35
        versionCode = 1
        versionName = "1"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            signingConfig = signingConfigs.getByName("debug")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    lint {
        checkReleaseBuilds = false
    }
}
