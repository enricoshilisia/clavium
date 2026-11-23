plugins {
    id("com.android.application")
    // The Flutter Gradle Plugin must be applied after the Android and Kotlin Gradle plugins.
    id("dev.flutter.flutter-gradle-plugin")
}

android {
    namespace = "com.clavium.app"
    compileSdk = flutter.compileSdkVersion
    ndkVersion = flutter.ndkVersion

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    defaultConfig {
        applicationId = "com.clavium.app"
        // You can update the following values to match your application needs.
        // For more information, see: https://flutter.dev/to/review-gradle-config.
        // Android 7+: hardware-backed keystore and biometric prompt.
        minSdk = 24
        targetSdk = flutter.targetSdkVersion
        // Uses the version code from pubspec.yaml. When using split APKs, 1000 * ABI_VERSION
        // is added automatically by Flutter. (https://developer.android.com/studio/build/configure-apk-splits#configure-APK-versions)
        // You can force using the value of versionCode by specifying the `-P force-version-code-ignoring-abi=true`
        // flag during build.
        versionCode = flutter.versionCode
        versionName = flutter.versionName
    }

    buildTypes {
        release {
            // CI signs with the release key when CLAVIUM_KEYSTORE is set
            // (see .github/workflows/build-mobile.yml); otherwise the build
            // is debug-signed and must not be distributed.
            val ks = System.getenv("CLAVIUM_KEYSTORE")
            signingConfig = if (ks != null && file(ks).exists()) {
                signingConfigs.create("release") {
                    storeFile = file(ks)
                    storePassword = System.getenv("CLAVIUM_KEYSTORE_PASSWORD")
                    keyAlias = System.getenv("CLAVIUM_KEY_ALIAS")
                    keyPassword = System.getenv("CLAVIUM_KEY_PASSWORD")
                }
            } else {
                signingConfigs.getByName("debug")
            }
        }
    }
}

kotlin {
    compilerOptions {
        jvmTarget = org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17
    }
}

flutter {
    source = "../.."
}
