package com.clavium.app

import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.view.WindowManager
import android.view.autofill.AutofillManager
import io.flutter.embedding.android.FlutterFragmentActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

// FlutterFragmentActivity is required by the biometric prompt (local_auth).
class MainActivity : FlutterFragmentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // No screenshots, screen recording, or vault contents in the
        // recent-apps preview.
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
    }

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        // Settings screen: is Clavium the autofill service, and a way to
        // open Android's chooser.
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, "clavium/autofill_settings").setMethodCallHandler { call, result ->
            val supported = Build.VERSION.SDK_INT >= Build.VERSION_CODES.O
            when (call.method) {
                "status" -> {
                    if (!supported) {
                        result.success(mapOf("supported" to false, "enabled" to false))
                    } else {
                        val am = getSystemService(AutofillManager::class.java)
                        result.success(
                            mapOf(
                                "supported" to (am?.isAutofillSupported == true),
                                "enabled" to (am?.hasEnabledAutofillServices() == true),
                            ),
                        )
                    }
                }
                "open" -> {
                    if (supported) {
                        try {
                            startActivity(Intent(Settings.ACTION_REQUEST_SET_AUTOFILL_SERVICE).setData(Uri.parse("package:$packageName")))
                        } catch (e: Exception) {
                            startActivity(Intent(Settings.ACTION_SETTINGS))
                        }
                    }
                    result.success(null)
                }
                else -> result.notImplemented()
            }
        }
    }
}
