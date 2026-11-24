package com.clavium.app

import android.app.Activity
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.service.autofill.Dataset
import android.view.WindowManager
import android.view.autofill.AutofillId
import android.view.autofill.AutofillManager
import android.view.autofill.AutofillValue
import android.widget.RemoteViews
import androidx.annotation.RequiresApi
import io.flutter.embedding.android.FlutterFragmentActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

/**
 * The small Clavium screen Android opens when someone picks "Fill from
 * Clavium". It runs the Dart entry point `autofillMain` (set in the
 * manifest), which unlocks the vault and lets the person pick a login,
 * then calls back here with the username and password to fill.
 */
@RequiresApi(Build.VERSION_CODES.O)
class AutofillActivity : FlutterFragmentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
    }

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, CHANNEL).setMethodCallHandler { call, result ->
            when (call.method) {
                "request" -> result.success(
                    mapOf(
                        "package" to intent.getStringExtra(EXTRA_PACKAGE),
                        "webDomain" to intent.getStringExtra(EXTRA_WEB_DOMAIN),
                        "hasUsername" to ids(EXTRA_USERNAME_IDS).isNotEmpty(),
                        "hasPassword" to ids(EXTRA_PASSWORD_IDS).isNotEmpty(),
                    ),
                )
                "fill" -> {
                    fill(call.argument<String>("username") ?: "", call.argument<String>("password") ?: "")
                    result.success(null)
                }
                "cancel" -> {
                    setResult(Activity.RESULT_CANCELED)
                    finish()
                    result.success(null)
                }
                else -> result.notImplemented()
            }
        }
    }

    private fun ids(key: String): List<AutofillId> {
        val raw = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            intent.getParcelableArrayExtra(key, AutofillId::class.java)?.toList()
        } else {
            @Suppress("DEPRECATION")
            intent.getParcelableArrayExtra(key)?.mapNotNull { it as? AutofillId }
        }
        return raw ?: emptyList()
    }

    private fun fill(username: String, password: String) {
        val presentation = RemoteViews(packageName, R.layout.autofill_item).apply {
            setTextViewText(R.id.autofill_text, if (username.isNotEmpty()) username else "Clavium")
        }
        @Suppress("DEPRECATION")
        val builder = Dataset.Builder(presentation)
        var any = false
        if (username.isNotEmpty()) ids(EXTRA_USERNAME_IDS).forEach { builder.setValue(it, AutofillValue.forText(username)); any = true }
        if (password.isNotEmpty()) ids(EXTRA_PASSWORD_IDS).forEach { builder.setValue(it, AutofillValue.forText(password)); any = true }
        if (!any) {
            setResult(Activity.RESULT_CANCELED)
        } else {
            setResult(Activity.RESULT_OK, Intent().putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, builder.build()))
        }
        finish()
    }

    companion object {
        const val CHANNEL = "clavium/autofill"
        const val EXTRA_PACKAGE = "clavium.package"
        const val EXTRA_WEB_DOMAIN = "clavium.web_domain"
        const val EXTRA_USERNAME_IDS = "clavium.username_ids"
        const val EXTRA_PASSWORD_IDS = "clavium.password_ids"
    }
}
