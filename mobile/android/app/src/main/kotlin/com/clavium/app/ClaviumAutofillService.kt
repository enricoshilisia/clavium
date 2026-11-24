package com.clavium.app

import android.app.PendingIntent
import android.app.assist.AssistStructure
import android.content.Intent
import android.os.Build
import android.os.CancellationSignal
import android.service.autofill.AutofillService
import android.service.autofill.Dataset
import android.service.autofill.FillCallback
import android.service.autofill.FillRequest
import android.service.autofill.FillResponse
import android.service.autofill.SaveCallback
import android.service.autofill.SaveRequest
import android.text.InputType
import android.view.View
import android.view.autofill.AutofillId
import android.widget.RemoteViews
import androidx.annotation.RequiresApi

/**
 * Clavium as Android's autofill provider.
 *
 * It never reads the vault here. It only works out which fields on the
 * screen are a username and a password and which website or app they
 * belong to, then offers a single "Unlock Clavium" choice. Picking it opens
 * [AutofillActivity], where the person unlocks and chooses a login; that
 * activity hands back the filled-in values.
 */
@RequiresApi(Build.VERSION_CODES.O)
class ClaviumAutofillService : AutofillService() {

    override fun onFillRequest(request: FillRequest, cancellationSignal: CancellationSignal, callback: FillCallback) {
        val structure = request.fillContexts.lastOrNull()?.structure
        if (structure == null) {
            callback.onSuccess(null)
            return
        }
        val form = FormParser(structure).parse()
        // Nothing to fill, or Clavium itself.
        if (form.passwordIds.isEmpty() && form.usernameIds.isEmpty() || form.packageName == packageName) {
            callback.onSuccess(null)
            return
        }
        // A username field alone is only worth offering on a known login page
        // shape (e.g. step one of a two-step sign-in), not on every text box.
        if (form.passwordIds.isEmpty() && !form.usernameStrong) {
            callback.onSuccess(null)
            return
        }

        val intent = Intent(this, AutofillActivity::class.java).apply {
            putExtra(AutofillActivity.EXTRA_PACKAGE, form.packageName)
            putExtra(AutofillActivity.EXTRA_WEB_DOMAIN, form.webDomain)
            putExtra(AutofillActivity.EXTRA_USERNAME_IDS, form.usernameIds.toTypedArray())
            putExtra(AutofillActivity.EXTRA_PASSWORD_IDS, form.passwordIds.toTypedArray())
        }
        val flags = PendingIntent.FLAG_CANCEL_CURRENT or
            (if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) PendingIntent.FLAG_MUTABLE else 0)
        val sender = PendingIntent.getActivity(this, nextRequestCode(), intent, flags).intentSender

        val label = if (form.webDomain != null) "Fill from Clavium · ${form.webDomain}" else "Fill from Clavium"
        val presentation = RemoteViews(packageName, R.layout.autofill_item).apply {
            setTextViewText(R.id.autofill_text, label)
        }
        @Suppress("DEPRECATION")
        val dataset = Dataset.Builder(presentation).apply {
            (form.usernameIds + form.passwordIds).forEach { setValue(it, null) }
            setAuthentication(sender)
        }.build()
        callback.onSuccess(FillResponse.Builder().addDataset(dataset).build())
    }

    // Saving new logins from other apps comes later; nothing is stored now.
    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
        callback.onSuccess()
    }

    companion object {
        private var requestCode = 1
        @Synchronized
        private fun nextRequestCode(): Int = requestCode++
    }
}

/** What the login form on screen looks like. */
@RequiresApi(Build.VERSION_CODES.O)
class Form(
    val packageName: String,
    val webDomain: String?,
    val usernameIds: List<AutofillId>,
    val passwordIds: List<AutofillId>,
    /** The username field says outright that it is one (hints or HTML). */
    val usernameStrong: Boolean,
)

@RequiresApi(Build.VERSION_CODES.O)
class FormParser(private val structure: AssistStructure) {
    private val usernames = mutableListOf<AutofillId>()
    private val passwords = mutableListOf<AutofillId>()
    private var strong = false
    private var webDomain: String? = null
    /** Text fields in screen order, to guess the username before a password. */
    private val textFields = mutableListOf<Pair<AutofillId, Boolean>>() // id, isPassword

    fun parse(): Form {
        for (i in 0 until structure.windowNodeCount) visit(structure.getWindowNodeAt(i).rootViewNode)
        if (usernames.isEmpty() && passwords.isNotEmpty()) {
            // The text field just before the first password field.
            val firstPw = textFields.indexOfFirst { it.second }
            textFields.take(maxOf(firstPw, 0)).lastOrNull { !it.second }?.let { usernames.add(it.first) }
        }
        return Form(structure.activityComponent.packageName, webDomain, usernames.distinct(), passwords.distinct(), strong)
    }

    private fun visit(node: AssistStructure.ViewNode) {
        if (webDomain == null && !node.webDomain.isNullOrBlank()) webDomain = node.webDomain
        val id = node.autofillId
        if (id != null && node.autofillType == View.AUTOFILL_TYPE_TEXT && node.visibility == View.VISIBLE) classify(node, id)
        for (i in 0 until node.childCount) visit(node.getChildAt(i))
    }

    private fun classify(node: AssistStructure.ViewNode, id: AutofillId) {
        val hints = node.autofillHints?.map { it.lowercase() } ?: emptyList()
        val html = node.htmlInfo
        val attrs = html?.attributes?.associate { (it.first ?: "").lowercase() to (it.second ?: "").lowercase() } ?: emptyMap()
        val htmlType = attrs["type"] ?: ""
        val auto = attrs["autocomplete"] ?: ""
        val words = listOfNotNull(node.idEntry, node.hint, attrs["name"], attrs["id"], attrs["placeholder"], attrs["aria-label"])
            .joinToString(" ").lowercase()

        // Never touch search boxes, one-time codes or card fields.
        if (hints.any { it.contains("otp") || it.contains("sms") || it.contains("creditcard") } ||
            auto.contains("one-time-code") || auto.startsWith("cc-") || htmlType == "search" ||
            words.contains("search") || words.contains("otp") || words.contains("captcha")
        ) {
            return
        }

        val variation = node.inputType and InputType.TYPE_MASK_VARIATION
        val cls = node.inputType and InputType.TYPE_MASK_CLASS
        val isPassword = hints.any { it.contains("password") } ||
            htmlType == "password" || auto == "current-password" || auto == "new-password" ||
            (cls == InputType.TYPE_CLASS_TEXT && (variation == InputType.TYPE_TEXT_VARIATION_PASSWORD ||
                variation == InputType.TYPE_TEXT_VARIATION_WEB_PASSWORD ||
                variation == InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD)) ||
            (cls == InputType.TYPE_CLASS_NUMBER && variation == InputType.TYPE_NUMBER_VARIATION_PASSWORD) ||
            (html == null && words.contains("password"))

        if (isPassword) {
            passwords.add(id)
            textFields.add(id to true)
            return
        }

        val strongUser = hints.any { it.contains("username") || it.contains("email") || it == View.AUTOFILL_HINT_PHONE.lowercase() } ||
            auto == "username" || auto == "email" || htmlType == "email"
        val looksUser = strongUser ||
            (cls == InputType.TYPE_CLASS_TEXT && (variation == InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS ||
                variation == InputType.TYPE_TEXT_VARIATION_WEB_EMAIL_ADDRESS)) ||
            listOf("user", "email", "login", "account", "phone", "mobile", "msisdn", "id number").any { words.contains(it) }

        if (looksUser) {
            usernames.add(id)
            if (strongUser) strong = true
        }
        if (cls == InputType.TYPE_CLASS_TEXT || cls == InputType.TYPE_CLASS_PHONE || cls == InputType.TYPE_CLASS_NUMBER || html != null) {
            textFields.add(id to false)
        }
    }
}
