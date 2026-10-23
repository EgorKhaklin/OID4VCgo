package dev.idfoundry.oid4vcgo.demowallet

import android.content.Intent
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.padding
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import dev.idfoundry.oid4vcwallet.DigitalCredentials

/**
 * What Credential Manager launches when the holder picks one of the
 * wallet's credentials for a page's or app's Digital Credentials API
 * request: the consent screen for its OpenID4VP request, answered back
 * to the platform. The counterpart of the iOS demo's document provider
 * extension, for OpenID4VP requests.
 */
class GetCredentialActivity : ComponentActivity() {
    private val model: WalletModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // The consent screen's claims stay out of the recents thumbnail
        // and screenshots.
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        enableEdgeToEdge()
        model.attach(this)
        model.start(null, provider = true)
        val privileged = resources.openRawResource(R.raw.privileged_browsers).bufferedReader().use { it.readText() }
        // Null unless Credential Manager started the activity (any app
        // can start an exported one), and for a caller whose origin can't
        // be established, among others.
        val request = DigitalCredentials.request(this, privileged)
        // org-iso-mdoc is Safari's route (iOS's): Chrome asks over OpenID4VP.
        if (request == null || request.isMdoc) return fail()
        if (savedInstanceState == null) {
            model.startDCAPI(request) { data ->
                when {
                    data != null -> finishWith(DigitalCredentials.response(request, data))
                    // A request that couldn't be opened: its screen stays,
                    // for the holder to read and close.
                    showsError() -> Unit
                    else -> fail()
                }
            }
        }
        setContent {
            MaterialTheme(colorScheme = if (isSystemInDarkTheme()) darkColorScheme() else lightColorScheme()) {
                Content()
            }
        }
    }

    /** The consent screen once the request is open, else where opening it is. */
    @Composable
    private fun Content() {
        if (model.requestPhase != WalletModel.RequestPhase.IDLE) {
            RequestScreen(model, openBrowser = {})
            return
        }
        when (val phase = model.phase) {
            is WalletModel.Phase.Failed -> Column(Modifier.padding(24.dp)) {
                Text(phase.text)
                TextButton(::fail) { Text("Close") }
            }
            WalletModel.Phase.UntrustedVerifier -> Column {
                UntrustedVerifier()
                TextButton(::fail, Modifier.padding(horizontal = 12.dp)) { Text("Close") }
            }
            else -> Text("Opening the request…", Modifier.padding(24.dp))
        }
    }

    /** Whether the request couldn't be opened, and the screen says why. */
    private fun showsError(): Boolean =
        model.phase is WalletModel.Phase.Failed || model.phase == WalletModel.Phase.UntrustedVerifier

    private fun finishWith(result: Intent) {
        setResult(RESULT_OK, result)
        finish()
    }

    private fun fail() = finishWith(DigitalCredentials.failure("the wallet couldn't answer"))
}
