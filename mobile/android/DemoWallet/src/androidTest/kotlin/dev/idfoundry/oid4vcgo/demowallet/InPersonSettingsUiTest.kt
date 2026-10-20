package dev.idfoundry.oid4vcgo.demowallet

import androidx.compose.foundation.layout.Column
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import dev.idfoundry.oid4vcwallet.ProximityBLEMode
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test

/** Engagement and Bluetooth mode are chosen together, and an unused Bluetooth mode can't be. */
class InPersonSettingsUiTest {
    @get:Rule val compose = createComposeRule()

    private var engagement by mutableStateOf(InPersonEngagement.QR)
    private var modes by mutableStateOf(ProximityBLEMode.entries.toSet())

    private fun show() = compose.setContent { MaterialTheme { Column {
        InPersonSettings(engagement, modes, { engagement = it }, { modes = it })
    } } }

    @Test fun engagementThenBluetoothModeInOneVisit() {
        show()
        compose.onNodeWithTag("engagement-NFC_NEGOTIATED").performClick()
        compose.onNodeWithTag("ble-modes-PERIPHERAL_SERVER").performClick()
        compose.runOnIdle {
            assertEquals(InPersonEngagement.NFC_NEGOTIATED, engagement)
            assertEquals(setOf(ProximityBLEMode.PERIPHERAL_SERVER), modes)
        }
    }

    @Test fun nfcTransferGreysOutBluetoothModes() {
        show()
        compose.onNodeWithTag("engagement-NFC_DATA").performClick()
        compose.onNodeWithTag("ble-modes-unused").assertIsDisplayed()
        compose.onNodeWithTag("ble-modes-CENTRAL_CLIENT").assertIsNotEnabled().performClick()
        compose.runOnIdle { assertEquals(ProximityBLEMode.entries.toSet(), modes) }
        compose.onNodeWithTag("engagement-QR_OR_NFC").performClick()
        compose.onNodeWithTag("ble-modes-unused").assertDoesNotExist()
        compose.onNodeWithTag("ble-modes-CENTRAL_CLIENT").assertIsEnabled()
    }

    @Test fun sharedShowsGreenTickAndDeclinedDoesNot() {
        var state by mutableStateOf<dev.idfoundry.oid4vcwallet.ProximityPresentation.State>(dev.idfoundry.oid4vcwallet.ProximityPresentation.State.Presented(false))
        compose.setContent { MaterialTheme { InPersonOutcome(state, onDone = {}) } }
        compose.onNodeWithTag("in-person-shared").assertIsDisplayed()
        state = dev.idfoundry.oid4vcwallet.ProximityPresentation.State.Declined
        compose.onNodeWithTag("in-person-shared").assertDoesNotExist()
        compose.onNodeWithTag("in-person-ended").assertIsDisplayed()
    }

    @Test fun combinedOfferAsksForTheTapUnderTheQrCode() {
        compose.setContent { MaterialTheme { QRCodeView("mdoc:owBjMS4w", connected = false, orTap = true) } }
        compose.onNodeWithTag("in-person-qr").assertIsDisplayed()
        compose.onNodeWithTag("in-person-or-tap").assertIsDisplayed()
        compose.onNodeWithTag("nfc-tap-indicator").assertIsDisplayed()
    }
}
