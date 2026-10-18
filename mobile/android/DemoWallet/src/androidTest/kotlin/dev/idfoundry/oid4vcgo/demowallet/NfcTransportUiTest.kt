package dev.idfoundry.oid4vcgo.demowallet

import androidx.compose.material3.MaterialTheme
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import dev.idfoundry.oid4vcwallet.ProximityBLEMode
import org.junit.Rule
import org.junit.Test

/** A tap must not be reported as NFC data when the session actually selected BLE. */
class NfcTransportUiTest {
    @get:Rule val compose = createComposeRule()

    @Test fun nfcDataDoesNotDisplayBleMode() {
        compose.setContent { MaterialTheme { ReaderDataTransport(true, ProximityBLEMode.CENTRAL_CLIENT) } }
        compose.onNodeWithText("NFC only").assertIsDisplayed()
        compose.onNodeWithTag("reader-ble-mode").assertDoesNotExist()
    }

    @Test fun bleCentralDisplaysActualRole() {
        compose.setContent { MaterialTheme { ReaderDataTransport(false, ProximityBLEMode.CENTRAL_CLIENT) } }
        compose.onNodeWithText("Central client mode: the holder connected to this reader").assertIsDisplayed()
        compose.onNodeWithText("NFC only").assertDoesNotExist()
    }

    @Test fun blePeripheralDisplaysActualRole() {
        compose.setContent { MaterialTheme { ReaderDataTransport(false, ProximityBLEMode.PERIPHERAL_SERVER) } }
        compose.onNodeWithText("Peripheral server mode: this reader connected to the holder").assertIsDisplayed()
        compose.onNodeWithText("NFC only").assertDoesNotExist()
    }
}
