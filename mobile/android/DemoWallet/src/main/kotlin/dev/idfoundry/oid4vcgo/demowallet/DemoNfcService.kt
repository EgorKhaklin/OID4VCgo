package dev.idfoundry.oid4vcgo.demowallet

import dev.idfoundry.oid4vcwallet.NfcEngagementService

/** Routes NFC commands to the application's armed presentation. */
class DemoNfcService : NfcEngagementService()

/**
 * How the holder engages a reader in person. [nfc] offers an NFC tap,
 * [qr] a QR code; with both, the first reader to engage wins.
 */
enum class InPersonEngagement(
    val label: String,
    val qr: Boolean = false,
    val nfc: Boolean = true,
    val negotiated: Boolean = false,
    val nfcData: Boolean = false,
) {
    QR("QR code and Bluetooth", qr = true, nfc = false),
    QR_OR_NFC("QR code or NFC tap, then Bluetooth", qr = true),
    NFC_STATIC("NFC tap and Bluetooth"),
    NFC_NEGOTIATED("Negotiated NFC tap and Bluetooth", negotiated = true),
    NFC_DATA("NFC tap and transfer", nfcData = true),
    NFC_NEGOTIATED_DATA("Negotiated NFC tap and transfer", negotiated = true, nfcData = true);

    /** Whether the Bluetooth mode setting applies: NFC transfer doesn't use Bluetooth. */
    val usesBluetooth: Boolean get() = !nfcData
}
