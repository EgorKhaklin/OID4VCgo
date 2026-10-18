package dev.idfoundry.oid4vcgo.demowallet

import dev.idfoundry.oid4vcwallet.NfcEngagementService

/** Routes NFC commands to the application's armed presentation. */
class DemoNfcService : NfcEngagementService()

enum class InPersonEngagement(val label: String) {
    QR("QR code and Bluetooth"),
    NFC_STATIC("NFC tap and Bluetooth"),
    NFC_NEGOTIATED("Negotiated NFC tap and Bluetooth"),
    NFC_DATA("NFC tap and transfer"),
    NFC_NEGOTIATED_DATA("Negotiated NFC tap and transfer"),
}
