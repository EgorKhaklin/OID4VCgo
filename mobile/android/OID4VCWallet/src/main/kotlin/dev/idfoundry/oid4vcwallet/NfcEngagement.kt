package dev.idfoundry.oid4vcwallet

/** Application-owned APDU state, shared by HCE and host tests without Android or Go handles. */
internal class NfcEngagement(
    initialMessage: ByteArray,
    negotiate: ((ByteArray) -> ByteArray)?,
    private val dataTransport: NfcDataHolderTransport?,
    private val combined: CombinedEngagementArbiter?,
    private val cancel: () -> Unit,
) {
    val gate = NfcHandoverGate()
    private val tnep = negotiate?.let { NfcTnepHolder(it) }
    private val type4 = NfcType4(initialMessage, tnep?.let { it::transact }) {
        // NFC data commits on its own AID SELECT. BLE commits only after reading Hs.
        val handoverRead = tnep == null || tnep.handoverReady
        if (handoverRead && (dataTransport != null || combined == null || combined.select(true))) {
            gate.complete()
            ProximityDiagnostics.event("NFC handover fully read; gate complete")
        }
    }
    private var dataSelected = false

    @Synchronized fun process(command: ByteArray, respond: (ByteArray) -> Unit = {}): ByteArray? {
        val c = NfcCommand.parse(command)
        if (combined?.acceptNfc(c, gate.isComplete) == false) return nfcResponse(0x6985)
        if (c?.cla == 0 && c.ins == 0xa4 && c.p1 == 4 && (c.p2 == 0 || c.p2 == 0x0c)) {
            dataSelected = dataTransport != null && c.data.contentEquals(NfcData.aid)
            if (c.data.contentEquals(NfcType4.AID)) ProximityDiagnostics.event("NFC Type 4 SELECT accepted (discovery)")
        }
        val response = if (dataSelected) dataTransport!!.process(command, respond) else type4.process(command)
        // QR may finish while an APDU (including negotiation) is being processed.
        return if (combined?.acceptNfc(null, gate.isComplete) == false) nfcResponse(0x6985) else response
    }

    @Synchronized fun deactivate() {
        if (combined?.state?.value == SelectedEngagement.QR) {
            type4.deactivate()
            dataSelected = false
            return // Losing NFC field loss must not cancel the winning QR session.
        }
        if (tnep != null && !gate.isComplete) {
            if (tnep.handoverReady) {
                ProximityDiagnostics.event("NFC field lost after negotiated Hs creation; cancelling frozen handover")
                cancel()
                type4.deactivate()
            } else {
                tnep.resetBeforeSelection()
                type4.deactivate(NfcTnep.parameters)
            }
        } else type4.deactivate()
        if (dataSelected) dataTransport?.deactivate()
        dataSelected = false
        if (!gate.isComplete && (tnep == null || !tnep.handoverReady)) {
            ProximityDiagnostics.event("NFC attempt reset before handover; QR offer retained if available")
        }
    }
}
