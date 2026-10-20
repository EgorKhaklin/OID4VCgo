package dev.idfoundry.oid4vcwallet

/**
 * Application-owned NFC engagement state: [holder] (Go) answers every APDU;
 * this adds QR/NFC arbitration, the handover gate and NFC data's transport.
 */
internal class NfcEngagement(
    private val holder: NfcHolderCore,
    private val dataTransport: NfcDataHolderTransport?,
    private val combined: CombinedEngagementArbiter?,
    private val cancel: () -> Unit,
) {
    val gate = NfcHandoverGate()

    init { dataTransport?.attach(holder) }

    @Synchronized fun process(command: ByteArray, respond: (ByteArray) -> Unit = {}): ByteArray? {
        val kind = holder.classify(command)
        if (combined?.acceptNfc(kind, gate.isComplete) == false) return nfcResponse(0x6985)
        if (kind == NfcCommandKind.SELECT_NDEF) ProximityDiagnostics.event("NFC Type 4 SELECT accepted (discovery)")
        val step = holder.process(command)
        // NFC data commits on its own AID SELECT. BLE commits only after reading Hs.
        if (step.handoverRead && (dataTransport != null || combined == null || combined.select(true))) {
            gate.complete()
            ProximityDiagnostics.event("NFC handover fully read; gate complete")
        }
        if (step.dataSelected) dataTransport?.selected()
        if (step.delivered) dataTransport?.delivered()
        // A session message's response waits for the session (null), unless it's refused.
        val message = step.message
        val response = if (message != null) checkNotNull(dataTransport).message(message, respond) else step.response
        // QR may finish while an APDU (including negotiation) is being processed.
        return if (combined?.acceptNfc(NfcCommandKind.OTHER, gate.isComplete) == false) nfcResponse(0x6985) else response
    }

    @Synchronized fun deactivate() {
        val qrSelected = combined?.state?.value == SelectedEngagement.QR
        val d = holder.deactivate(gate.isComplete, qrSelected)
        if (qrSelected) return // Losing NFC field loss must not cancel the winning QR session.
        if (d.cancel) {
            ProximityDiagnostics.event("NFC field lost after negotiated Hs creation; cancelling frozen handover")
            cancel()
        }
        if (d.dataClosed) dataTransport?.lost()
        if (!gate.isComplete && !d.cancel) {
            ProximityDiagnostics.event("NFC attempt reset before handover; QR offer retained if available")
        }
    }
}
