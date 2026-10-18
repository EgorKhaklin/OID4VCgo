package dev.idfoundry.oid4vcwallet

import android.app.Activity
import android.content.ComponentName
import android.nfc.NfcAdapter
import android.nfc.cardemulation.CardEmulation
import android.nfc.cardemulation.HostApduService
import android.os.Bundle
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import dev.idfoundry.oid4vcwallet.gomobile.mobile.ProximityPresentation as MobileProximityPresentation

/**
 * One armed static NFC engagement and its subsequent BLE presentation.
 * The application retains this object across HCE service recreation. Repeated
 * reads reuse its key, service UUID and handover bytes. Consent and results
 * are exposed through [presentation].
 */
public class NfcPresentation internal constructor(
    handle: MobileProximityPresentation,
    timeouts: ProximityTimeouts,
    negotiated: Boolean = false,
    private val dataTransport: NfcDataHolderTransport? = null,
    transportFor: (HolderEngagement) -> ProximityTransport,
) {
    private val gate = NfcHandoverGate()
    private val tnep = if (negotiated) NfcTnepHolder {
        handle.handleHandoverRequest(it).also { hs ->
            if (dataTransport != null) dataTransport.selectParameters(decode<NfcDataParametersJSON>(
                dev.idfoundry.oid4vcwallet.gomobile.mobile.Mobile.parseNfcDataParameters(hs)))
        }
    } else null
    private val type4 = NfcType4(
        if (negotiated) NfcTnep.parameters else handle.handoverSelect(),
        tnep?.let { it::transact },
    ) { if (tnep == null || tnep.handoverReady) gate.complete() }

    /** The consent flow and final result of this presentation. */
    public val presentation: ProximityPresentation = ProximityPresentation(handle, {
        gate.transport { dataTransport ?: transportFor(currentEngagement()) }
    }, timeouts)

    private fun currentEngagement(): HolderEngagement = presentation.currentHolderEngagement()

    private var dataSelected = false
    @Synchronized internal fun process(command: ByteArray, respond: (ByteArray) -> Unit = {}): ByteArray? {
        if (presentation.state.value.isFinal) return nfcResponse(0x6985)
        val c = NfcCommand.parse(command)
        if (c?.ins == 0xa4 && c.p1 == 4) dataSelected = dataTransport != null && c.data.contentEquals(NfcData.aid)
        return if (dataSelected) dataTransport!!.process(command, respond) else type4.process(command)
    }

    @Synchronized internal fun deactivate() {
        if (tnep != null && !gate.isComplete) {
            if (tnep.handoverReady) {
                presentation.cancel() // Frozen Hr/Hs cannot be replaced after an incomplete RF exchange.
                type4.deactivate()
            } else {
                tnep.resetBeforeSelection()
                type4.deactivate(NfcTnep.parameters)
            }
        } else type4.deactivate()
        if (dataSelected) dataTransport?.deactivate()
        dataSelected = false
    }

    /**
     * Makes the app's declared [service] preferred while [activity] is resumed.
     * Call on every resume while armed, and [releaseForeground] on pause.
     */
    public fun preferForeground(activity: Activity, service: Class<out NfcEngagementService>): Boolean {
        val adapter = NfcAdapter.getDefaultAdapter(activity) ?: return false
        return CardEmulation.getInstance(adapter).setPreferredService(activity, ComponentName(activity, service))
    }

    /** Releases foreground preference when the activity pauses or the presentation ends. */
    public fun releaseForeground(activity: Activity): Boolean {
        val adapter = NfcAdapter.getDefaultAdapter(activity) ?: return false
        return CardEmulation.getInstance(adapter).unsetPreferredService(activity)
    }

    /** Cancels and waits for radio cleanup before a replacement can be armed. */
    public suspend fun close() {
        presentation.cancel()
        presentation.awaitClosed()
        NfcPresentations.clear(this)
    }
}

/** App-level registry; service instances never own or manufacture presentations. */
internal object NfcPresentations {
    private val replacing = Mutex()
    @Volatile private var active: NfcPresentation? = null

    suspend fun replace(create: () -> NfcPresentation): NfcPresentation = replacing.withLock {
        active?.close()
        create().also { active = it }
    }

    @Synchronized fun clear(owner: NfcPresentation) { if (active === owner) active = null }
    fun owner(): NfcPresentation? = active
    fun deactivate() { active?.deactivate() }
}

/** Defers native resource creation until the reader has read the complete Hs. */
internal class NfcHandoverGate {
    private val ready = CompletableDeferred<Unit>()
    val isComplete: Boolean get() = ready.isCompleted && !ready.isCancelled
    fun complete() { ready.complete(Unit) }

    fun transport(create: () -> ProximityTransport): ProximityTransport = object : ProximityTransport {
        private var delegate: ProximityTransport? = null
        private var closed = false
        override suspend fun connect() {
            ready.await()
            val transport = synchronized(this) {
                if (closed) throw ProximityTransportException("NFC presentation closed")
                (delegate ?: create().also { delegate = it })
            }
            transport.connect()
        }
        override suspend fun send(message: ByteArray) = connected().send(message)
        override suspend fun receive(): ByteArray = connected().receive()
        private fun connected(): ProximityTransport = synchronized(this) {
            delegate ?: throw ProximityTransportException("NFC handover incomplete")
        }
        @Synchronized override fun close() {
            if (closed) return
            closed = true
            ready.cancel()
            delegate?.close()
        }
    }
}

/**
 * Subclass and declare in the app manifest with BIND_NFC_SERVICE, the
 * HOST_APDU_SERVICE action and @xml/oid4vc_nfc_aids metadata. The service
 * starts unarmed after process restart; arm using [Wallet.startNfcPresentation].
 */
public abstract class NfcEngagementService : HostApduService() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val serial = Mutex()
    private val responseLock = Any()
    private var epoch = 0L

    /** Serializes one command off the APDU callback thread and returns its response asynchronously. */
    final override fun processCommandApdu(commandApdu: ByteArray, extras: Bundle?): ByteArray? {
        val owner = NfcPresentations.owner() ?: return nfcResponse(0x6985)
        val requestEpoch = synchronized(responseLock) { epoch }
        val command = commandApdu.copyOf()
        scope.launch {
            serial.withLock {
                if (synchronized(responseLock) { epoch != requestEpoch } || NfcPresentations.owner() !== owner) return@withLock
                fun respond(response: ByteArray) {
                    synchronized(responseLock) {
                        if (epoch != requestEpoch || NfcPresentations.owner() !== owner) throw ProximityTransportException("NFC link is no longer active")
                        sendResponseApdu(response)
                    }
                }
                val response = runCatching { owner.process(command, ::respond) }.getOrElse { nfcResponse(0x6f00) }
                response?.let { runCatching { respond(it) } }
            }
        }
        return null
    }

    /** Invalidates pending RF responses and resets file selection; a completed BLE handover continues. */
    final override fun onDeactivated(reason: Int) {
        synchronized(responseLock) { epoch++ }
        val owner = NfcPresentations.owner()
        scope.launch { serial.withLock { owner?.deactivate() } }
    }

    /** Stops this service instance's worker without replacing the application-owned presentation. */
    final override fun onDestroy() {
        synchronized(responseLock) { epoch++ }
        scope.cancel()
        super.onDestroy()
    }
}
