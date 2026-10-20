package dev.idfoundry.oid4vcwallet

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.TimeoutCancellationException
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
internal data class NfcDataParametersJSON(
    @SerialName("max_command") val maxCommand: Int,
    @SerialName("max_response") val maxResponse: Int,
)

/**
 * Holder side of NFC data retrieval, as a [ProximityTransport]. Go's holder
 * (via [NfcEngagement]) reassembles the reader's messages and chains the
 * answers; this hands them to and from the session, and holds the final
 * ENVELOPE's response until consent.
 */
internal class NfcDataHolderTransport(private val sendTimeout: Duration = 300.seconds) : ProximityTransport {
    private val connected = CompletableDeferred<Unit>()
    private val incoming = Channel<ByteArray>(1)
    private var core: NfcHolderCore? = null
    private var closed = false
    private var pending: ((ByteArray) -> Unit)? = null
    private var delivered: CompletableDeferred<Unit>? = null

    @Synchronized fun attach(holder: NfcHolderCore) { core = holder }

    override suspend fun connect() { connected.await() }
    override suspend fun receive(): ByteArray = incoming.receive()

    override suspend fun send(message: ByteArray) {
        val completion = synchronized(this) {
            val callback = pending
            if (closed || callback == null) throw ProximityTransportException("NFC has no pending response")
            val step = try { checkNotNull(core).respond(message) } catch (e: Exception) {
                throw ProximityTransportException("NFC response refused", cause = e)
            }
            pending = null
            val ack = CompletableDeferred<Unit>()
            if (step.delivered) ack.complete(Unit) else delivered = ack
            callback(checkNotNull(step.response))
            ack
        }
        try { withTimeout(sendTimeout) { completion.await() } }
        catch (e: TimeoutCancellationException) { throw ProximityTransportException("NFC reader did not finish reading the response", cause = e) }
    }

    /** The reader selected the data application. */
    @Synchronized fun selected() { connected.complete(Unit) }

    /** A session message arrived; its response waits for [send]. Returns the refusal if the session can't take it. */
    @Synchronized fun message(message: ByteArray, respond: (ByteArray) -> Unit): ByteArray? {
        if (closed || !incoming.trySend(message).isSuccess) return checkNotNull(core).refuseMessage()
        // send() takes this lock too, so it can't run before pending is set.
        pending = respond
        return null
    }

    /** The reader read the last of the response. */
    @Synchronized fun delivered() { delivered?.complete(Unit); delivered = null }

    /** Field loss ended retrieval; Go's holder already refuses further commands. */
    @Synchronized fun lost() { closeChannels() }

    @Synchronized override fun close() {
        if (closed) return
        core?.close()
        closeChannels()
    }

    private fun closeChannels() {
        if (closed) return
        closed = true
        val error = ProximityTransportException("NFC field lost or session closed")
        incoming.close(error)
        connected.completeExceptionally(error)
        delivered?.completeExceptionally(error)
        pending = null
    }
}

/** Reader side of classic command-driven NFC; Go builds and parses every APDU. */
internal class NfcDataReaderTransport(
    private val exchange: (ByteArray) -> ByteArray,
    private val closeTag: () -> Unit,
    private val maxTransceive: Int,
    private val parameters: NfcDataParametersJSON,
    private val codec: NfcDataCodec = GoNfcDataCodec,
) : ProximityTransport {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val incoming = Channel<ByteArray>(1)
    private var closed = false
    private var sending = false

    override suspend fun connect(): Unit = runNfcExchange(closeTag) {
        codec.checkSelected(exchange(codec.selectCommand()))
    }

    override suspend fun send(message: ByteArray) {
        synchronized(this) {
            if (closed || sending) throw ProximityTransportException("NFC exchange already pending or closed")
            sending = true
            scope.launch {
                try { incoming.send(transact(message)) }
                catch (e: Exception) { incoming.close(ProximityTransportException("NFC exchange failed", cause = e)) }
                finally { synchronized(this@NfcDataReaderTransport) { sending = false } }
            }
        }
    }

    internal fun transact(message: ByteArray): ByteArray = codec.transact(maxTransceive, parameters, message).drive(exchange)

    override suspend fun receive(): ByteArray = incoming.receive()
    @Synchronized override fun close() {
        if (closed) return
        closed = true
        scope.cancel()
        closeTag()
        incoming.close()
    }
}
