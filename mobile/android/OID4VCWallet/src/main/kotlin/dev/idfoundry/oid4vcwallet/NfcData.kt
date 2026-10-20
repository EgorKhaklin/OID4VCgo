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
import java.io.ByteArrayOutputStream
import java.io.IOException

internal object NfcData {
    const val MAX_MESSAGE = 2 * 1024 * 1024
    val aid: ByteArray get() = byteArrayOf(0xa0.toByte(), 0, 0, 2, 0x48, 4, 0)

    fun wrap(message: ByteArray): ByteArray {
        require(message.size <= MAX_MESSAGE) { "NFC message too large" }
        val length = message.size
        val field = when {
            length < 128 -> byteArrayOf(length.toByte())
            length <= 255 -> byteArrayOf(0x81.toByte(), length.toByte())
            length <= 65535 -> byteArrayOf(0x82.toByte(), (length ushr 8).toByte(), length.toByte())
            else -> byteArrayOf(0x83.toByte(), (length ushr 16).toByte(), (length ushr 8).toByte(), length.toByte())
        }
        return byteArrayOf(0x53) + field + message
    }

    fun unwrap(encoded: ByteArray): ByteArray {
        if (encoded.size < 2 || encoded[0].toInt() != 0x53) throw IOException("missing NFC DO53")
        val first = encoded[1].toInt() and 255
        val count = if (first < 128) 0 else first and 127
        if (count > 3 || first == 128 || encoded.size < 2 + count) throw IOException("invalid DO53 length")
        var length = if (count == 0) first else 0
        repeat(count) { length = (length shl 8) or (encoded[it + 2].toInt() and 255) }
        if (length > MAX_MESSAGE || length != encoded.size - 2 - count) throw IOException("NFC message length mismatch")
        if (count > 0 && (length < 128 || encoded[2].toInt() == 0)) throw IOException("noncanonical DO53 length")
        return encoded.copyOfRange(2 + count, encoded.size)
    }
}

@Serializable
internal data class NfcDataParametersJSON(
    @SerialName("max_command") val maxCommand: Int,
    @SerialName("max_response") val maxResponse: Int,
)

/** Command-driven holder transport. Final ENVELOPE waits asynchronously for consent. */
internal class NfcDataHolderTransport(private val sendTimeout: Duration = 300.seconds) : ProximityTransport {
    private val connected = CompletableDeferred<Unit>()
    private val incoming = Channel<ByteArray>(1)
    private val chain = ByteArrayOutputStream()
    private var selected = false
    private var closed = false
    private var outgoing: ByteArray? = null
    private var offset = 0
    private var pending: ((ByteArray) -> Unit)? = null
    private var le = 0
    private var delivered: CompletableDeferred<Unit>? = null
    private var maxCommand = 255
    private var maxResponse = 256

    @Synchronized fun selectParameters(parameters: NfcDataParametersJSON) {
        check(!selected)
        require(parameters.maxCommand in 1..255 && parameters.maxResponse in 1..256)
        maxCommand = parameters.maxCommand
        maxResponse = parameters.maxResponse
    }

    override suspend fun connect() { connected.await() }
    override suspend fun receive(): ByteArray = incoming.receive()

    override suspend fun send(message: ByteArray) {
        val completion = synchronized(this) {
            if (closed || outgoing != null || pending == null) throw ProximityTransportException("NFC has no pending response")
            outgoing = NfcData.wrap(message)
            offset = 0
            val ack = CompletableDeferred<Unit>()
            delivered = ack
            val callback = pending!!
            pending = null
            callback(nextResponse(le))
            ack
        }
        try { withTimeout(sendTimeout) { completion.await() } }
        catch (e: TimeoutCancellationException) { throw ProximityTransportException("NFC reader did not finish reading the response", cause = e) }
    }

    @Synchronized fun process(bytes: ByteArray, respond: (ByteArray) -> Unit): ByteArray? {
        if (closed) return nfcResponse(0x6985)
        val c = NfcCommand.parse(bytes) ?: return nfcResponse(0x6700)
        if (c.ins == 0xa4) {
            if (c.cla != 0 || c.p1 != 4 || c.p2 != 0 || !c.data.contentEquals(NfcData.aid)) return nfcResponse(0x6a82)
            if (chain.size() != 0 || pending != null || outgoing != null) return nfcResponse(0x6985)
            selected = true
            connected.complete(Unit)
            return nfcResponse(0x9000)
        }
        if (!selected) return nfcResponse(0x6985)
        if (c.p1 != 0 || c.p2 != 0) return nfcResponse(0x6a86)
        return when (c.ins) {
            0xc3 -> {
                if (c.cla != 0 && c.cla != 0x10) return nfcResponse(0x6e00)
                if (pending != null || outgoing != null) return nfcResponse(0x6985)
                if (c.data.isEmpty() || c.data.size > maxCommand || chain.size() + c.data.size > NfcData.MAX_MESSAGE + 5) {
                    chain.reset(); return nfcResponse(0x6700)
                }
                if (c.cla == 0x10 && c.le != null || c.cla == 0 && c.le !in 1..maxResponse) return nfcResponse(0x6a86)
                chain.write(c.data)
                if (c.cla == 0x10) return nfcResponse(0x9000)
                val message = try { NfcData.unwrap(chain.toByteArray()) } catch (_: IOException) {
                    chain.reset(); return nfcResponse(0x6a80)
                }
                chain.reset()
                le = c.le!!
                pending = respond
                if (!incoming.trySend(message).isSuccess) { pending = null; return nfcResponse(0x6985) }
                null
            }
            0xc0 -> {
                if (c.cla != 0 || c.data.isNotEmpty() || c.le !in 1..maxResponse) return nfcResponse(0x6a86)
                if (outgoing == null) return nfcResponse(0x6985)
                nextResponse(c.le!!)
            }
            else -> nfcResponse(0x6d00)
        }
    }

    private fun nextResponse(maximum: Int): ByteArray {
        val message = outgoing ?: error("no response")
        val end = minOf(offset + maximum, message.size)
        val chunk = message.copyOfRange(offset, end)
        offset = end
        val remaining = message.size - end
        if (remaining == 0) {
            outgoing = null
            delivered?.complete(Unit)
            return nfcResponse(0x9000, chunk)
        }
        return nfcResponse(0x6100 or if (remaining < 256) remaining else 0, chunk)
    }

    @Synchronized fun deactivate() {
        if (selected) close()
    }

    @Synchronized override fun close() {
        if (closed) return
        closed = true
        val error = ProximityTransportException("NFC field lost or session closed")
        incoming.close(error)
        connected.completeExceptionally(error)
        delivered?.completeExceptionally(error)
        pending = null
        outgoing = null
        chain.reset()
    }
}

/** Reader side of classic command-driven NFC; short APDUs work with limited controllers. */
internal class NfcDataReaderTransport(
    private val exchange: (ByteArray) -> ByteArray,
    private val closeTag: () -> Unit,
    private val maxTransceive: Int,
    private val parameters: NfcDataParametersJSON,
) : ProximityTransport {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val incoming = Channel<ByteArray>(1)
    private var closed = false
    private var sending = false

    override suspend fun connect(): Unit = runNfcExchange(closeTag) {
        val response = exchange(byteArrayOf(0, 0xa4.toByte(), 4, 0, 7) + NfcData.aid + byteArrayOf(0))
        if (!response.contentEquals(nfcResponse(0x9000))) throw IOException("NFC data application unavailable")
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

    internal fun transact(message: ByteArray): ByteArray {
        val commandLimit = minOf(255, maxTransceive - 6, parameters.maxCommand)
        val responseLimit = minOf(256, maxTransceive - 2, parameters.maxResponse)
        if (commandLimit < 1 || responseLimit < 1) throw IOException("NFC controller limits unusable")
        val encoded = NfcData.wrap(message)
        val assembled = ByteArrayOutputStream()
        var offset = 0
        var response = byteArrayOf()
        while (offset < encoded.size) {
            val end = minOf(offset + commandLimit, encoded.size)
            val last = end == encoded.size
            val command = byteArrayOf(if (last) 0 else 0x10, 0xc3.toByte(), 0, 0, (end - offset).toByte()) +
                encoded.copyOfRange(offset, end) + if (last) byteArrayOf(responseLimit.toByte()) else byteArrayOf()
            response = exchange(command)
            if (!last && !response.contentEquals(nfcResponse(0x9000))) throw IOException("NFC command chain failed")
            offset = end
        }
        var polls = 0
        while (true) {
            if (response.size < 2 || response.size - 2 > responseLimit) throw IOException("invalid NFC response size")
            if (assembled.size() + response.size - 2 > NfcData.MAX_MESSAGE + 5) throw IOException("NFC response too large")
            assembled.write(response, 0, response.size - 2)
            val status = ((response[response.size - 2].toInt() and 255) shl 8) or (response.last().toInt() and 255)
            if (status == 0x9000) return NfcData.unwrap(assembled.toByteArray())
            if (response.size == 2) throw IOException("empty NFC response continuation")
            if (status and 0xff00 != 0x6100 || ++polls > NfcData.MAX_MESSAGE + 5) throw IOException("NFC response chain failed")
            val indicated = status and 255
            val le = if (indicated == 0) responseLimit else minOf(indicated, responseLimit)
            // Case 2S: GET RESPONSE has Le only, never a spurious Lc.
            response = exchange(byteArrayOf(0, 0xc0.toByte(), 0, 0, le.toByte()))
        }
    }

    override suspend fun receive(): ByteArray = incoming.receive()
    @Synchronized override fun close() {
        if (closed) return
        closed = true
        scope.cancel()
        closeTag()
        incoming.close()
    }
}
