package dev.idfoundry.oid4vcwallet

import android.nfc.Tag
import android.nfc.tech.IsoDep
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.suspendCancellableCoroutine
import java.io.IOException
import kotlin.math.ceil
import kotlin.math.pow

/** Type 4 reader, shared by IsoDep and simulated APDU tests. */
internal class NfcType4Reader(private val exchange: (ByteArray) -> ByteArray, private val maxTransceive: Int) {
    private var chunk = minOf(255, maxTransceive - 2)
    private var writeChunk = minOf(255, maxTransceive - 5)
    private var maxSize = 0
    private var writable = false
    var negotiated: Boolean = false
        private set

    fun read(handoverRequest: ByteArray? = null): ByteArray {
        if (chunk < 15) throw IOException("NFC transceive limit too small")
        command(byteArrayOf(0, 0xa4.toByte(), 4, 0, 7) + NfcType4.AID + byteArrayOf(0))
        select(0xe103)
        val ccLength = unsigned(readBinary(0, 2), 0)
        if (ccLength !in 15..255) throw IOException("invalid capability container length")
        val cc = readFile(0, ccLength)
        if (cc[2].toInt() ushr 4 != 2) throw IOException("unsupported Type 4 mapping")
        val mle = unsigned(cc, 3)
        if (mle < 15) throw IOException("invalid maximum read length")
        chunk = minOf(chunk, mle)
        writeChunk = minOf(writeChunk, unsigned(cc, 5))
        var position = 7
        var ndefFile = -1
        while (position < cc.size) {
            val type = cc[position++].toInt() and 255
            if (type == 0) continue
            if (type == 0xfe) break
            if (position >= cc.size) throw IOException("truncated capability TLV")
            val length = cc[position++].toInt() and 255
            if (position + length > cc.size) throw IOException("truncated capability TLV")
            if (type == 4 && length == 6 && cc[position + 4].toInt() == 0) {
                ndefFile = unsigned(cc, position)
                maxSize = unsigned(cc, position + 2)
                writable = cc[position + 5].toInt() == 0
                break
            }
            position += length
        }
        if (ndefFile < 0 || maxSize !in 3..32767) throw IOException("no supported readable NDEF file")
        select(ndefFile)
        val initial = readMessage()
        val parameters = NfcTnep.serviceParameters(initial) ?: return initial
        negotiated = true
        if (handoverRequest == null || !writable) throw IOException("negotiated NFC handover unavailable")
        val status = transact(NfcTnep.select, parameters)
        if (NfcTnep.payload(status,"Te")?.contentEquals(byteArrayOf(0)) != true) throw IOException("TNEP service selection failed")
        return transact(handoverRequest, parameters)
    }

    private fun readMessage(): ByteArray {
        val nlen = unsigned(readBinary(0, 2), 0)
        if (nlen == 0 || nlen > maxSize - 2) throw IOException("invalid NDEF length")
        val message = ByteArray(nlen)
        var copied = 0
        while (copied < nlen) {
            val count = minOf(chunk, nlen - copied)
            readBinary(copied + 2, count).copyInto(message, copied)
            copied += count
        }
        return message
    }

    internal fun writeMessage(message: ByteArray) {
        if (!writable || writeChunk < 2 || message.size !in 1..(maxSize - 2)) throw IOException("NDEF write exceeds capability")
        writeBinary(0, byteArrayOf(0, 0))
        var written = 0
        while (written < message.size) {
            val end = minOf(written + writeChunk, message.size)
            writeBinary(written + 2, message.copyOfRange(written, end))
            written = end
        }
        writeBinary(0, byteArrayOf((message.size ushr 8).toByte(), message.size.toByte()))
    }

    private fun transact(message: ByteArray, timing: Triple<Int, Int, Int>): ByteArray {
        if (message.size > timing.third) throw IOException("message exceeds TNEP service limit")
        writeMessage(message)
        val delay = ceil(2.0.pow(timing.first / 4.0 - 1)).toLong().coerceAtLeast(1)
        repeat(timing.second + 1) {
            Thread.sleep(delay)
            val nlen = readBinary(0, 2)
            if (unsigned(nlen, 0) > 0) return readMessage()
        }
        throw IOException("TNEP response timed out")
    }

    private fun writeBinary(offset: Int, data: ByteArray) {
        command(byteArrayOf(0, 0xd6.toByte(), (offset ushr 8).toByte(), offset.toByte(), data.size.toByte()) + data)
    }

    private fun select(file: Int) { command(byteArrayOf(0, 0xa4.toByte(), 0, 0x0c, 2, (file ushr 8).toByte(), file.toByte())) }
    private fun readFile(offset: Int, length: Int): ByteArray {
        val result = ByteArray(length)
        var copied = 0
        while (copied < length) {
            val count = minOf(chunk, length - copied)
            readBinary(offset + copied, count).copyInto(result, copied)
            copied += count
        }
        return result
    }
    private fun readBinary(offset: Int, length: Int): ByteArray {
        val response = command(byteArrayOf(0, 0xb0.toByte(), (offset ushr 8).toByte(), offset.toByte(), length.toByte()))
        if (response.size != length) throw IOException("short READ BINARY response")
        return response
    }
    private fun command(bytes: ByteArray): ByteArray {
        if (bytes.size > maxTransceive) throw IOException("NFC command exceeds transceive limit")
        val response = exchange(bytes)
        if (response.size < 2 || unsigned(response, response.size - 2) != 0x9000) throw IOException("NFC command failed")
        return response.copyOf(response.size - 2)
    }
    private fun unsigned(bytes: ByteArray, offset: Int): Int =
        ((bytes[offset].toInt() and 255) shl 8) or (bytes[offset + 1].toInt() and 255)
}

/** Reads engagement with cancellation closing IsoDep to interrupt a blocking transceive. */
internal data class NfcHandover(val hs: ByteArray, val hr: ByteArray?)

internal class NfcTagConnection(tag: Tag) {
    private val iso = IsoDep.get(tag) ?: throw IOException("tag does not support ISO-DEP")
    val maxTransceive: Int get() = iso.maxTransceiveLength
    fun exchange(command: ByteArray): ByteArray = iso.transceive(command)
    fun close() { runCatching { iso.close() } }
    fun allowConsentDelay(milliseconds: Int) { iso.timeout = milliseconds }

    suspend fun read(hr: ByteArray): NfcHandover = withContext(Dispatchers.IO) {
        suspendCancellableCoroutine { continuation ->
            continuation.invokeOnCancellation { close() }
            if (!continuation.isActive) return@suspendCancellableCoroutine
            // This function runs on Dispatchers.IO; cancellation can still close the tag.
            val result = runCatching {
                iso.connect()
                if (!continuation.isActive) { close(); throw kotlinx.coroutines.CancellationException("NFC read cancelled") }
                iso.timeout = 5000
                val reader = NfcType4Reader(iso::transceive, iso.maxTransceiveLength)
                val hs = reader.read(hr)
                NfcHandover(hs, if (reader.negotiated) hr else null)
            }
            continuation.resumeWith(result)
        }
    }
}
