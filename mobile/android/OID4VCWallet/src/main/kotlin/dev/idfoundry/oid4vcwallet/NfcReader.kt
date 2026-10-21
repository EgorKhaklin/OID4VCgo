package dev.idfoundry.oid4vcwallet

import android.nfc.Tag
import android.nfc.tech.IsoDep
import java.io.IOException
import dev.idfoundry.oid4vcwallet.gomobile.mobile.Mobile

/** Type 4 reader, shared by IsoDep and simulated APDU tests. Go builds and parses every APDU. */
internal class NfcType4Reader(private val exchange: (ByteArray) -> ByteArray, private val maxTransceive: Int) {
    var negotiated: Boolean = false
        private set

    /** Reads the Handover Select, negotiating with [handoverRequest] if the tag offers TNEP. */
    fun read(handoverRequest: ByteArray? = null): ByteArray {
        val read = GoNfcExchange(Mobile.newNFCHandoverRead(maxTransceive.toLong(), handoverRequest))
        return read.drive(exchange).also { negotiated = read.negotiated() }
    }
}

/** The handover bytes used to construct the reader's session transcript. */
internal data class NfcHandover(val hs: ByteArray, val hr: ByteArray?)

internal class NfcTagConnection(tag: Tag) {
    private val iso = IsoDep.get(tag) ?: throw IOException("tag does not support ISO-DEP")
    val maxTransceive: Int get() = iso.maxTransceiveLength
    fun exchange(command: ByteArray): ByteArray = iso.transceive(command)
    fun close() { runCatching { iso.close() } }
    fun allowConsentDelay(milliseconds: Int) { iso.timeout = milliseconds }

    suspend fun read(hr: ByteArray): NfcHandover = runNfcExchange(::close) {
        iso.connect()
        iso.timeout = 5000
        val reader = NfcType4Reader(iso::transceive, iso.maxTransceiveLength)
        val hs = reader.read(hr)
        NfcHandover(hs, if (reader.negotiated) hr else null)
    }
}
