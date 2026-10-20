package dev.idfoundry.oid4vcwallet

import java.io.IOException

/** Small TNEP control records; Hs/Hr themselves are handled by the bounded Go codec. */
internal object NfcTnep {
    private val service = "urn:nfc:sn:handover".toByteArray(Charsets.US_ASCII)
    val parameters: ByteArray get() = record("Tp", byteArrayOf(0x10, service.size.toByte()) + service + byteArrayOf(0, 16, 15, 0x7f, 0xfd.toByte()))
    val select: ByteArray get() = record("Ts", byteArrayOf(service.size.toByte()) + service)
    val deselect: ByteArray get() = record("Ts", byteArrayOf(0))
    val success: ByteArray get() = record("Te", byteArrayOf(0))

    fun record(type: String, payload: ByteArray): ByteArray {
        require(type.length == 2 && payload.size <= 255)
        return byteArrayOf(0xd1.toByte(), 2, payload.size.toByte()) + type.toByteArray(Charsets.US_ASCII) + payload
    }

    fun payload(message: ByteArray, type: String): ByteArray? {
        val entries = records(message)
        return entries.singleOrNull()?.takeIf { it.first == type }?.second
    }

    private fun records(message: ByteArray): List<Pair<String, ByteArray>> {
        if (message.size !in 1..32765) throw IOException("invalid TNEP NDEF size")
        var pos = 0
        val entries = mutableListOf<Pair<String, ByteArray>>()
        while (pos < message.size && entries.size < 128) {
            fun next(): Int = if (pos < message.size) message[pos++].toInt() and 255 else throw IOException("truncated NDEF record")
            val flags = next()
            if ((flags and 0x80 != 0) != entries.isEmpty() || flags and 0x20 != 0 || flags and 7 > 5) throw IOException("unsupported NDEF framing")
            val typeLength = next()
            var size = next().toLong()
            if (flags and 0x10 == 0) repeat(3) { size = (size shl 8) or next().toLong() }
            val idLength = if (flags and 8 != 0) next() else 0
            val tnf = flags and 7
            if (tnf == 0 && typeLength + idLength + size != 0L || tnf in 1..4 && typeLength == 0 || tnf == 5 && typeLength != 0) throw IOException("invalid NDEF type")
            if (typeLength + idLength + size > message.size - pos) throw IOException("truncated NDEF payload")
            val type = message.copyOfRange(pos, pos + typeLength).toString(Charsets.US_ASCII)
            pos += typeLength + idLength
            val end = pos + size.toInt()
            entries.add((if (flags and 7 == 1) type else "") to message.copyOfRange(pos, end))
            pos = end
            if (flags and 0x40 != 0) {
                if (pos != message.size) throw IOException("bytes after NDEF end")
                return entries
            }
        }
        throw IOException("missing NDEF end or too many records")
    }

    fun serviceParameters(message: ByteArray): Triple<Int, Int, Int>? {
        val matching = records(message).filter { (type, p) ->
            type == "Tp" && p.size >= 2 && (p[1].toInt() and 255) == service.size && p.size >= service.size + 2 && p.copyOfRange(2, 2 + service.size).contentEquals(service)
        }
        if (matching.isEmpty()) return null
        if (matching.size != 1) throw IOException("duplicate TNEP handover service")
        val p = matching.single().second
        if (p.size != service.size + 7 || p[0].toInt() != 0x10 || p[2 + service.size].toInt() != 0) throw IOException("unsupported TNEP service")
        val wt = p[3 + service.size].toInt() and 255
        val waits = p[4 + service.size].toInt() and 255
        val maximum = ((p[5 + service.size].toInt() and 255) shl 8) or (p[6 + service.size].toInt() and 255)
        if (wt > 63 || waits > 15) throw IOException("invalid TNEP timing")
        if (maximum == 0) throw IOException("invalid TNEP message limit")
        return Triple(wt, waits, maximum)
    }
}

internal class NfcTnepHolder(private val selectCarrier: (ByteArray) -> ByteArray) {
    private var selected = false
    var handoverReady: Boolean = false
        private set

    fun resetBeforeSelection() { check(!handoverReady); selected = false }

    fun transact(message: ByteArray): ByteArray {
        val service = NfcTnep.payload(message, "Ts")
        if (service?.contentEquals(byteArrayOf(0)) == true) {
            selected = false
            return NfcTnep.parameters
        }
        if (service != null && service.contentEquals(NfcTnep.payload(NfcTnep.select, "Ts"))) {
            selected = true
            return NfcTnep.success
        }
        check(selected) { "TNEP service not selected" }
        if (NfcTnep.payload(message, "Te")?.contentEquals(byteArrayOf(0)) == true && handoverReady) return NfcTnep.success
        return selectCarrier(message).also { handoverReady = true }
    }
}
