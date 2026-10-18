package dev.idfoundry.oid4vcwallet

/** ISO 7816 command cases, with no Android dependency for boundary testing. */
internal data class NfcCommand(val cla: Int, val ins: Int, val p1: Int, val p2: Int, val data: ByteArray, val le: Int?) {
    companion object {
        fun parse(bytes: ByteArray): NfcCommand? {
            if (bytes.size < 4 || bytes.size > 65544) return null
            fun u(i: Int): Int = bytes[i].toInt() and 255
            var data = byteArrayOf()
            var le: Int? = null
            if (bytes.size == 5) {
                le = u(4).let { if (it == 0) 256 else it }
            } else if (bytes.size > 5) {
                val extended = u(4) == 0
                val start = if (extended) 7 else 5
                if (bytes.size < start) return null
                val length = if (extended) (u(5) shl 8) or u(6) else u(4)
                if (extended && bytes.size == 7) {
                    le = if (length == 0) 65536 else length
                } else {
                    if (length == 0 || start + length > bytes.size) return null
                    val remaining = bytes.size - start - length
                    if (remaining != 0 && remaining != if (extended) 2 else 1) return null
                    data = bytes.copyOfRange(start, start + length)
                    if (remaining != 0) {
                        val n = if (extended) (u(bytes.size - 2) shl 8) or u(bytes.size - 1) else u(bytes.size - 1)
                        le = if (n == 0) { if (extended) 65536 else 256 } else n
                    }
                }
            }
            return NfcCommand(u(0), u(1), u(2), u(3), data, le)
        }
    }
}

internal fun nfcResponse(status: Int, data: ByteArray = byteArrayOf()): ByteArray =
    data + byteArrayOf((status ushr 8).toByte(), status.toByte())

/** Read-only Type 4 NDEF application. An armed owner supplies immutable Hs bytes. */
internal class NfcType4(handover: ByteArray, private val update: ((ByteArray) -> ByteArray)? = null, private val readComplete: () -> Unit) {
    private var ndef: ByteArray
    private var committed: ByteArray
    private val coverage = java.util.BitSet(handover.size)
    private var notified = false
    private var selected = false
    private var file = 0
    private var staged: ByteArray? = null
    private val written = java.util.BitSet(32765)

    init {
        require(handover.isNotEmpty() && handover.size <= 32765) { "NDEF file too large or empty" }
        ndef = byteArrayOf((handover.size ushr 8).toByte(), handover.size.toByte()) + handover.copyOf()
        committed = ndef
    }

    @Synchronized fun deactivate(resetMessage: ByteArray? = null) {
        selected = false
        file = 0
        if (resetMessage != null) {
            require(resetMessage.size in 1..32765)
            committed = byteArrayOf((resetMessage.size ushr 8).toByte(), resetMessage.size.toByte()) + resetMessage.copyOf()
            notified = false
        }
        ndef = committed
        coverage.clear()
        staged = null
        written.clear()
    }

    @Synchronized fun process(bytes: ByteArray): ByteArray {
        val c = NfcCommand.parse(bytes) ?: return nfcResponse(0x6700)
        if (c.cla != 0) return nfcResponse(0x6e00)
        if (c.ins == 0xa4 && c.p1 == 4) {
            if (c.p2 != 0 && c.p2 != 0x0c) return nfcResponse(0x6a86)
            // A failed application selection invalidates any previous file selection.
            selected = c.data.contentEquals(AID)
            file = 0
            return nfcResponse(if (selected) 0x9000 else 0x6a82)
        }
        if (!selected) return nfcResponse(0x6985)
        return when (c.ins) {
            0xa4 -> {
                if (c.p1 != 0 || c.p2 != 0x0c || c.data.size != 2) return nfcResponse(0x6a86)
                file = ((c.data[0].toInt() and 255) shl 8) or (c.data[1].toInt() and 255)
                if (file != 0xe103 && file != 0xe104) { file = 0; nfcResponse(0x6a82) } else nfcResponse(0x9000)
            }
            0xb0 -> {
                if (c.p1 and 0x80 != 0 || c.data.isNotEmpty() || c.le == null) return nfcResponse(0x6a86)
                val source = when (file) { 0xe103 -> CC.copyOf().also { if (update != null) it[14] = 0 }; 0xe104 -> ndef; else -> return nfcResponse(0x6985) }
                val offset = (c.p1 shl 8) or c.p2
                if (offset >= source.size) return nfcResponse(0x6b00)
                if (c.le > 255) return nfcResponse(0x6cFF)
                val end = minOf(offset + c.le, source.size)
                if (file == 0xe104) {
                    val from = maxOf(offset, 2) - 2
                    val to = maxOf(end, 2) - 2
                    if (to > from) coverage.set(from, to)
                    if (!notified && coverage.nextClearBit(0) >= ndef.size - 2) {
                        notified = true
                        readComplete()
                    }
                }
                nfcResponse(if (end - offset == c.le) 0x9000 else 0x6282, source.copyOfRange(offset, end))
            }
            0xd6 -> write(c)
            else -> nfcResponse(0x6d00)
        }
    }

    private fun write(c: NfcCommand): ByteArray {
        val handler = update ?: return nfcResponse(0x6986)
        if (file != 0xe104) return nfcResponse(0x6985)
        if (c.p1 and 0x80 != 0 || c.data.isEmpty() || c.data.size > 255 || c.le != null) return nfcResponse(0x6a86)
        val offset = (c.p1 shl 8) or c.p2
        if (offset == 0) {
            if (c.data.size < 2) return nfcResponse(0x6700)
            val length = ((c.data[0].toInt() and 255) shl 8) or (c.data[1].toInt() and 255)
            if (length == 0 && c.data.size == 2) {
                staged = ByteArray(32765)
                written.clear()
                ndef = byteArrayOf(0, 0)
                return nfcResponse(0x9000)
            }
            if (length !in 1..32765) return nfcResponse(0x6a84)
            val incoming = when {
                c.data.size == length + 2 -> c.data.copyOfRange(2, c.data.size)
                c.data.size == 2 && staged != null && written.nextClearBit(0) >= length -> staged!!.copyOf(length)
                else -> return nfcResponse(0x6985)
            }
            staged = null
            written.clear()
            val response = try { handler(incoming) } catch (_: Exception) { return nfcResponse(0x6a80) }
            if (response.size !in 1..32765) return nfcResponse(0x6a84)
            ndef = byteArrayOf((response.size ushr 8).toByte(), response.size.toByte()) + response
            committed = ndef
            coverage.clear()
            notified = false
            return nfcResponse(0x9000)
        }
        val buffer = staged ?: return nfcResponse(0x6985)
        if (offset < 2 || offset - 2 + c.data.size > buffer.size) return nfcResponse(0x6a84)
        c.data.copyInto(buffer, offset - 2)
        written.set(offset - 2, offset - 2 + c.data.size)
        return nfcResponse(0x9000)
    }

    companion object {
        val AID: ByteArray get() = byteArrayOf(0xd2.toByte(), 0x76, 0, 0, 0x85.toByte(), 1, 1)
        private val CC = byteArrayOf(0, 15, 0x20, 0, 0xff.toByte(), 0, 0xff.toByte(), 4, 6, 0xe1.toByte(), 4, 0x7f, 0xff.toByte(), 0, 0xff.toByte())
    }
}
