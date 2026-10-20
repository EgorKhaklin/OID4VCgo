package dev.idfoundry.oid4vcwallet

import java.io.IOException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.*
import org.junit.Test

class CombinedNfcHandoverTest {
    private class Transport(private val start: suspend () -> Unit) : ProximityTransport {
        var closed = false
        var connections = 0
        override suspend fun connect() { connections++; start() }
        override suspend fun send(message: ByteArray) {}
        override suspend fun receive(): ByteArray = byteArrayOf(1)
        override fun close() { closed = true }
    }

    private class Offers(negotiated: Boolean, data: Boolean = false) {
        val hs = NfcTnep.record("Hs", ByteArray(120) { it.toByte() })
        val hr = NfcTnep.record("Hr", byteArrayOf(0x15))
        val qrStarted = CompletableDeferred<Unit>()
        val qrConnected = CompletableDeferred<Unit>()
        var claims = 0
        var cancelled = false
        var hsProduced = false
        var beforeHs: () -> Unit = {}
        val arbiter = CombinedEngagementArbiter(data) { claims++ }
        val engagement = NfcEngagement(
            if (negotiated) NfcTnep.parameters else hs,
            if (negotiated) { _ -> hsProduced = true; beforeHs(); hs } else null,
            if (data) NfcDataHolderTransport() else null,
            arbiter,
        ) { cancelled = true; arbiter.close() }
        val qr = Transport { qrStarted.complete(Unit); qrConnected.await() }
        val nfc = Transport { assertTrue("NFC started before QR cleanup", qr.closed) }
        var nativeCreated = 0
        val combined = CombinedTransport(arbiter, qr, engagement.gate.transport { nativeCreated++; nfc })

        fun exchange(command: ByteArray): ByteArray = checkNotNull(engagement.process(command))
        fun ok(command: ByteArray, trace: Boolean = false): ByteArray {
            val response = exchange(command)
            if (trace) println("APDU ${command.hex()} -> ${response.hex()}")
            assertTrue("unexpected APDU status", response.takeLast(2).toByteArray().contentEquals(nfcResponse(0x9000)))
            return response.copyOf(response.size - 2)
        }
        // A static reader performs only SELECT/READ BINARY; never TNEP UPDATE BINARY.
        fun selectNdef(trace: Boolean = false): Int {
            ok(byteArrayOf(0, 0xa4.toByte(), 4, 0, 7) + NfcType4.AID + byteArrayOf(0), trace)
            ok(byteArrayOf(0, 0xa4.toByte(), 0, 0x0c, 2, 0xe1.toByte(), 3), trace)
            ok(byteArrayOf(0, 0xb0.toByte(), 0, 0, 15), trace)
            ok(byteArrayOf(0, 0xa4.toByte(), 0, 0x0c, 2, 0xe1.toByte(), 4), trace)
            val length = ok(byteArrayOf(0, 0xb0.toByte(), 0, 0, 2), trace)
            return ((length[0].toInt() and 255) shl 8) or (length[1].toInt() and 255)
        }
        fun staticRead(trace: Boolean = false): ByteArray {
            val length = selectNdef(trace)
            return ok(byteArrayOf(0, 0xb0.toByte(), 0, 2, length.toByte()), trace)
        }
    }

    private suspend fun withOffers(negotiated: Boolean, block: suspend (Offers, suspend () -> Unit) -> Unit) = coroutineScope {
        val offers = Offers(negotiated)
        val connecting = async { offers.combined.connect() }
        try {
            withTimeout(5000) { offers.qrStarted.await() }
            block(offers) { withTimeout(5000) { connecting.await() } }
        } finally {
            connecting.cancelAndJoin()
            offers.combined.close()
        }
    }

    @Test fun staticOnlyReaderOnNegotiatedHolderLeavesQrConnectable(): Unit = runBlocking {
        withOffers(true) { f, connected ->
            val message = f.staticRead(trace = true)
            assertArrayEquals(NfcTnep.parameters, message)
            assertNull(NfcTnep.payload(message, "Hs"))
            assertFalse(f.hsProduced)
            assertFalse(f.engagement.gate.isComplete)
            assertNull(f.arbiter.state.value)
            f.engagement.deactivate()
            assertFalse(f.cancelled)
            assertFalse(f.qr.closed)
            f.qrConnected.complete(Unit)
            connected()
            assertEquals(SelectedEngagement.QR, f.arbiter.state.value)
            assertEquals(0, f.nativeCreated)
            assertEquals(1, f.claims)
        }
    }

    @Test fun fieldLossBeforeFullStaticHsLeavesQrConnectable(): Unit = runBlocking {
        withOffers(false) { f, connected ->
            f.selectNdef()
            f.ok(byteArrayOf(0, 0xb0.toByte(), 0, 2, 1))
            assertFalse(f.engagement.gate.isComplete)
            f.engagement.deactivate()
            assertFalse(f.qr.closed)
            f.qrConnected.complete(Unit)
            connected()
            assertEquals(SelectedEngagement.QR, f.arbiter.state.value)
            assertEquals(0, f.nativeCreated)
        }
    }

    @Test fun fullStaticHsCommitsAndStartsNfcExactlyOnce(): Unit = runBlocking {
        withOffers(false) { f, connected ->
            assertArrayEquals(f.hs, NfcType4Reader(f::exchange, 128).read())
            connected()
            assertEquals(SelectedEngagement.NFC_BLE, f.arbiter.state.value)
            assertTrue(f.qr.closed)
            assertArrayEquals(f.hs, NfcType4Reader(f::exchange, 128).read())
            assertEquals(1, f.nativeCreated)
            assertEquals(1, f.nfc.connections)
            assertEquals(1, f.claims)
        }
    }

    @Test fun negotiatedHsCommitsOnlyAfterCompleteRead(): Unit = runBlocking {
        withOffers(true) { f, connected ->
            f.beforeHs = {
                assertNull(f.arbiter.state.value)
                assertFalse(f.qr.closed)
                assertFalse(f.engagement.gate.isComplete)
            }
            assertArrayEquals(f.hs, NfcType4Reader(f::exchange, 128).read(f.hr))
            connected()
            assertEquals(SelectedEngagement.NFC_BLE, f.arbiter.state.value)
            assertEquals(1, f.nativeCreated)
            assertEquals(1, f.nfc.connections)
        }
    }

    @Test fun qrWinWhileHrIsProcessedRejectsNfcAndSurvivesFieldLoss(): Unit = runBlocking {
        withOffers(true) { f, connected ->
            f.beforeHs = { assertTrue(f.arbiter.select(false)); f.qrConnected.complete(Unit) }
            try { NfcType4Reader(f::exchange, 128).read(f.hr); fail("losing NFC reader continued") }
            catch (_: IOException) {}
            connected()
            assertArrayEquals(nfcResponse(0x6985), f.exchange(byteArrayOf(0, 0xb0.toByte(), 0, 0, 2)))
            f.engagement.deactivate()
            assertFalse("losing NFC field loss cancelled QR", f.cancelled)
            assertFalse(f.qr.closed)
            assertEquals(SelectedEngagement.QR, f.arbiter.state.value)
            assertEquals(1, f.claims)
            assertEquals(0, f.nativeCreated)
        }
    }

    @Test fun uncommittedAttemptCanBeRetriedForBothHandoverModes(): Unit = runBlocking {
        for (negotiated in listOf(false, true)) withOffers(negotiated) { f, connected ->
            f.selectNdef()
            f.ok(byteArrayOf(0, 0xb0.toByte(), 0, 2, 1))
            f.engagement.deactivate()
            assertNull(f.arbiter.state.value)
            assertArrayEquals(f.hs, NfcType4Reader(f::exchange, 128).read(if (negotiated) f.hr else null))
            connected()
            assertEquals(SelectedEngagement.NFC_BLE, f.arbiter.state.value)
            assertEquals(1, f.nativeCreated)
        }
    }

    @Test fun frozenNegotiatedHsIsCancelledAfterIncompleteRead(): Unit = runBlocking {
        withOffers(true) { f, _ ->
            try {
                NfcType4Reader({ command ->
                    if (f.hsProduced && NfcCommand.parse(command)?.ins == 0xb0) throw IOException("field lost before Hs read")
                    f.exchange(command)
                }, 128).read(f.hr)
                fail("simulated field loss was not reached")
            } catch (_: IOException) {}
            assertTrue(f.hsProduced)
            assertFalse(f.engagement.gate.isComplete)
            assertNull(f.arbiter.state.value)
            f.engagement.deactivate()
            assertTrue(f.cancelled)
            assertFalse(f.arbiter.select(false))
        }
    }

    @Test fun nfcDataCommitsOnDataAidAfterHsNotType4Read() {
        val f = Offers(false, data = true)
        assertArrayEquals(f.hs, f.staticRead())
        assertTrue(f.engagement.gate.isComplete)
        assertNull(f.arbiter.state.value)
        val select = byteArrayOf(0, 0xa4.toByte(), 4, 0, 7) + NfcData.aid + byteArrayOf(0)
        assertArrayEquals(nfcResponse(0x9000), f.exchange(select))
        assertEquals(SelectedEngagement.NFC_DATA, f.arbiter.state.value)
        assertFalse(f.arbiter.select(false))
        f.combined.close()
    }

    private companion object {
        fun ByteArray.hex(): String = joinToString("") { "%02X".format(it.toInt() and 255) }
    }
}
