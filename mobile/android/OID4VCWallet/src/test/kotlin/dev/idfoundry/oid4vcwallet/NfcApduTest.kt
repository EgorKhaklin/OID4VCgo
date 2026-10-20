package dev.idfoundry.oid4vcwallet

import org.junit.Assert.*
import org.junit.Test
import java.io.IOException
import kotlinx.coroutines.async
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.runCurrent

class NfcApduTest {
    private fun fixture(size: Int): ByteArray = byteArrayOf(0xc1.toByte(), 2, 0, 0, (size ushr 8).toByte(), size.toByte(), 'H'.code.toByte(), 's'.code.toByte()) + ByteArray(size) { it.toByte() }

    @Test fun staticReadsAreStableAndStartOnlyOnce() {
        val message = fixture(600)
        val original = message.copyOf()
        var completions = 0
        val holder = NfcType4(message) { completions++ }
        val reader = NfcType4Reader(holder::process, 261)
        assertArrayEquals(message, reader.read())
        assertEquals(1, completions)
        holder.deactivate()
        assertArrayEquals(message, reader.read())
        assertEquals(1, completions)
        message.fill(0) // Construction copied the caller's mutable buffer.
        assertArrayEquals(original, reader.read())
    }

    @Test fun partialReadDoesNotCompleteHandover() {
        var completions = 0
        val holder = NfcType4(ByteArray(300)) { completions++ }
        holder.process(byteArrayOf(0, 0xa4.toByte(), 4, 0, 7) + NfcType4.AID)
        holder.process(byteArrayOf(0, 0xa4.toByte(), 0, 0x0c, 2, 0xe1.toByte(), 4))
        repeat(10) { holder.process(byteArrayOf(0, 0xb0.toByte(), 0, 2, 50)) }
        assertEquals(0, completions)
        holder.deactivate()
        assertArrayEquals(nfcResponse(0x6985), holder.process(byteArrayOf(0, 0xb0.toByte(), 0, 0, 2)))
    }

    @Test fun malformedCommandsNeverEscapeAsExceptions() {
        val holder = NfcType4(byteArrayOf(1)) {}
        val random = java.util.Random(917)
        repeat(20000) {
            val bytes = ByteArray(random.nextInt(600)).also(random::nextBytes)
            assertTrue(holder.process(bytes).size >= 2)
        }
        assertNull(NfcCommand.parse(byteArrayOf(0, 0xc3.toByte(), 0, 0, 4, 1)))
        assertEquals(256, NfcCommand.parse(byteArrayOf(0, 0xc0.toByte(), 0, 0, 0))!!.le)
        assertEquals(65536, NfcCommand.parse(byteArrayOf(0, 0xc0.toByte(), 0, 0, 0, 0, 0))!!.le)
        assertArrayEquals(byteArrayOf(4, 5), NfcCommand.parse(byteArrayOf(0, 0xc3.toByte(), 0, 0, 0, 0, 2, 4, 5, 0, 0))!!.data)
    }

    @Test fun readerRejectsShortAndFailedResponses() {
        for (response in listOf(byteArrayOf(), nfcResponse(0x6a82), nfcResponse(0x9000))) {
            assertThrows(IOException::class.java) { NfcType4Reader({ response }, 261).read() }
        }
    }

    @Test fun fragmentedNegotiationAndDeselection() {
        val request = fixture(550)
        val response = ByteArray(400) { (it + 2).toByte() }
        var selections = 0
        var complete = 0
        val tnep = NfcTnepHolder {
            assertArrayEquals(request, it)
            selections++
            response
        }
        val holder = NfcType4(NfcTnep.parameters, tnep::transact) { if (tnep.handoverReady) complete++ }
        val reader = NfcType4Reader(holder::process, 128)
        assertArrayEquals(response, reader.read(request))
        assertTrue(reader.negotiated)
        assertEquals(1, selections)
        assertEquals(1, complete)
        assertArrayEquals(NfcTnep.success, tnep.transact(NfcTnep.success))
        assertArrayEquals(NfcTnep.parameters, tnep.transact(NfcTnep.deselect))
        assertThrows(IllegalStateException::class.java) { tnep.transact(request) }
    }

    @Test fun incompleteNdefWritesNeverCommit() {
        var commits = 0
        val holder = NfcType4(NfcTnep.parameters, { commits++; it }) {}
        holder.process(byteArrayOf(0, 0xa4.toByte(), 4, 0, 7) + NfcType4.AID)
        holder.process(byteArrayOf(0, 0xa4.toByte(), 0, 0x0c, 2, 0xe1.toByte(), 4))
        fun write(offset: Int, bytes: ByteArray) = holder.process(byteArrayOf(0, 0xd6.toByte(), (offset ushr 8).toByte(), offset.toByte(), bytes.size.toByte()) + bytes)
        assertArrayEquals(nfcResponse(0x9000), write(0, byteArrayOf(0, 0)))
        write(2, byteArrayOf(1, 2))
        assertArrayEquals(nfcResponse(0x6985), write(0, byteArrayOf(0, 3)))
        assertEquals(0, commits)
        holder.deactivate()
        assertArrayEquals(nfcResponse(0x6985), write(0, byteArrayOf(0, 2)))
        assertEquals(0, commits)
    }

    @Test fun tnepSupportsMultipleServicesAndNormalControlRecords() {
        val other = NfcTnep.record("Tp", byteArrayOf(0x10,1,'x'.code.toByte(),0,16,15,1,0)).also { it[0] = 0x91.toByte() }
        val handover = NfcTnep.parameters.also { it[0] = 0x51 }
        assertEquals(Triple(16, 15, 32765), NfcTnep.serviceParameters(other + handover))
        val selected = NfcTnep.payload(NfcTnep.select,"Ts")!!
        val normal = byteArrayOf(0xc1.toByte(),2,0,0,0,selected.size.toByte(),'T'.code.toByte(),'s'.code.toByte()) + selected
        val holder = NfcTnepHolder { fixture(1) }
        assertArrayEquals(NfcTnep.success, holder.transact(normal))
    }

    @Test fun cancelledGateNeverConstructsNativeResources() = runTest {
        var created = 0
        val gate = NfcHandoverGate()
        val transport = gate.transport { created++; error("must not construct") }
        val pending = async { runCatching { transport.connect() } }
        runCurrent()
        assertEquals(0, created)
        transport.close()
        gate.complete()
        pending.await()
        assertEquals(0, created)
    }
}
