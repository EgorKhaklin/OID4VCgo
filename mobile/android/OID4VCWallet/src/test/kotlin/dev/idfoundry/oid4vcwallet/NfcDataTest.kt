package dev.idfoundry.oid4vcwallet

import org.junit.Assert.*
import org.junit.Test
import java.io.IOException
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay

class NfcDataTest {
    @Test fun do53BoundariesAndMalformedLengths() {
        for (size in listOf(0, 1, 127, 128, 255, 256, 65535, 65536, 180000)) {
            val original = ByteArray(size) { it.toByte() }
            assertArrayEquals(original, NfcData.unwrap(NfcData.wrap(original)))
        }
        for (bad in listOf(byteArrayOf(), byteArrayOf(0x53, 0x80.toByte()), byteArrayOf(0x53, 0x81.toByte(), 1, 7), byteArrayOf(0x53, 5, 1))) {
            assertThrows(IOException::class.java) { NfcData.unwrap(bad) }
        }
    }

    @Test fun largePortraitChainsAndConsentDelay() = runBlocking {
        val holder = NfcDataHolderTransport()
        val commands = mutableListOf<ByteArray>()
        val request = ByteArray(1500) { (it + 3).toByte() }
        val portrait = ByteArray(180000) { (it + 5).toByte() }
        val exchange: (ByteArray) -> ByteArray = { command ->
            synchronized(commands) { commands.add(command) }
            val pending = ArrayBlockingQueue<ByteArray>(1)
            holder.process(command) { pending.offer(it) } ?: pending.poll(5, TimeUnit.SECONDS) ?: error("no APDU response")
        }
        val reader = NfcDataReaderTransport(exchange, holder::close, 128, NfcDataParametersJSON(255, 256))
        reader.connect()
        val answer = async(Dispatchers.IO) {
            assertArrayEquals(request, holder.receive())
            delay(150) // Final ENVELOPE remains pending while consent is shown.
            holder.send(portrait)
        }
        reader.send(request)
        assertArrayEquals(portrait, reader.receive())
        answer.await()
        assertTrue(commands.any { it[0].toInt() == 0x10 })
        val getResponse = commands.filter { it[1] == 0xc0.toByte() }
        assertTrue(getResponse.size > 100)
        getResponse.forEach { assertEquals(5, it.size); assertNull(NfcCommand.parse(it)!!.data.takeIf { it.isNotEmpty() }) }
        reader.close()
    }

    @Test fun fieldLossReleasesPendingReceiveAndPartialChain() = runBlocking {
        val holder = NfcDataHolderTransport()
        holder.process(byteArrayOf(0, 0xa4.toByte(), 4, 0, 7) + NfcData.aid) {}
        holder.connect()
        val waiting = async { runCatching { holder.receive() } }
        holder.process(byteArrayOf(0x10, 0xc3.toByte(), 0, 0, 2, 0x53, 10)) {}
        holder.deactivate()
        assertTrue(waiting.await().isFailure)
        assertArrayEquals(nfcResponse(0x6985), holder.process(byteArrayOf(0, 0xc0.toByte(), 0, 0, 0)) {})
        val fresh = NfcDataHolderTransport()
        assertArrayEquals(nfcResponse(0x9000), fresh.process(byteArrayOf(0, 0xa4.toByte(), 4, 0, 7) + NfcData.aid) {})
        fresh.close()
    }
}
