package dev.idfoundry.oid4vcwallet

import org.junit.Assert.*
import org.junit.Test
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.withTimeout
import kotlin.time.Duration.Companion.milliseconds
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/** A codec whose commands are opaque: the reader transport's plumbing is under test, not APDUs (Go's). */
private object OpaqueCodec : NfcDataCodec {
    override fun selectCommand(): ByteArray = byteArrayOf(1)
    override fun checkSelected(response: ByteArray) {
        // Any response selects: the codec is opaque here.
    }
    override fun transact(maxTransceive: Int, parameters: NfcDataParametersJSON, message: ByteArray): NfcCommandSequence =
        object : NfcCommandSequence {
            private var answer: ByteArray? = null
            override fun done() = answer != null
            override fun waitMillis() = 0L
            override fun command() = message
            override fun next(response: ByteArray) { answer = response }
            override fun result() = checkNotNull(answer)
            override fun close() {
                // Nothing to release.
            }
        }
}

class NfcDataTest {
    @Test fun cancelConnectClosesTagAndInterruptsBlockingWork(): Unit = runBlocking {
        val started = CountDownLatch(1)
        val released = CountDownLatch(1)
        val finished = CountDownLatch(1)
        val closed = AtomicBoolean(false)
        val reader = NfcDataReaderTransport({
            started.countDown()
            try { released.await(); nfcResponse(0x9000) }
            finally { finished.countDown() }
        }, { closed.set(true) }, 258, NfcDataParametersJSON(255, 256), OpaqueCodec)
        val job = launch(Dispatchers.Default) { reader.connect() }
        val interrupted = try {
            assertTrue("connect did not start", started.await(5, TimeUnit.SECONDS))
            job.cancel()
            finished.await(1, TimeUnit.SECONDS)
        } finally {
            released.countDown()
            job.cancelAndJoin()
            reader.close()
        }
        assertTrue("cancellation did not close the NFC tag", closed.get())
        assertTrue("cancelled NFC work continued blocking its worker", interrupted)
    }

    @Test fun readerTransportCarriesMessages(): Unit = runBlocking {
        val reader = NfcDataReaderTransport({ it.reversedArray() }, {}, 258, NfcDataParametersJSON(255, 256), OpaqueCodec)
        reader.connect()
        reader.send(byteArrayOf(1, 2, 3))
        assertArrayEquals(byteArrayOf(3, 2, 1), withTimeout(1000) { reader.receive() })
        reader.close()
    }

    @Test fun finalResponseWaitsForConsentThenForTheReader(): Unit = runBlocking {
        val holder = ScriptedHolder()
        val transport = NfcDataHolderTransport(sendTimeout = 2000.milliseconds)
        val engagement = NfcEngagement(holder, transport, null) {}
        holder.onProcess = { NfcStep(nfcResponse(0x9000), dataSelected = true) }
        engagement.process(ScriptedHolder.command(NfcCommandKind.SELECT_DATA))
        withTimeout(1000) { transport.connect() }

        holder.onProcess = { NfcStep(null, message = byteArrayOf(7)) }
        var answered: ByteArray? = null
        assertNull("the final ENVELOPE was answered before consent", engagement.process(ScriptedHolder.command()) { answered = it })
        assertArrayEquals(byteArrayOf(7), withTimeout(1000) { transport.receive() })

        holder.onRespond = { NfcStep(byteArrayOf(9, 0x61, 0)) } // more to come
        val sending = async(Dispatchers.IO) { transport.send(byteArrayOf(8)) }
        delay(100)
        assertArrayEquals(byteArrayOf(9, 0x61, 0), answered)
        assertFalse("send returned before the reader read the whole response", sending.isCompleted)
        holder.onProcess = { NfcStep(nfcResponse(0x9000), delivered = true) }
        engagement.process(ScriptedHolder.command())
        withTimeout(1000) { sending.await() }
    }

    @Test fun aMessageTheSessionCannotTakeIsRefused(): Unit = runBlocking {
        val holder = ScriptedHolder()
        val engagement = NfcEngagement(holder, NfcDataHolderTransport(), null) {}
        holder.onProcess = { NfcStep(null, message = byteArrayOf(7)) }
        assertNull(engagement.process(ScriptedHolder.command()))
        // The channel holds one message; a second before the first is read is refused.
        assertArrayEquals(nfcResponse(0x6985), engagement.process(ScriptedHolder.command()))
        assertEquals(1, holder.refused)
    }

    @Test fun fieldLossReleasesPendingReceive(): Unit = runBlocking {
        val holder = ScriptedHolder()
        val transport = NfcDataHolderTransport()
        val engagement = NfcEngagement(holder, transport, null) {}
        val waiting = async { runCatching { transport.receive() } }
        holder.deactivation = NfcDeactivation(cancel = false, dataClosed = true)
        engagement.deactivate()
        assertTrue(withTimeout(1000) { waiting.await() }.isFailure)
        assertFalse("field loss closed the Go holder, which ends itself", holder.closed)
        transport.close()
    }

    @Test fun closingTheTransportClosesTheHolder() {
        val holder = ScriptedHolder()
        val transport = NfcDataHolderTransport()
        NfcEngagement(holder, transport, null) {}
        transport.close()
        assertTrue(holder.closed)
    }
}
