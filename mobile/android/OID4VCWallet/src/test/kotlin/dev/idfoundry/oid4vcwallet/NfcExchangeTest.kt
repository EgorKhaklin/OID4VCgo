package dev.idfoundry.oid4vcwallet

import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.*
import org.junit.Test

class NfcExchangeTest {
    @Test fun successfulHandoverRetainsTagForDataSelection(): Unit = runBlocking {
        val closed = AtomicBoolean(false)
        val handover = NfcTnep.record("Hs", byteArrayOf(1, 2, 3))
        val tag = NfcType4(handover) {}
        assertArrayEquals(handover, runNfcExchange({ closed.set(true) }) {
            NfcType4Reader(tag::process, 258).read()
        })
        val data = NfcDataReaderTransport({
            assertFalse("handover closed the tag before data selection", closed.get())
            nfcResponse(0x9000)
        }, { closed.set(true) }, 258, NfcDataParametersJSON(255, 256))
        data.connect()
        assertFalse(closed.get())
        data.close()
        assertTrue(closed.get())
    }

    @Test fun cancellationInterruptsNegotiatedHandoverWait(): Unit = runBlocking {
        val parameters = NfcTnep.payload(NfcTnep.parameters, "Tp")!!
        parameters[parameters.size - 4] = 63 // A valid TNEP wait of about 27 seconds.
        val selected = CountDownLatch(1)
        val finished = CountDownLatch(1)
        val closed = AtomicBoolean(false)
        val thread = AtomicReference<Thread>()
        val tag = NfcType4(NfcTnep.record("Tp", parameters), {
            selected.countDown()
            NfcTnep.success
        }) {}
        val job = launch(Dispatchers.Default) {
            runNfcExchange({ closed.set(true) }) {
                thread.set(Thread.currentThread())
                try { NfcType4Reader(tag::process, 258).read(byteArrayOf(1)) }
                finally { finished.countDown() }
            }
        }
        var stopped = false
        try {
            assertTrue("TNEP selection did not start", selected.await(5, TimeUnit.SECONDS))
            job.cancel()
            stopped = finished.await(1, TimeUnit.SECONDS)
        } finally {
            // Prevent a failed cancellation regression from leaving a sleeping test worker.
            if (!stopped) thread.get()?.interrupt()
            job.cancelAndJoin()
        }
        assertTrue("cancelled TNEP reader continued sleeping", stopped)
        assertTrue(closed.get())
    }

    @Test fun timeoutClosesNativeHandleAndWaitsForWorker(): Unit = runBlocking {
        val closed = AtomicBoolean(false)
        val finished = CountDownLatch(1)
        val nativeWait = CountDownLatch(1)
        var timedOut = false
        try {
            withTimeout(2000) {
                runNfcExchange({ closed.set(true); nativeWait.countDown() }) {
                    try { nativeWait.await() } finally { finished.countDown() }
                }
            }
        } catch (_: TimeoutCancellationException) { timedOut = true }
        assertTrue(timedOut)
        assertTrue(closed.get())
        assertEquals("timeout returned before NFC worker exited", 0L, finished.count)
    }
}
