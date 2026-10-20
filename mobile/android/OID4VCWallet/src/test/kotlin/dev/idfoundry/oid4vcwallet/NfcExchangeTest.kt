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
    /** A sequence of [commands], each awaiting one response, after [waitMillis] each. */
    private class Sequence(private val commands: List<ByteArray>, private val waitMillis: Long = 0) : NfcCommandSequence {
        private var index = 0
        var closed = false
        override fun done() = index == commands.size
        override fun waitMillis() = waitMillis
        override fun command() = commands[index]
        override fun next(response: ByteArray) { index++ }
        override fun result() = byteArrayOf(9)
        override fun close() { closed = true }
    }

    @Test fun successfulExchangeRetainsTheTag(): Unit = runBlocking {
        val closed = AtomicBoolean(false)
        val sequence = Sequence(listOf(byteArrayOf(1), byteArrayOf(2)))
        assertArrayEquals(byteArrayOf(9), runNfcExchange({ closed.set(true) }) { sequence.drive { nfcResponse(0x9000) } })
        assertFalse("a successful handover closed the tag before data selection", closed.get())
        assertTrue("the Go exchange was left open", sequence.closed)
    }

    @Test fun cancellationInterruptsTheTnepWait(): Unit = runBlocking {
        val waiting = CountDownLatch(1)
        val finished = CountDownLatch(1)
        val closed = AtomicBoolean(false)
        val thread = AtomicReference<Thread>()
        // TNEP's longest wait (WT 63) is about 27 seconds.
        val sequence = object : NfcCommandSequence {
            override fun done() = false
            override fun waitMillis(): Long { waiting.countDown(); return 27_000 }
            override fun command() = byteArrayOf(1)
            override fun next(response: ByteArray) {
                // The wait is cancelled before any response.
            }
            override fun result() = byteArrayOf()
            override fun close() {
                // Nothing to release.
            }
        }
        val job = launch(Dispatchers.Default) {
            runNfcExchange({ closed.set(true) }) {
                thread.set(Thread.currentThread())
                try { sequence.drive { nfcResponse(0x9000) } }
                finally { finished.countDown() }
            }
        }
        var stopped = false
        try {
            assertTrue("the TNEP wait did not start", waiting.await(5, TimeUnit.SECONDS))
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

    @Test fun aFailedExchangeClosesTheSequence() {
        val sequence = Sequence(listOf(byteArrayOf(1)))
        assertThrows(java.io.IOException::class.java) { sequence.drive { throw java.io.IOException("field lost") } }
        assertTrue(sequence.closed)
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
