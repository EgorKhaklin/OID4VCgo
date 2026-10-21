package dev.idfoundry.oid4vcwallet

import kotlinx.coroutines.async
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Test

class NfcHandoverGateTest {
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
