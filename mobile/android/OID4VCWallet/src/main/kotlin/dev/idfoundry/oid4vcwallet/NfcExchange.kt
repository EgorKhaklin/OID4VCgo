package dev.idfoundry.oid4vcwallet

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.runInterruptible
import kotlinx.coroutines.suspendCancellableCoroutine

/** Interrupt JVM waits and close the native tag on cancellation; retain it on success. */
internal suspend fun <T> runNfcExchange(closeTag: () -> Unit, block: () -> T): T = coroutineScope {
    suspendCancellableCoroutine { continuation ->
        val worker = launch(Dispatchers.IO) {
            val result = runCatching { runInterruptible { block() } }
            // A connect racing cancellation may have opened the tag after the first close.
            if (!isActive) runCatching(closeTag)
            continuation.resumeWith(result)
        }
        continuation.invokeOnCancellation {
            runCatching(closeTag)
            worker.cancel()
        }
    }
}
