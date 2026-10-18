package dev.idfoundry.oid4vcwallet

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/** Shared serialization for application owners, independent of HCE instances. */
internal class PresentationOwners<T : Any>(private val close: suspend (T) -> Unit) {
    private val replacing = Mutex()
    @Volatile private var active: T? = null

    suspend fun replace(create: () -> T): T = replacing.withLock {
        active?.let { close(it); clear(it) }
        create().also { active = it }
    }
    @Synchronized fun clear(owner: T) { if (active === owner) active = null }
    fun owner(): T? = active
}
