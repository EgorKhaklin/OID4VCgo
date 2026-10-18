package dev.idfoundry.oid4vcwallet

import android.util.Log

/** Opt-in transport lifecycle diagnostics. Disabled by default; no credential or APDU payloads. */
public object ProximityDiagnostics {
    /** Enable debug events under the Android log tag `OID4VCProximity` while troubleshooting. */
    @Volatile public var enabled: Boolean = false

    internal fun event(message: String) {
        if (enabled) Log.d("OID4VCProximity", message)
    }
}
