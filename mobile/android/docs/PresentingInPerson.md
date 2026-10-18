# Presenting in person

Share an mdoc with a reader nearby over Bluetooth, or be the reader,
with ISO/IEC 18013-5 device retrieval.

In person, the holder shows a QR code and the reader scans it: the code
carries the holder's ephemeral key and how to reach it over Bluetooth
LE. The two devices then exchange encrypted messages over GATT. The
library carries the Bluetooth side itself: your app shows or scans the
QR code, follows the session's states, and asks the holder.

The library's manifest adds the Bluetooth permissions to your app's:
on Android 11 and earlier `BLUETOOTH`, `BLUETOOTH_ADMIN` and
`ACCESS_FINE_LOCATION`, which a reader needs for scan results; from
Android 12 `BLUETOOTH_ADVERTISE`, `BLUETOOTH_CONNECT` and
`BLUETOOTH_SCAN` (with `neverForLocation`). Request
`ProximityPermissions.holder` or `ProximityPermissions.reader` at runtime
before starting a session: without them, starting one throws a
`ProximityException` (`PermissionMissing`).

Keep the app in the foreground during a session: neither side keeps
one going while the app is in the background. A session answers one
request. Bluetooth failures are `ProximityException`s; protocol failures
are `WalletException`s. The emulator has no Bluetooth: use devices.

## Share as the holder

`Wallet.startProximityPresentation` returns a `ProximityPresentation`
whose `qrCode` you show. It offers both `ProximityBLEMode`s by default:
it advertises for the reader and scans for it at once, until a reader
connects either way (a reader offered both should connect in central
client mode). Pass `modes` to offer one, and request
`ProximityPermissions.holder(modes)` for them. Scanning makes the
default ask the holder for more than peripheral server mode alone:
`BLUETOOTH_SCAN` from Android 12, and location on Android 11 and
earlier, where Android delivers scan results only with it. An app that
would rather not ask can offer `setOf(ProximityBLEMode.PERIPHERAL_SERVER)`,
which needs neither. Then its `state` becomes
`RequestReceived`, with who is asking and what: ask the
holder, then respond or decline.

```kotlin
import android.content.Context
import dev.idfoundry.oid4vcwallet.MdocPresentation
import dev.idfoundry.oid4vcwallet.ProximityPresentation
import dev.idfoundry.oid4vcwallet.ProximityReader
import dev.idfoundry.oid4vcwallet.ProximityReaderConfiguration
import dev.idfoundry.oid4vcwallet.ProximityReaderSession
import dev.idfoundry.oid4vcwallet.VerifiedMdoc
import dev.idfoundry.oid4vcwallet.Wallet
import kotlinx.coroutines.flow.first

/** What the holder agreed to share: a requested document, the held mdoc to answer it with, and the elements to disclose. */
data class InPersonAnswer(val document: Int, val credentialID: String, val elements: List<MdocPresentation.Element>)

/**
 * Shares an mdoc in person. `showQRCode` displays the code; `consent`
 * shows the reader's request and returns the holder's answer, or null to
 * decline. Returns whether the copy shared had been seen by another
 * Verifier, or null when nothing was shared.
 */
suspend fun shareInPerson(
    context: Context,
    wallet: Wallet,
    showQRCode: (String) -> Unit,
    consent: suspend (ProximityPresentation.Request) -> InPersonAnswer?,
): Boolean? {
    val session = wallet.startProximityPresentation(context)
    showQRCode(session.qrCode)
    val state = session.state.first { it is ProximityPresentation.State.RequestReceived || it.isFinal }
    if (state is ProximityPresentation.State.Failed) throw state.error
    if (state !is ProximityPresentation.State.RequestReceived) return null
    val answer = consent(state.request)
    if (answer == null) {
        session.decline()
        return null
    }
    // The holder key signs now: the fingerprint or screen lock, if the key store asks.
    return session.respond(answer.document, answer.credentialID, answer.elements)
}
```

Show the request's `reader` on the consent screen. A reader that signs
its request (reader authentication) is named, and `Trusted` when its
certificate chains to `WalletConfiguration.mdocReaderRoots`. An
unsigned request could come from anyone who scanned the code.
`WalletConfiguration.requireTrustedMdocReader` ends a session from any
other reader before the holder sees it.

`cancel()` ends a session at any point, as the holder leaves the screen,
say. `ProximityTimeouts` sets how long it waits: by default 60 seconds
for a reader to connect, 30 for its request, and 300 for the holder to
decide.

## Read as the verifier

A `ProximityReader` needs no `Wallet`: give it the IACAs whose mdocs it
accepts, and, to sign its requests so holders see who is asking, a key
in a `KeyStore` and its certificate chain, with the reader
authentication extended key usage (`ProximityReaderConfiguration`).
`start` takes the holder's QR code and what to ask for.

```kotlin
/** Reads an mDL's name and portrait from the holder whose QR code was scanned. Returns the verified mdoc, or null if the holder declined. */
suspend fun readInPerson(context: Context, qrCode: String, issuerRoots: String): VerifiedMdoc? {
    val reader = ProximityReader(ProximityReaderConfiguration(issuerRoots = issuerRoots))
    val session = reader.start(
        context, qrCode, "org.iso.18013.5.1.mDL",
        mapOf("org.iso.18013.5.1" to listOf("given_name", "family_name", "portrait")),
    )
    return when (val state = session.state.first { it.isFinal }) {
        is ProximityReaderSession.State.Verified -> state.result
        is ProximityReaderSession.State.Failed -> throw state.error
        else -> null
    }
}
```

`VerifiedMdoc` carries the disclosed elements, the document signer and
the IACA it chains to, and its validity. Its status list reference is
unchecked: check it before relying on the document.

## NFC holder and reader

The NFC additions include static and negotiated handover for BLE and
classic NFC-only retrieval. They require physical interoperability and
normative specification review before a conformance claim. iOS NFC,
USB readers, L2CAP and Concurrent Channel Engagement are outside this work.

Declare an application subclass, for example `class IdentityNfcService :
NfcEngagementService()`, and its HCE service:

```xml
<service android:name=".IdentityNfcService" android:exported="true"
    android:permission="android.permission.BIND_NFC_SERVICE">
    <intent-filter>
        <action android:name="android.nfc.cardemulation.action.HOST_APDU_SERVICE" />
    </intent-filter>
    <meta-data android:name="android.nfc.cardemulation.host_apdu_service"
        android:resource="@xml/oid4vc_nfc_aids" />
</service>
```

The library declares optional NFC/HCE hardware and the NFC permission.
Its AID resource uses category `other` and requires device unlock. Retain
one `NfcPresentation` at application/view-model level. Start it with:

```kotlin
val owner = wallet.startNfcPresentation(context, modes = modes)
// For negotiated NFC-to-BLE, pass negotiated = true.
// For static NFC-only retrieval, pass nfcData = true.
// For negotiated NFC-only, pass both nfcData = true and negotiated = true.
val session = owner.presentation
```

Follow `session.state` and use the existing `respond`/`decline` consent
flow. On a resumed Activity, call
`owner.preferForeground(activity, IdentityNfcService::class.java)` and
check its Boolean result. Call `releaseForeground(activity)` on pause
and completion, and acquire preference again on every resume. The
platform can refuse preference; the application should explain how
to select its NFC service. Reapply it to each new presentation.

`owner.close()` cancels and awaits cleanup. Starting another NFC owner
waits for the previous owner's tasks and radio resources to close.
Use `startCombinedPresentation` below to offer QR and NFC together;
do not combine two independent owners. HCE service
recreation reuses the owner. A process restart leaves it unarmed.
Repeated reads reuse the key/UUID/Hs and trigger BLE only once the whole
Hs has been read. NFC removal after BLE handover leaves BLE running.
Field loss during NFC-only retrieval ends that session; start a new one
to recover. NFC-only mode does not require Bluetooth permissions.

On the verifier, enable Android reader mode with NFC-A/NFC-B and
`FLAG_READER_SKIP_NDEF_CHECK`, then invoke from a coroutine:

```kotlin
val session = reader.startFromNfc(context, tag, docType, elements)
```

The reader detects static versus negotiated handover and the selected
carrier. BLE retrieval needs `ProximityPermissions.reader` granted.
For NFC-only, keep the phones together through consent and response;
`session.usesNfcData` identifies this path. The BLE `mode` property has
meaning only when `usesNfcData` is false. Disable reader mode on pause
or after leaving the reader screen. Cancellation closes IsoDep and interrupts
blocking transceives and negotiated-handover waits; the coroutine waits for
its worker to exit. A successful handover keeps the tag open for NFC data
selection. Removing the tag after BLE selection is safe.

Android Type 4 supports read-only static Hs and staged TNEP writes,
with a 32767-byte NDEF file limit and chunked NDEF records rejected.
Classic NFC-only uses short APDUs, ENVELOPE command chaining, DO53,
and GET RESPONSE with a Le-only command. It supports a 2 MiB complete
message; the controller's smaller transceive limit is applied as well.
The final ENVELOPE remains asynchronous during consent, so hardware
timeout/WTX behavior must be included in real-device validation.

The demo's presentation settings select QR, static NFC-to-BLE,
negotiated NFC-to-BLE, or NFC-only. Reader presets offer NFC/Bluetooth
and NFC-only actions; the latter does not request Bluetooth permissions.

## Combined QR and NFC engagement

Use one owner for a screen that displays a QR code and accepts an NFC tap:

```kotlin
val owner = wallet.startCombinedPresentation(
    context,
    nfc = NfcEngagementOptions(negotiated = false, nfcData = false),
)
showQr(owner.qrCode) // Empty when NFC-only is available but BLE permission is absent.
// Collect owner.state, the same ProximityPresentation.State used by QR sessions.
// On RequestReceived, use owner.respond(document, credentialID, elements)
// or owner.decline(). owner.selectedEngagement records QR, NFC_BLE or NFC_DATA.
```

Hide the QR once `selectedEngagement` becomes non-null; it cannot accept another
reader after either offer has won.

Retain the owner at application/presentation scope across HCE recreation. Create
it once on entering the screen, after checking NFC availability. Reuse the
declared `NfcEngagementService` and `@xml/oid4vc_nfc_aids` manifest entry above.
The exact activity/screen calls, while that owner exists, are:

```kotlin
// Activity.onResume(), and immediately after creating an owner while resumed:
val preferred = owner.preferForeground(activity, IdentityNfcService::class.java)
if (!preferred) showNfcServiceSelectionInstructions()

// Activity.onPause():
owner.releaseForeground(activity)

// Screen exit or terminal state, from a retained coroutine that survives navigation:
owner.releaseForeground(activity)
owner.cancel() // Withdraw immediately, even if cleanup has to suspend.
owner.close()  // Await tasks and radio cleanup before dropping/replacing the owner.
```

Do not create another owner on each resume or use a coroutine cancelled by the
screen exit to await cleanup. If creation finishes after pause, retain it and
defer foreground preference until resume. A refused foreground preference is a
Boolean result, not proof that NFC routing is available; offer service-selection
instructions and the QR alternative if present. Do not force a different wallet's
routing. Pausing releases preference; explicitly close on screen exit.

QR BLE advertising/scanning starts immediately. A completed QR BLE connection
(the State-start handshake) or an accepted Type 4 NFC application SELECT claims
the presentation. The losing offer can never attach or be revived by field loss.
After QR wins, further NFC APDUs return `6985`. After NFC wins, QR tasks stop and
their BLE resources close before any NFC BLE transport is created. NFC BLE still
waits until the complete Hs has been read. There are never two offer advertisers
running together. For NFC data, keep the devices together through consent.

The offers have independent ephemeral keys, DeviceEngagements and service UUIDs.
QR uses a null Handover; NFC uses exactly `[Hs, null]` (static) or `[Hs, Hr]`
(negotiated). Selection switches the Go session before processing any request;
consent and response remain one state machine. This avoids assuming permission
to reuse one EDeviceKey across engagement mechanisms. Existing Annex D vectors
cover transcript construction; they do not establish that key reuse is permitted.

With `nfcData = true`, missing Bluetooth runtime permissions omit the QR offer
(`qrCode == ""`) and no Bluetooth transport is constructed. NFC remains armed.
A QR transport startup failure also leaves the NFC offer available until the
connection timeout. NFC-to-BLE requires Bluetooth permissions as before.

The additive method keeps the JVM descriptors and default-argument bridges of
the existing QR and NFC APIs unchanged. `CombinedPresentation` delegates the
existing state/consent flow and uses the same serialized NFC owner registry.
