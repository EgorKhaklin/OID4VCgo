// Package nfcapdu implements the byte-level NFC protocols ISO/IEC
// 18013-5:2021 uses for NFC engagement (§8.2.2.1, §8.2.2.2) and NFC
// data retrieval (§8.3.3.1.2): ISO/IEC 7816-4 command APDUs, the NFC
// Forum Type 4 Tag NDEF application, TNEP negotiated handover, and the
// DO53 ENVELOPE / GET RESPONSE chaining that carries session messages.
//
// It performs no I/O. The native app keeps the radio: on the mdoc
// (holder) side its host card emulation service hands each command APDU
// to Holder.Process and sends back the response; on the reader side it
// sends each command an Exchange yields over its tag connection and
// passes the response to Exchange.Next. Waits TNEP asks for are returned
// to the caller (Exchange.Wait) rather than slept here, so the native
// app can cancel them.
//
// The handover messages themselves (Handover Select and Request) are
// built and parsed by package proximity; this package only carries
// them.
package nfcapdu
