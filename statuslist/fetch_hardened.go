package statuslist

// HardenedForProduction reports whether f keeps its full address
// policy: none of AllowLoopback, AllowPrivate, AllowProxy and
// UncheckedTransport is set, each of which lets a Referenced Token's
// status_list uri reach, or leaves it to something else to keep it
// from, the Verifier's own network. A Verifier running under
// production assurance should check its status Fetcher with it: the
// verifier package can't, since its status check (an Accept function)
// is opaque to it.
func (f Fetcher) HardenedForProduction() bool {
	return !f.AllowLoopback && !f.AllowPrivate && !f.AllowProxy && !f.UncheckedTransport
}
