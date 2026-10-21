#!/bin/sh
# Writes a mobile library release's "What's new" as Markdown: the feat,
# fix and perf commits, breaking ones first, between the commit the
# previous release was built from and this one, that touched what the
# library ships. That's the Go code gomobile compiles into it (the
# OID4VCgo packages mobile/ imports, as go list sees them at this
# commit, tests aside), go.mod and go.sum, the
# platform library's own sources, and its build script, whose flags
# shape the binary: mobile/android/OID4VCWallet and build-aar.sh, or
# mobile/ios/OID4VCWallet and build-xcframework.sh. Demo apps and
# docs-only commits aren't listed. Oldest first.
#
#   mobile/release-notes.sh <previous-commit> <this-commit> android|ios
#
# The commits are Conventional Commits (CONTRIBUTING.md), so their
# headers are fit to list. A header repeated, as release-please's
# multiple-changes form repeats one, is listed once, at its first commit.
set -eu
[ $# -eq 3 ] || { echo "usage: $0 <previous-commit> <this-commit> android|ios" >&2; exit 2; }
PREV=$1 THIS=$2
case $3 in
android) LIB=mobile/android/OID4VCWallet BUILD=mobile/build-aar.sh ;;
ios) LIB=mobile/ios/OID4VCWallet BUILD=mobile/build-xcframework.sh ;;
*) echo "the platform is android or ios, not $3" >&2; exit 2 ;;
esac
cd "$(git rev-parse --show-toplevel)"
git cat-file -e "$PREV^{commit}" 2>/dev/null || { echo "no commit $PREV: fetch the full history" >&2; exit 1; }

# Each OID4VCgo package the library compiles, as a pathspec for its own
# Go files: github.com/idfoundry/oid4vcgo/internal/jose is internal/jose/*.go.
PACKAGES=$(cd mobile && go list -deps . | sed -n 's|^github\.com/idfoundry/oid4vcgo||p' |
	sed 's|^/||; s|^\(..*\)$|\1/|; s|^\(.*\)$|:(glob)\1*.go|')
[ -n "$PACKAGES" ] || { echo "go list found no OID4VCgo packages in mobile/" >&2; exit 1; }

# Short hash, then "B" for a breaking change ("!" or a BREAKING CHANGE
# footer) or "-", then the header.
# Both libraries compile the same Go code, so one's features show in the
# other's list too: say so where they can't be reached.
if [ "$3" = ios ]; then
	echo "Changes to the Go code both libraries share are listed too. Features named for Android, such as NFC engagement, aren't in this package."
	echo
fi

# shellcheck disable=SC2086 # PACKAGES is one pathspec per word.
git log --reverse --no-merges --format='%h%x09%(trailers:key=BREAKING CHANGE,valueonly,separator=%x20)%x09%s' "$PREV..$THIS" -- \
	$PACKAGES go.mod go.sum mobile/go.mod mobile/go.sum "$LIB" "$BUILD" ':!*_test.go' |
	awk -F '\t' '
	$3 !~ /^(feat|fix|perf)(\([^)]*\))?!?: / { next }
	seen[$3]++ { next }
	{
		breaking = ($2 != "" || $3 ~ /^[a-z]+(\([^)]*\))?!: /)
		line = "- " $3 " (" $1 ")"
		if (breaking) b[nb++] = line; else if ($3 ~ /^feat/) f[nf++] = line; else x[nx++] = line
	}
	END {
		if (nb + nf + nx == 0) { print "No changes to the library since the previous release."; exit }
		if (nb) { print "### Breaking changes\n"; for (i = 0; i < nb; i++) print b[i]; print "" }
		if (nf) { print "### Features\n"; for (i = 0; i < nf; i++) print f[i]; print "" }
		if (nx) { print "### Fixes\n"; for (i = 0; i < nx; i++) print x[i]; print "" }
	}'
