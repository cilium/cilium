# CHANGELOG

# v1.1.0

- [Improvement]: updated dependencies, test with Go 1.22.
- [New API] [PR](https://github.com/mdlayher/ndp/pull/31): `ndp.PREF64`
  implements the PREF64 option as defined in RFC 8781. Thanks @jmbaur for the
  contribution.

# v1.0.1

- [Improvement]: updated dependencies, test with Go 1.20.
- [Improvement]: switch from `math/rand` to `crypto/rand` for Nonce generation.

## v1.0.0

First stable release, no API changes since v0.10.0.

## v0.10.0

- [API Change]
  [commit](https://github.com/mdlayher/ndp/commit/0e153112a3ae254e05f4e55afdb684da0712d5c9):
  `ndp.CaptivePortal` and `ndp.MTU` are now structs to allow for better
  extensibility. `ndp.NewCaptivePortal` now does argument validation and returns
  an error for various cases. `ndp.Unrestricted` is available to specify "no
  captive portal".
- [New API]
  [commit](https://github.com/mdlayher/ndp/commit/7d558c930180892ed63e3213bb45bc62c71b6fa5):
  `ndp.Nonce` implements the NDP Nonce option as described in RFC 3971. Though
  this library does not implement Secure Neighbor Discovery (SEND) as of today,
  this option can also be used for Enhanced Duplicate Address Detection (DAD).

## v0.9.0

**This is the first release of package `ndp` that only supports Go 1.18+ due to
the use of `net/netip`. Users on older versions of Go must use v0.8.0.**

- [Improvement]: cut over from `net.IP` to `netip.Addr` throughout
- [API Change]: drop `ndp.TestConns`; this API was awkward and didn't test
  actual ICMPv6 functionality. Users are encouraged to either run privileged
  ICMPv6 tests or to swap out `*ndp.Conn` via an interface.
- [Improvement]: drop a lot of awkward test functionality related to
  unprivileged UDP connections to mock out ICMPv6 connections

## v0.8.0

First release of package `ndp` based on the APIs that have been stable for years
with `net.IP`.

**This is the first and last release of package `ndp` which supports Go 1.17 or
older. Future versions will require Go 1.18 and `net/netip`.**
