# CHANGELOG

# v1.2.0

**This is the first release of package packet that only supports Go 1.26+.
Users on older versions of Go must use v1.1.2.**

- [New API]: `Conn.JoinGroup` and `Conn.LeaveGroup` can be used to join and
  leave link layer multicast group addresses on a `Conn`'s network interface,
  so traffic destined for those groups is delivered even when an interface
  filters multicast in hardware.
- [Bug Fix]: `Addr.String` no longer panics when called on a nil `*Addr`, which
  could occur while stringifying a `net.OpError` produced by this package.
- [Improvement]: drop the `github.com/josharian/native` dependency in favor of
  `encoding/binary.NativeEndian` from the standard library.
- [Improvement]: updated dependencies, test with Go 1.26 and 1.27.

# v1.1.2

- [Improvement]: updated dependencies, test with Go 1.20.

# v1.1.1

- [Bug Fix]: fix test compilation on big endian machines.

# v1.1.0

**This is the first release of package packet that only supports Go 1.18+. Users
on older versions of Go must use v1.0.0.**

- [Improvement]: drop support for older versions of Go so we can begin using
  modern versions of `x/sys` and other dependencies.

## v1.0.0

**This is the last release of package vsock that supports Go 1.17 and below.**

- Initial stable commit! The API is mostly a direct translation of the previous
  `github.com/mdlayher/raw` package APIs, with some updates to make everything
  focused explicitly on Linux and `AF_PACKET` sockets. Functionally, the two
  packages are equivalent, and `*raw.Conn` is now backed by `*packet.Conn` in
  the latest version of the `raw` package.
