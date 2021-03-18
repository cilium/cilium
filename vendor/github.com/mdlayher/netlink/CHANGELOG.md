# CHANGELOG

## Unreleased

- n/a

## v1.1.0

- [New API] [#157](https://github.com/mdlayher/netlink/pull/157): the
  `netlink.AttributeDecoder.TypeFlags` method enables retrieval of the type bits
  stored in a netlink attribute's type field, because the existing `Type` method
  masks away these bits. Thanks @ti-mo!
- [Performance] [#157](https://github.com/mdlayher/netlink/pull/157): `netlink.AttributeDecoder`
  now decodes netlink attributes on demand, enabling callers who only need a
  limited number of attributes to exit early from decoding loops. Thanks @ti-mo!
- [Improvement] [#161](https://github.com/mdlayher/netlink/pull/161): `netlink.Conn`
  system calls are now ready for Go 1.14+'s changes to goroutine preemption.
  See the PR for details.

## v1.0.0

- Initial stable commit.
