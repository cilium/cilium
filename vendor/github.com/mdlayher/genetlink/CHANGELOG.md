# CHANGELOG

## v1.3.2

- [Improvement]: updated dependencies, test with Go 1.20.

# v1.3.1

- [Improvement]: bump package netlink to pull in big endian architecture fixes.

# v1.3.0

**This is the first release of package genetlink that only supports Go 1.18+.
Users on older versions of Go must use v1.2.0.**

- [Improvement]: drop support for older versions of Go so we can begin using
  modern versions of `x/sys` and other dependencies.

## v1.2.0

**This is the last release of package genetlink that supports Go 1.17 and
below.**

- [Improvement]: pruned Go module dependencies via package `netlink` v1.6.0 and
  removing tool version pins.

## v1.1.0

**This is the first release of package genetlink that only supports Go 1.12+.
Users on older versions must use v1.0.0.**

- [Improvement]: modernization of various parts of the code and documentation in
  prep for future work.

## v1.0.0

- Initial stable commit.
