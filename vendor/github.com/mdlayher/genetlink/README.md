# genetlink [![Test Status](https://github.com/mdlayher/genetlink/workflows/Linux%20Test/badge.svg)](https://github.com/mdlayher/genetlink/actions) [![Go Reference](https://pkg.go.dev/badge/github.com/mdlayher/genetlink.svg)](https://pkg.go.dev/github.com/mdlayher/genetlink)  [![Go Report Card](https://goreportcard.com/badge/github.com/mdlayher/genetlink)](https://goreportcard.com/report/github.com/mdlayher/genetlink)

Package `genetlink` implements generic netlink interactions and data types.
MIT Licensed.

For more information about how netlink and generic netlink work,
check out my blog series on [Linux, Netlink, and Go](https://mdlayher.com/blog/linux-netlink-and-go-part-1-netlink/).

If you have any questions or you'd like some guidance, please join us on
[Gophers Slack](https://invite.slack.golangbridge.org) in the `#networking`
channel!

## Stability

See the [CHANGELOG](./CHANGELOG.md) file for a description of changes between
releases.

This package has a stable v1 API and any future breaking changes will prompt
the release of a new major version. Features and bug fixes will continue to
occur in the v1.x.x series.

This package only supports the two most recent major versions of Go, mirroring
Go's own release policy. Older versions of Go may lack critical features and bug
fixes which are necessary for this package to function correctly.
