# raw [![builds.sr.ht status](https://builds.sr.ht/~mdlayher/raw.svg)](https://builds.sr.ht/~mdlayher/raw?) [![GoDoc](https://godoc.org/github.com/mdlayher/raw?status.svg)](https://godoc.org/github.com/mdlayher/raw) [![Go Report Card](https://goreportcard.com/badge/github.com/mdlayher/raw)](https://goreportcard.com/report/github.com/mdlayher/raw)

Package `raw` enables reading and writing data at the device driver level for
a network interface.  MIT Licensed.

For more information about using raw sockets with Ethernet frames in Go, check
out my blog post: [Network Protocol Breakdown: Ethernet and Go](https://medium.com/@mdlayher/network-protocol-breakdown-ethernet-and-go-de985d726cc1).

Portions of this code are taken from the Go standard library.  The Go
standard library is Copyright (c) 2012 The Go Authors. All rights reserved.
The Go license can be found at https://golang.org/LICENSE.

## Stability

At this time, package `raw` is in a pre-v1.0.0 state. Changes are being made
which may impact the exported API of this package and others in its ecosystem.

The general policy of this package is to only support the latest, stable version
of Go. Compatibility shims may be added for prior versions of Go on an as-needed
basis. If you would like to raise a concern, please [file an issue](https://github.com/mdlayher/raw/issues/new).

**If you depend on this package in your applications, please vendor it or use Go
modules when building your application.**
