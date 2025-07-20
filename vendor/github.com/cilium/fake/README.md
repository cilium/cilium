# fake - generate random data for testing and/or performance evaluation

[![Go Reference](https://pkg.go.dev/badge/github.com/cilium/fake.svg)](https://pkg.go.dev/github.com/cilium/fake)
[![CI](https://github.com/cilium/fake/actions/workflows/tests.yml/badge.svg)](https://github.com/cilium/fake/actions/workflows/tests.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/cilium/fake)](https://goreportcard.com/report/github.com/cilium/fake)

Fake is a Go library and CLI to generate random data such as names, adjectives,
IP addresses and so on.

This repository contains three Go modules:

* [`github.com/cilium/fake`][1]: a library to generate generic random data which
  can be useful to any project (e.g. `fake.Adjective()`, `fake.IP()`, ...).
* [`github.com/cilium/fake/flow`][2]: a library to generate random [Hubble]
  network flows and flow related data. This library is only relevant to projects
  directly related to [Cilium] and/or [Hubble].
* `github.com/cilium/fake/cmd`: a CLI to generate random data.

As opposed to most fake data generator Go libraries, a design philosophy of this
library is to allow fine-grained control over generated data.

Let's illustrate this with an example. Instead of having separate functions to
generate IPv4 and IPv6 addresses (e.g. `fake.IPv4()` and `fake.IPv6()`), there
is a single `fake.IP()` function. However, this generator function, like most
others, can take optional arguments. By default, i.e. when no option is
specified (`fake.IP()`), it generates a random IP address which can be either v4
or v6. However, when passing the option to generate IPv4 addresses only
(`fake.IP(fake.WithIPv4())` option, only v4 addresses are generated. It is also
possible to pass an option to specify a CIDR that randomly generated IP
addresses must belong to (e.g. `fake.IP(fake.WithIPCIDR("10.0.0.0/8"))`).

Compared to other fake data generator Go libraries such as
[`github.com/icrowley/fake`][icrowley/fake] or
[`github.com/bxcodec/faker`][bxcodec/faker], this library does not (yet) support
as many generators (contributions welcome!).

## Installing the CLI

Go needs to be installed. Then, from either the root directory or the `cmd`
subdirectory, the `fake` binary can be compiled and installed via the `install`
make target. E.g.

    make install

By default, it installs the binary to `/usr/local/bin/fake`. The destination
directory can be specified using the `BINDIR` environment variable, e.g.:

    BINDIR=~/.local/bin make install

[1]: https://pkg.go.dev/github.com/cilium/fake
[2]: https://pkg.go.dev/github.com/cilium/fake/flow
[Cilium]: https://github.com/cilium/cilium
[Hubble]: https://github.com/cilium/hubble
[icrowley/fake]: https://github.com/icrowley/fake
[bxcodec/faker]: https://github.com/bxcodec/faker
