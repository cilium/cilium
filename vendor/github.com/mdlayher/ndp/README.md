# ndp [![builds.sr.ht status](https://builds.sr.ht/~mdlayher/ndp.svg)](https://builds.sr.ht/~mdlayher/ndp?) [![GoDoc](https://godoc.org/github.com/mdlayher/ndp?status.svg)](https://godoc.org/github.com/mdlayher/ndp) [![Go Report Card](https://goreportcard.com/badge/github.com/mdlayher/ndp)](https://goreportcard.com/report/github.com/mdlayher/ndp)

Package `ndp` implements the Neighbor Discovery Protocol, as described in
[RFC 4861](https://tools.ietf.org/html/rfc4861).  MIT Licensed.

The command `ndp` is a utility for working with the Neighbor Discovery Protocol.

Install the package and utility using `go get`:

```none
$ go get github.com/mdlayher/ndp/...
```

To learn more about NDP, and how to use this package, check out my blog:
[Network Protocol Breakdown:  NDP and Go](https://medium.com/@mdlayher/network-protocol-breakdown-ndp-and-go-3dc2900b1c20).

## Examples

Listen for incoming NDP messages on interface eth0 to one of the interface's
global unicast addresses.

```none
$ sudo ndp -i eth0 -a global listen
$ sudo ndp -i eth0 -a 2001:db8::1 listen
````

Send router solicitations on interface eth0 from the interface's link-local
address until a router advertisement is received.

```none
$ sudo ndp -i eth0 -a linklocal rs
```

Send neighbor solicitations on interface eth0 to a neighbor's link-local
address until a neighbor advertisement is received.

```none
$ sudo ndp -i eth0 -a linklocal -t fe80::1 ns
```

An example of the tool sending a router solicitation and receiving a router
advertisement on the WAN interface of a Ubiquiti router:

```none
$ sudo ndp -i eth1 -a linklocal rs
ndp> interface: eth1, link-layer address: 04:18:d6:a1:ce:b8, IPv6 address: fe80::618:d6ff:fea1:ceb8
ndp rs> router solicitation:
    - source link-layer address: 04:18:d6:a1:ce:b8

ndp rs> router advertisement from: fe80::201:5cff:fe69:f246:
    - hop limit:        0
    - flags:            [MO]
    - preference:       0
    - router lifetime:  2h30m0s
    - reachable time:   1h0m0s
    - retransmit timer: 0s
    - options:
        - prefix information: 2600:6c4a:7002:100::/64, flags: [], valid: 720h0m0s, preferred: 168h0m0s
```
