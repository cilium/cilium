# pro-bing
[![PkgGoDev](https://pkg.go.dev/badge/github.com/prometheus-community/pro-bing)](https://pkg.go.dev/github.com/prometheus-community/pro-bing)
[![Circle CI](https://circleci.com/gh/prometheus-community/pro-bing.svg?style=svg)](https://circleci.com/gh/prometheus-community/pro-bing)

A simple but powerful ICMP echo (ping) library for Go, inspired by
[go-ping](https://github.com/go-ping/ping) & [go-fastping](https://github.com/tatsushid/go-fastping).

Here is a very simple example that sends and receives three packets:

```go
pinger, err := probing.NewPinger("www.google.com")
if err != nil {
	panic(err)
}
pinger.Count = 3
err = pinger.Run() // Blocks until finished.
if err != nil {
	panic(err)
}
stats := pinger.Statistics() // get send/receive/duplicate/rtt stats
```

Here is an example that emulates the traditional UNIX ping command:

```go
pinger, err := probing.NewPinger("www.google.com")
if err != nil {
	panic(err)
}

// Listen for Ctrl-C.
c := make(chan os.Signal, 1)
signal.Notify(c, os.Interrupt)
go func() {
	for _ = range c {
		pinger.Stop()
	}
}()

pinger.OnRecv = func(pkt *probing.Packet) {
	fmt.Printf("%d bytes from %s: icmp_seq=%d time=%v\n",
		pkt.Nbytes, pkt.IPAddr, pkt.Seq, pkt.Rtt)
}

pinger.OnDuplicateRecv = func(pkt *probing.Packet) {
	fmt.Printf("%d bytes from %s: icmp_seq=%d time=%v ttl=%v (DUP!)\n",
		pkt.Nbytes, pkt.IPAddr, pkt.Seq, pkt.Rtt, pkt.TTL)
}

pinger.OnFinish = func(stats *probing.Statistics) {
	fmt.Printf("\n--- %s ping statistics ---\n", stats.Addr)
	fmt.Printf("%d packets transmitted, %d packets received, %v%% packet loss\n",
		stats.PacketsSent, stats.PacketsRecv, stats.PacketLoss)
	fmt.Printf("round-trip min/avg/max/stddev = %v/%v/%v/%v\n",
		stats.MinRtt, stats.AvgRtt, stats.MaxRtt, stats.StdDevRtt)
}

fmt.Printf("PING %s (%s):\n", pinger.Addr(), pinger.IPAddr())
err = pinger.Run()
if err != nil {
	panic(err)
}
```

It sends ICMP Echo Request packet(s) and waits for an Echo Reply in
response. If it receives a response, it calls the `OnRecv` callback
unless a packet with that sequence number has already been received,
in which case it calls the `OnDuplicateRecv` callback. When it's
finished, it calls the `OnFinish` callback.

For a full ping example, see
[cmd/ping/ping.go](https://github.com/prometheus-community/pro-bing/blob/master/cmd/ping/ping.go).

## Installation

```
go get -u github.com/prometheus-community/pro-bing
```

To install the native Go ping executable:

```bash
go get -u github.com/prometheus-community/pro-bing/...
$GOPATH/bin/ping
```

## Supported Operating Systems

### Linux
This library attempts to send an "unprivileged" ping via UDP. On Linux,
this must be enabled with the following sysctl command:

```
sudo sysctl -w net.ipv4.ping_group_range="0 2147483647"
```

If you do not wish to do this, you can call `pinger.SetPrivileged(true)`
in your code and then use setcap on your binary to allow it to bind to
raw sockets (or just run it as root):

```
setcap cap_net_raw=+ep /path/to/your/compiled/binary
```

See [this blog](https://sturmflut.github.io/linux/ubuntu/2015/01/17/unprivileged-icmp-sockets-on-linux/)
and the Go [x/net/icmp](https://godoc.org/golang.org/x/net/icmp) package
for more details.

This library supports setting the `SO_MARK` socket option which is equivalent to the `-m mark`
flag in standard ping binaries on linux. Setting this option requires the `CAP_NET_ADMIN` capability
(via `setcap` or elevated privileges). You can set a mark (ex: 100) with `pinger.SetMark(100)` in your code.

Setting the "Don't Fragment" bit is supported under Linux which is equivalent to `ping -Mdo`.
You can enable this with `pinger.SetDoNotFragment(true)`.

### Windows

You must use `pinger.SetPrivileged(true)`, otherwise you will receive
the following error:

```
socket: The requested protocol has not been configured into the system, or no implementation for it exists.
```

Despite the method name, this should work without the need to elevate
privileges and has been tested on Windows 10. Please note that accessing
packet TTL values is not supported due to limitations in the Go
x/net/ipv4 and x/net/ipv6 packages.

### Plan 9 from Bell Labs

There is no support for Plan 9. This is because the entire `x/net/ipv4`
and `x/net/ipv6` packages are not implemented by the Go programming
language.

## HTTP

This library also provides support for HTTP probing.
Here is a trivial example:

```go
httpCaller := probing.NewHttpCaller("https://www.google.com",
    probing.WithHTTPCallerCallFrequency(time.Second),
    probing.WithHTTPCallerOnResp(func(suite *probing.TraceSuite, info *probing.HTTPCallInfo) {
        fmt.Printf("got resp, status code: %d, latency: %s\n",
            info.StatusCode,
            suite.GetGeneralEnd().Sub(suite.GetGeneralStart()),
        )
    }),
)

// Listen for Ctrl-C.
c := make(chan os.Signal, 1)
signal.Notify(c, os.Interrupt)
go func() {
    <-c
    httpCaller.Stop()
}()
httpCaller.Run()
```

Library provides a rich list of options available for a probing. You can check the full list of available
options in a generated doc.

### Callbacks

HTTPCaller uses `net/http/httptrace` pkg to provide an API to track specific request event, e.g. tls handshake start.
It is highly recommended to check the httptrace library [doc](https://pkg.go.dev/net/http/httptrace) to understand
the purpose of provided callbacks. Nevertheless, httptrace callbacks are concurrent-unsafe, our implementation provides
a concurrent-safe API. In addition to that, each callback contains a TraceSuite object which provides an Extra field
which you can use to propagate your data across them and a number of timer fields, which are set prior to the execution of a
corresponding callback.

### Target RPS & performance

Library provides two options, allowing to manipulate your call load: `callFrequency` & `maxConcurrentCalls`.
In case you set `callFrequency` to a value X, but it can't be achieved during the execution - you will need to
try increasing a number of `maxConcurrentCalls`. Moreover, your callbacks might directly influence an execution
performance.

For a full documentation, please refer to the generated [doc](https://pkg.go.dev/github.com/prometheus-community/pro-bing).

## Maintainers and Getting Help:

This repo was originally in the personal account of
[sparrc](https://github.com/sparrc), but is now maintained by the
[Prometheus Community](https://prometheus.io/community).

## Contributing

Refer to [CONTRIBUTING.md](https://github.com/prometheus-community/pro-bing/blob/master/CONTRIBUTING.md)
