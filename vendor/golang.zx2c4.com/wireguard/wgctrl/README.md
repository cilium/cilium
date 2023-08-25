# wgctrl [![Test Status](https://github.com/WireGuard/wgctrl-go/workflows/Linux%20Test/badge.svg)](https://github.com/WireGuard/wgctrl-go/actions) [![Go Reference](https://pkg.go.dev/badge/golang.zx2c4.com/wireguard/wgctrl.svg)](https://pkg.go.dev/golang.zx2c4.com/wireguard/wgctrl) [![Go Report Card](https://goreportcard.com/badge/golang.zx2c4.com/wireguard/wgctrl)](https://goreportcard.com/report/golang.zx2c4.com/wireguard/wgctrl)


Package `wgctrl` enables control of WireGuard devices on multiple platforms.

For more information on WireGuard, please see <https://www.wireguard.com/>.

MIT Licensed.

## Overview

`wgctrl` can control multiple types of WireGuard devices, including:

- Kernel module devices
  - Linux: via generic netlink
  - FreeBSD: via ioctl interface
  - OpenBSD: via ioctl interface (read-only)
  - Windows: via ioctl interface
- Userspace devices via the userspace configuration protocol

As new operating systems add support for in-kernel WireGuard implementations,
this package should also be extended to support those native implementations.

If you are aware of any efforts on this front, please
[file an issue](https://github.com/WireGuard/wgctrl-go/issues/new).

This package implements WireGuard configuration protocol operations, enabling
the configuration of existing WireGuard devices. Operations such as creating
WireGuard devices, or applying IP addresses to those devices, are out of scope
for this package.
