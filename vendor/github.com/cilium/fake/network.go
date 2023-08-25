// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fake

import (
	"fmt"
	"math/rand"
	"net"
)

// a MAC address have different sizes. For the purpose of simplicity, only
// support 6 bytes MAC.
const macLen = 6

// MAC generates a random MAC address.
func MAC() string {
	hw := make(net.HardwareAddr, macLen)
	_, _ = rand.Read(hw)
	return hw.String()
}

type ipOptions struct {
	v4, v6  bool
	network *net.IPNet
}

// IPOption is an option to use with IP.
type IPOption interface {
	apply(o *ipOptions)
}

type funcIPOption func(*ipOptions)

func (fio funcIPOption) apply(io *ipOptions) {
	fio(io)
}

// WithIPv6 specifies that the generated IP address must be IPv6.
// This option is incompatible with WithIPv4 and WithIPCIDR.
func WithIPv6() IPOption {
	return funcIPOption(func(o *ipOptions) {
		o.v6 = true
	})
}

// WithIPv4 specifies that the generated IP address must be IPv4.
// This option is incompatible with WithIPv6 and WithIPCIDR.
func WithIPv4() IPOption {
	return funcIPOption(func(o *ipOptions) {
		o.v4 = true
	})
}

// WithIPCIDR defines a network for generated IPs. This option is incompatible
// with WithIPv4 and WithIPv6. It panics if the given cidr is invalid.
func WithIPCIDR(cidr string) IPOption {
	return funcIPOption(func(o *ipOptions) {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(fmt.Sprintf("invalid CIDR (%s): %s", cidr, err))
		}
		o.network = network
	})
}

// IP generates a random IP address. Options may be provided to specify a
// network for the address or if it should be IPv4 or IPv6.
func IP(options ...IPOption) string {
	opts := ipOptions{}
	for _, opt := range options {
		opt.apply(&opts)
	}

	var size int
	if opts.network == nil {
		switch {
		case opts.v4 == opts.v6:
			sizes := []int{net.IPv4len, net.IPv6len}
			size = sizes[rand.Intn(len(sizes))]
		case opts.v4:
			size = net.IPv4len
		case opts.v6:
			size = net.IPv6len
		}
		ip := make([]byte, size)
		_, _ = rand.Read(ip)
		return net.IP(ip).String()
	}

	size = len(opts.network.Mask)
	raw := make([]byte, size)
	_, _ = rand.Read(raw)
	ip := opts.network.IP
	for i, v := range raw {
		ip[i] += v &^ opts.network.Mask[i]
	}
	return ip.String()
}

type portOptions struct {
	min, max int
}

// PortOption is an option to use with Port.
type PortOption interface {
	apply(o *portOptions)
}

type funcPortOption func(*portOptions)

func (fpo funcPortOption) apply(po *portOptions) {
	fpo(po)
}

// WithPortSystem specifies that the generated port must in the system range.
// If zero is true, the port range is [0,1023], otherwise it's [1,1023].
// This option is incompatible with WithPortUser and WithPortDynamic.
func WithPortSystem(zero bool) PortOption {
	return funcPortOption(func(o *portOptions) {
		o.min = 1
		if zero {
			o.min = 0
		}
		o.max = 1023
	})
}

// WithPortUser specifies that the generated port must be in the user range,
// i.e. [1024, 49151].
// This option is incompatible with WithPortSystem and WithPortDynamic.
func WithPortUser() PortOption {
	return funcPortOption(func(o *portOptions) {
		o.min = 1024
		o.max = 49_151
	})
}

// WithPortDynamic specifies that the generated port must be in the dynamic
// range, i.e. [49152,65535].
// This option is incompatible with WithPortSystem and WithPortUser.
func WithPortDynamic() PortOption {
	return funcPortOption(func(o *portOptions) {
		o.min = 49_152
		o.max = 65_535
	})
}

// Port generates a random port number between 1 and 65535 or in the range
// specified by the given option.
func Port(options ...PortOption) uint32 {
	opts := portOptions{
		min: 1,
		max: 65_535,
	}
	for _, opt := range options {
		opt.apply(&opts)
	}
	return uint32(rand.Intn(opts.max+1-opts.min) + opts.min)
}
