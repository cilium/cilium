package pflag

import (
	"fmt"
	"net"
)

// -- net.IPMask value
type ipMaskValue net.IPMask

func newIPMaskValue(val net.IPMask, p *net.IPMask) *ipMaskValue {
	*p = val
	return (*ipMaskValue)(p)
}

func (i *ipMaskValue) String() string { return net.IPMask(*i).String() }
func (i *ipMaskValue) Set(s string) error {
	ip := ParseIPv4Mask(s)
	if ip == nil {
		return fmt.Errorf("failed to parse IP mask: %q", s)
	}
	*i = ipMaskValue(ip)
	return nil
}

func (i *ipMaskValue) Type() string {
	return "ipMask"
}

// Parse IPv4 netmask written in IP form (e.g. 255.255.255.0).
// This function should really belong to the net package.
func ParseIPv4Mask(s string) net.IPMask {
	mask := net.ParseIP(s)
	if mask == nil {
		return nil
	}
	return net.IPv4Mask(mask[12], mask[13], mask[14], mask[15])
}

// IPMaskVar defines an net.IPMask flag with specified name, default value, and usage string.
// The argument p points to an net.IPMask variable in which to store the value of the flag.
func (f *FlagSet) IPMaskVar(p *net.IPMask, name string, value net.IPMask, usage string) {
	f.VarP(newIPMaskValue(value, p), name, "", usage)
}

// Like IPMaskVar, but accepts a shorthand letter that can be used after a single dash.
func (f *FlagSet) IPMaskVarP(p *net.IPMask, name, shorthand string, value net.IPMask, usage string) {
	f.VarP(newIPMaskValue(value, p), name, shorthand, usage)
}

// IPMaskVar defines an net.IPMask flag with specified name, default value, and usage string.
// The argument p points to an net.IPMask variable in which to store the value of the flag.
func IPMaskVar(p *net.IPMask, name string, value net.IPMask, usage string) {
	CommandLine.VarP(newIPMaskValue(value, p), name, "", usage)
}

// Like IPMaskVar, but accepts a shorthand letter that can be used after a single dash.
func IPMaskVarP(p *net.IPMask, name, shorthand string, value net.IPMask, usage string) {
	CommandLine.VarP(newIPMaskValue(value, p), name, shorthand, usage)
}

// IPMask defines an net.IPMask flag with specified name, default value, and usage string.
// The return value is the address of an net.IPMask variable that stores the value of the flag.
func (f *FlagSet) IPMask(name string, value net.IPMask, usage string) *net.IPMask {
	p := new(net.IPMask)
	f.IPMaskVarP(p, name, "", value, usage)
	return p
}

// Like IPMask, but accepts a shorthand letter that can be used after a single dash.
func (f *FlagSet) IPMaskP(name, shorthand string, value net.IPMask, usage string) *net.IPMask {
	p := new(net.IPMask)
	f.IPMaskVarP(p, name, shorthand, value, usage)
	return p
}

// IPMask defines an net.IPMask flag with specified name, default value, and usage string.
// The return value is the address of an net.IPMask variable that stores the value of the flag.
func IPMask(name string, value net.IPMask, usage string) *net.IPMask {
	return CommandLine.IPMaskP(name, "", value, usage)
}

// Like IP, but accepts a shorthand letter that can be used after a single dash.
func IPMaskP(name, shorthand string, value net.IPMask, usage string) *net.IPMask {
	return CommandLine.IPMaskP(name, shorthand, value, usage)
}
