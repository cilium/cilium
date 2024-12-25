package netutil

import (
	"encoding"
	"fmt"
)

// HostPort And Utilities

// HostPort is a convenient type for addresses that contain a hostname and
// a port, like "example.com:12345", "1.2.3.4:56789", or "[1234::cdef]:12345".
type HostPort struct {
	Host string
	Port uint16
}

// ParseHostPort parses a HostPort from addr.  Any error returned will have the
// underlying type of [*AddrError].
func ParseHostPort(addr string) (hp *HostPort, err error) {
	defer makeAddrError(&err, addr, AddrKindHostPort)

	var host string
	var port uint16
	host, port, err = SplitHostPort(addr)
	if err != nil {
		return nil, err
	}

	return &HostPort{
		Host: host,
		Port: port,
	}, nil
}

// CloneHostPorts returns a deep copy of hps.
func CloneHostPorts(hps []*HostPort) (clone []*HostPort) {
	if hps == nil {
		return nil
	}

	clone = make([]*HostPort, len(hps))
	for i, hp := range hps {
		clone[i] = hp.Clone()
	}

	return clone
}

// Clone returns a clone of hp.
func (hp *HostPort) Clone() (clone *HostPort) {
	if hp == nil {
		return nil
	}

	return &HostPort{
		Host: hp.Host,
		Port: hp.Port,
	}
}

// type check
var _ encoding.TextMarshaler = HostPort{}

// MarshalText implements the [encoding.TextMarshaler] interface for HostPort.
func (hp HostPort) MarshalText() (b []byte, err error) {
	return []byte(hp.String()), nil
}

// type check
var _ fmt.Stringer = HostPort{}

// String implements the [fmt.Stringer] interface for *HostPort.
func (hp HostPort) String() (s string) {
	return JoinHostPort(hp.Host, hp.Port)
}

// type check
var _ encoding.TextUnmarshaler = (*HostPort)(nil)

// UnmarshalText implements the [encoding.TextUnmarshaler] interface for
// *HostPort.  Any error returned will have the underlying type of [*AddrError].
func (hp *HostPort) UnmarshalText(b []byte) (err error) {
	var newHP *HostPort
	newHP, err = ParseHostPort(string(b))
	if err != nil {
		return err
	}

	*hp = *newHP

	return nil
}
