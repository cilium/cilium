package report

import (
	"net"
	"strings"
)

// Networks represent a set of subnets
type Networks []*net.IPNet

// Interface is exported for testing.
type Interface interface {
	Addrs() ([]net.Addr, error)
}

// Variables exposed for testing.
// TODO this design is broken, make it consistent with probe networks.
var (
	LocalNetworks       = Networks{}
	InterfaceByNameStub = func(name string) (Interface, error) { return net.InterfaceByName(name) }
)

// Contains returns true if IP is in Networks.
func (n Networks) Contains(ip net.IP) bool {
	for _, net := range n {
		if net.Contains(ip) {
			return true
		}
	}
	return false
}

// LocalAddresses returns a list of the local IP addresses.
func LocalAddresses() ([]net.IP, error) {
	result := []net.IP{}

	infs, err := net.Interfaces()
	if err != nil {
		return []net.IP{}, err
	}

	for _, inf := range infs {
		if strings.HasPrefix(inf.Name, "veth") ||
			strings.HasPrefix(inf.Name, "docker") ||
			strings.HasPrefix(inf.Name, "lo") {
			continue
		}

		addrs, err := inf.Addrs()
		if err != nil {
			return []net.IP{}, err
		}

		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			result = append(result, ipnet.IP)
		}
	}

	return result, nil
}

// AddLocalBridge records the subnet address associated with the bridge name
// supplied, such that MakeAddressNodeID will scope addresses in this subnet
// as local.
func AddLocalBridge(name string) error {
	inf, err := InterfaceByNameStub(name)
	if err != nil {
		return err
	}

	addrs, err := inf.Addrs()
	if err != nil {
		return err
	}
	for _, addr := range addrs {
		_, network, err := net.ParseCIDR(addr.String())
		if err != nil {
			return err
		}

		if network == nil {
			continue
		}

		LocalNetworks = append(LocalNetworks, network)
	}

	return nil
}
