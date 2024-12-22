package mapcidr

import (
	"net"

	"github.com/projectdiscovery/blackrock"
)

// ShuffleCidrsWithSeed uses blackrock to visit all ips in random order
func ShuffleCidrsWithSeed(cidrs []*net.IPNet, seed int64) chan Item {
	// Shrink and compact
	cidrs, _ = CoalesceCIDRs(cidrs)
	out := make(chan Item)
	go func(out chan Item, cidrs []*net.IPNet) {
		defer close(out)
		targetsCount := int64(TotalIPSInCidrs(cidrs))
		Range := targetsCount
		br := blackrock.New(Range, seed)
		for index := int64(0); index < Range; index++ {
			ipIndex := br.Shuffle(index)
			ip := PickIP(cidrs, ipIndex)
			if ip == "" {
				continue
			}
			out <- Item{IP: ip}
		}
	}(out, cidrs)
	return out
}

// ShuffleCidrsWithPortsAndSeed uses blackrock to visit all ips and ports combinations in random order
func ShuffleCidrsWithPortsAndSeed(cidrs []*net.IPNet, ports []int, seed int64) chan Item {
	// Shrink and compact
	cidrs, _ = CoalesceCIDRs(cidrs)
	out := make(chan Item)
	go func(out chan Item, cidrs []*net.IPNet) {
		defer close(out)
		targetsCount := int64(TotalIPSInCidrs(cidrs))
		portsCount := int64(len(ports))
		Range := targetsCount * portsCount
		br := blackrock.New(Range, seed)
		for index := int64(0); index < Range; index++ {
			xxx := br.Shuffle(index)
			ipIndex := xxx / portsCount
			portIndex := int(xxx % portsCount)
			ip := PickIP(cidrs, ipIndex)
			port := PickPort(ports, portIndex)

			if ip == "" || port <= 0 {
				continue
			}
			out <- Item{IP: ip, Port: port}
		}
	}(out, cidrs)
	return out
}

// PickIP takes an ip from a list of subnets
func PickIP(cidrs []*net.IPNet, index int64) string {
	for _, target := range cidrs {
		subnetIpsCount := int64(AddressCountIpnet(target))
		if index < subnetIpsCount {
			return PickSubnetIP(target, index)
		}
		index -= subnetIpsCount
	}

	return ""
}

// PickSubnetIP takes an ip from a subnet
func PickSubnetIP(network *net.IPNet, index int64) string {
	return Inet_ntoa(Inet_aton(network.IP) + index).String()
}

// PickPort takes a port from a list
func PickPort(ports []int, index int) int {
	return ports[index]
}

// CIDRsAsIPNET converts a list of cidrs to ipnet
func CIDRsAsIPNET(cidrs []string) (ipnets []*net.IPNet) {
	for _, cidr := range cidrs {
		ipnets = append(ipnets, AsIPV4CIDR(cidr))
	}
	return
}
