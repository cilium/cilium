package mapcidr

import (
	"crypto/rand"
	"encoding/hex"
	"net"
	"strings"
)

// inc increments an IP address to the next IP in the subnet
func inc(ip net.IP) net.IP {
	incIP := make([]byte, len(ip))
	copy(incIP, ip)
	for j := len(incIP) - 1; j >= 0; j-- {
		incIP[j]++
		if incIP[j] > 0 {
			break
		}
	}
	return incIP
}

// dec decrements an IP address to the previous IP in the subnet
// func dec(IP net.IP) net.IP {
// 	decIP := make([]byte, len(IP))
// 	copy(decIP, IP)
// 	for j := len(decIP) - 1; j >= 0; j-- {
// 		decIP[j]--
// 		if decIP[j] < 255 {
// 			break
// 		}
// 	}
// 	return decIP
// }

// TotalIPSInCidrs calculates the number of ips in the diven cidrs
func TotalIPSInCidrs(cidrs []*net.IPNet) (totalIPs uint64) {
	for _, cidr := range cidrs {
		totalIPs += AddressCountIpnet(cidr)
	}

	return
}

// AsIPV4CIDR converts ipv4 address to cidr representation
func AsIPV4CIDR(ipv4 string) *net.IPNet {
	if IsIPv4(net.ParseIP(ipv4)) {
		ipv4 += "/32"
	}
	_, network, err := net.ParseCIDR(ipv4)
	if err != nil {
		return nil
	}
	return network
}

func IsBaseIP(IP string) bool {
	ipParsed := net.ParseIP(IP)
	return ipParsed != nil && ipParsed.To4() != nil && strings.HasSuffix(IP, ".0")
}

func IsBroadcastIP(IP string) bool {
	ipParsed := net.ParseIP(IP)
	return ipParsed != nil && ipParsed.To4() != nil && strings.HasSuffix(IP, ".255")
}

func RandomHex(n int, suffix []byte) (string, error) {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(append(bytes, suffix...)), nil
}
