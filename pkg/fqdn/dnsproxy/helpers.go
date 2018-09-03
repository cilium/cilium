// Copyright 2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package dnsproxy

import (
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/cilium/cilium/pkg/maps/proxymap"
	"github.com/cilium/cilium/pkg/u8proto"
	"github.com/miekg/dns"
)

// simpleFQDNCheck matches plain DNS names
// See https://en.wikipedia.org/wiki/Hostname
var simpleFQDNCheck = regexp.MustCompile("^[-a-zA-Z0-9.]*[.]$")

// escapeSimpleFQDN escapes the dots in simple DNS names to avoid spurious
// matches.
func escapeSimpleFQDN(re string) string {
	if simpleFQDNCheck.MatchString(re) {
		// This simple replace is correct because we assert that no "." has other
		// regex control characters before or after it above.
		return strings.Replace(re, ".", "[.]", -1)
	}
	return re
}

// prepareNameMatch ensures that a name is an anchored regexp and that names
// with only "." (aka not a regexp) escape the "." so it does not match any
// character. DNS expects lowercase lookups (ignoring the highest ascii bit)
// and we mimic this by lowercasing the name here, and lookups later.
// Note: The trailing "." in a FQDN is assumed, and isn't added here.
func prepareNameMatch(name string) string {
	name = strings.ToLower(name)  // lowercase it
	name = escapeSimpleFQDN(name) // escape it

	// anchor it
	out := make([]string, 0, 3)
	if !strings.HasPrefix(name, "^") {
		out = append(out, "^")
	}
	out = append(out, name)
	if !strings.HasSuffix(name, "$") {
		out = append(out, "$")
	}
	return strings.Join(out, "")
}

// lookupTargetDNSServer finds the intended DNS target server for a specific
// request (passed in via ServeDNS) in proxymap. The IP:port combination is
// returned.
func lookupTargetDNSServer(w dns.ResponseWriter) (server string, err error) {
	key, err := createProxyMapKey(w)
	if err != nil {
		return "", fmt.Errorf("cannot create proxymap key: %s", err)
	}

	val, err := proxymap.Lookup(key)
	if err != nil {
		return "", fmt.Errorf("proxymap lookup failed: %s", err)
	}

	return val.HostPort(), nil
}

// splitPortHostProto returns the IP, port and protocol of a net.Addr in native
// form.
func splitPortHostProto(addr net.Addr) (ip net.IP, port uint16, proto string, err error) {
	if addr == nil {
		return nil, 0, "", fmt.Errorf("nil address cannot be parsed")
	}

	switch addr := addr.(type) {
	case *net.TCPAddr:
		return addr.IP, uint16(addr.Port), addr.Network(), nil
	case *net.UDPAddr:
		return addr.IP, uint16(addr.Port), addr.Network(), nil
	default:
		return nil, 0, "", fmt.Errorf("unknown address type %T: %v", addr, addr)
	}
}

// createProxyMapKey creates a lookup key from a dns.ResponseWriter, using the
// .RemoteAddr, .LocalAddr and .Network calls.
// This function is similar to proxy.createProxyMapKey.
func createProxyMapKey(w dns.ResponseWriter) (mapKey proxymap.ProxyMapKey, err error) {
	clientSourceIP, clientSourcePort, _, err := splitPortHostProto(w.RemoteAddr())
	if err != nil {
		return nil, fmt.Errorf("invalid remote address '%s'", w.RemoteAddr().String())
	}

	_, proxyListenPort, protocolStr, err := splitPortHostProto(w.LocalAddr())
	if err != nil {
		return nil, fmt.Errorf("invalid proxy address '%s'", w.LocalAddr().String())
	}

	protocol, err := u8proto.ParseProtocol(protocolStr)
	if err != nil {
		return nil, err
	}

	if clientSourceIP.To4() != nil {
		key := proxymap.Proxy4Key{
			SPort:   uint16(clientSourcePort),
			DPort:   proxyListenPort,
			Nexthdr: uint8(protocol),
		}

		copy(key.SAddr[:], clientSourceIP.To4())
		return key, nil
	}

	key := proxymap.Proxy6Key{
		SPort:   uint16(clientSourcePort),
		DPort:   proxyListenPort,
		Nexthdr: uint8(protocol),
	}

	copy(key.SAddr[:], clientSourceIP.To16())
	return key, nil
}
