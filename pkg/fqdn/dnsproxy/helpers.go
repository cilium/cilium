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
	"strconv"
	"strings"

	"github.com/cilium/cilium/pkg/maps/proxymap"
	"github.com/cilium/cilium/pkg/u8proto"
	"github.com/cilium/dns"
)

// prepareNameMatch ensures that a name is an anchored regexp and that names
// with only "." (aka not a regexp) escape the "." so it does not match any
// character. DNS expects lowercase lookups (ignoring the highest ascii bit)
// and we mimic this by lowercasing the name here, and lookups later.
// Note: The trailing "." in a FQDN is assumed, and isn't added here.
func prepareNameMatch(name string) string {
	name = strings.ToLower(name) // lowercase it

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

// createProxyMapKey creates a lookup key from a dns.ResponseWriter, using the
// .RemoteAddr, .LocalAddr and .Network calls.
// This function is similar to proxy.createProxyMapKey.
func createProxyMapKey(w dns.ResponseWriter) (mapKey proxymap.ProxyMapKey, err error) {
	clientSourceIPStr, clientSourcePortStr, err := net.SplitHostPort(w.RemoteAddr().String())
	if err != nil {
		return nil, fmt.Errorf("invalid remote address '%s'", w.RemoteAddr().String())
	}

	_, proxyListenPortStr, err := net.SplitHostPort(w.LocalAddr().String())
	if err != nil {
		return nil, fmt.Errorf("invalid proxy address '%s'", w.LocalAddr().String())
	}

	protocol, err := u8proto.ParseProtocol(w.LocalAddr().Network())
	if err != nil {
		return nil, err
	}

	clientSourceIP := net.ParseIP(clientSourceIPStr)
	clientSourcePort, err := parsePortString(clientSourcePortStr)
	if err != nil {
		return nil, fmt.Errorf("Invalid clientSourcePort when creating DNSProxy proxymap key: %s", err)
	}

	proxyListenPort, err := parsePortString(proxyListenPortStr)
	if err != nil {
		return nil, fmt.Errorf("Invalid proxyListenPort when creating DNSProxy proxymap key: %s", err)
	}

	if clientSourceIP.To4() != nil {
		key := proxymap.Proxy4Key{
			SPort:   clientSourcePort,
			DPort:   proxyListenPort,
			Nexthdr: uint8(protocol),
		}

		copy(key.SAddr[:], clientSourceIP.To4())
		return key, nil
	}

	key := proxymap.Proxy6Key{
		SPort:   uint16(clientSourcePort),
		DPort:   uint16(proxyListenPort),
		Nexthdr: uint8(protocol),
	}

	copy(key.SAddr[:], clientSourceIP.To16())
	return key, nil
}

// parsePortString parses a string as a 16-bit port. It will return an error on
// an unparseable string, or when the numeric value is invalid for a port.
func parsePortString(portStr string) (port uint16, err error) {
	portInt, err := strconv.Atoi(portStr)
	if err != nil {
		return 0, fmt.Errorf("Cannot parse port %s", portStr)
	}
	if portInt < 0 || portInt > 65535 {
		return 0, fmt.Errorf("Port(%s) is out of possible 0-65535 range", portStr)
	}
	return uint16(portInt), nil
}
