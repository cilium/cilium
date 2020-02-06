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

	"github.com/miekg/dns"
)

// lookupTargetDNSServer finds the intended DNS target server for a specific
// request (passed in via ServeDNS). The IP:port combination is
// returned.
func lookupTargetDNSServer(w dns.ResponseWriter) (serverIP net.IP, serverPort uint16, addrStr string, err error) {
	switch addr := (w.LocalAddr()).(type) {
	case *net.UDPAddr:
		return addr.IP, uint16(addr.Port), addr.String(), nil
	case *net.TCPAddr:
		return addr.IP, uint16(addr.Port), addr.String(), nil
	default:
		return nil, 0, addr.String(), fmt.Errorf("Cannot extract address information for type %T: %+v", addr, addr)
	}
}
