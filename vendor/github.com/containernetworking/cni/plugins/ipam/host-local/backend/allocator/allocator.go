// Copyright 2015 CNI authors
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

package allocator

import (
	"fmt"
	"log"
	"net"
	"os"

	"github.com/containernetworking/cni/pkg/ip"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/cni/plugins/ipam/host-local/backend"
)

type IPAllocator struct {
	// start is inclusive and may be allocated
	start net.IP
	// end is inclusive and may be allocated
	end   net.IP
	conf  *IPAMConfig
	store backend.Store
}

func NewIPAllocator(conf *IPAMConfig, store backend.Store) (*IPAllocator, error) {
	// Can't create an allocator for a network with no addresses, eg
	// a /32 or /31
	ones, masklen := conf.Subnet.Mask.Size()
	if ones > masklen-2 {
		return nil, fmt.Errorf("Network %v too small to allocate from", conf.Subnet)
	}

	var (
		start net.IP
		end   net.IP
		err   error
	)
	start, end, err = networkRange((*net.IPNet)(&conf.Subnet))
	if err != nil {
		return nil, err
	}

	// skip the .0 address
	start = ip.NextIP(start)

	if conf.RangeStart != nil {
		if err := validateRangeIP(conf.RangeStart, (*net.IPNet)(&conf.Subnet), nil, nil); err != nil {
			return nil, err
		}
		start = conf.RangeStart
	}
	if conf.RangeEnd != nil {
		if err := validateRangeIP(conf.RangeEnd, (*net.IPNet)(&conf.Subnet), start, nil); err != nil {
			return nil, err
		}
		end = conf.RangeEnd
	}
	return &IPAllocator{start, end, conf, store}, nil
}

func canonicalizeIP(ip net.IP) (net.IP, error) {
	if ip.To4() != nil {
		return ip.To4(), nil
	} else if ip.To16() != nil {
		return ip.To16(), nil
	}
	return nil, fmt.Errorf("IP %s not v4 nor v6", ip)
}

// Ensures @ip is within @ipnet, and (if given) inclusive of @start and @end
func validateRangeIP(ip net.IP, ipnet *net.IPNet, start net.IP, end net.IP) error {
	var err error

	// Make sure we can compare IPv4 addresses directly
	ip, err = canonicalizeIP(ip)
	if err != nil {
		return err
	}

	if !ipnet.Contains(ip) {
		return fmt.Errorf("%s not in network: %s", ip, ipnet)
	}

	if start != nil {
		start, err = canonicalizeIP(start)
		if err != nil {
			return err
		}
		if len(ip) != len(start) {
			return fmt.Errorf("%s %d not same size IP address as start %s %d", ip, len(ip), start, len(start))
		}
		for i := 0; i < len(ip); i++ {
			if ip[i] > start[i] {
				break
			} else if ip[i] < start[i] {
				return fmt.Errorf("%s outside of network %s with start %s", ip, ipnet, start)
			}
		}
	}

	if end != nil {
		end, err = canonicalizeIP(end)
		if err != nil {
			return err
		}
		if len(ip) != len(end) {
			return fmt.Errorf("%s %d not same size IP address as end %s %d", ip, len(ip), end, len(end))
		}
		for i := 0; i < len(ip); i++ {
			if ip[i] < end[i] {
				break
			} else if ip[i] > end[i] {
				return fmt.Errorf("%s outside of network %s with end %s", ip, ipnet, end)
			}
		}
	}
	return nil
}

// Returns newly allocated IP along with its config
func (a *IPAllocator) Get(id string) (*current.IPConfig, []*types.Route, error) {
	a.store.Lock()
	defer a.store.Unlock()

	gw := a.conf.Gateway
	if gw == nil {
		gw = ip.NextIP(a.conf.Subnet.IP)
	}

	var requestedIP net.IP
	if a.conf.Args != nil {
		requestedIP = a.conf.Args.IP
	}

	if requestedIP != nil {
		if gw != nil && gw.Equal(a.conf.Args.IP) {
			return nil, nil, fmt.Errorf("requested IP must differ gateway IP")
		}

		subnet := net.IPNet{
			IP:   a.conf.Subnet.IP,
			Mask: a.conf.Subnet.Mask,
		}
		err := validateRangeIP(requestedIP, &subnet, a.start, a.end)
		if err != nil {
			return nil, nil, err
		}

		reserved, err := a.store.Reserve(id, requestedIP)
		if err != nil {
			return nil, nil, err
		}

		if reserved {
			ipConfig := &current.IPConfig{
				Version: "4",
				Address: net.IPNet{IP: requestedIP, Mask: a.conf.Subnet.Mask},
				Gateway: gw,
			}
			routes := convertRoutesToCurrent(a.conf.Routes)
			return ipConfig, routes, nil
		}
		return nil, nil, fmt.Errorf("requested IP address %q is not available in network: %s", requestedIP, a.conf.Name)
	}

	startIP, endIP := a.getSearchRange()
	for cur := startIP; ; cur = a.nextIP(cur) {
		// don't allocate gateway IP
		if gw != nil && cur.Equal(gw) {
			continue
		}

		reserved, err := a.store.Reserve(id, cur)
		if err != nil {
			return nil, nil, err
		}
		if reserved {
			ipConfig := &current.IPConfig{
				Version: "4",
				Address: net.IPNet{IP: cur, Mask: a.conf.Subnet.Mask},
				Gateway: gw,
			}
			routes := convertRoutesToCurrent(a.conf.Routes)
			return ipConfig, routes, nil
		}
		// break here to complete the loop
		if cur.Equal(endIP) {
			break
		}
	}
	return nil, nil, fmt.Errorf("no IP addresses available in network: %s", a.conf.Name)
}

// Releases all IPs allocated for the container with given ID
func (a *IPAllocator) Release(id string) error {
	a.store.Lock()
	defer a.store.Unlock()

	return a.store.ReleaseByID(id)
}

// Return the start and end IP addresses of a given subnet, excluding
// the broadcast address (eg, 192.168.1.255)
func networkRange(ipnet *net.IPNet) (net.IP, net.IP, error) {
	if ipnet.IP == nil {
		return nil, nil, fmt.Errorf("missing field %q in IPAM configuration", "subnet")
	}
	ip, err := canonicalizeIP(ipnet.IP)
	if err != nil {
		return nil, nil, fmt.Errorf("IP not v4 nor v6")
	}

	if len(ip) != len(ipnet.Mask) {
		return nil, nil, fmt.Errorf("IPNet IP and Mask version mismatch")
	}

	var end net.IP
	for i := 0; i < len(ip); i++ {
		end = append(end, ip[i]|^ipnet.Mask[i])
	}

	// Exclude the broadcast address for IPv4
	if ip.To4() != nil {
		end[3]--
	}

	return ipnet.IP, end, nil
}

// nextIP returns the next ip of curIP within ipallocator's subnet
func (a *IPAllocator) nextIP(curIP net.IP) net.IP {
	if curIP.Equal(a.end) {
		return a.start
	}
	return ip.NextIP(curIP)
}

// getSearchRange returns the start and end ip based on the last reserved ip
func (a *IPAllocator) getSearchRange() (net.IP, net.IP) {
	var startIP net.IP
	var endIP net.IP
	startFromLastReservedIP := false
	lastReservedIP, err := a.store.LastReservedIP()
	if err != nil && !os.IsNotExist(err) {
		log.Printf("Error retriving last reserved ip: %v", err)
	} else if lastReservedIP != nil {
		subnet := net.IPNet{
			IP:   a.conf.Subnet.IP,
			Mask: a.conf.Subnet.Mask,
		}
		err := validateRangeIP(lastReservedIP, &subnet, a.start, a.end)
		if err == nil {
			startFromLastReservedIP = true
		}
	}
	if startFromLastReservedIP {
		startIP = a.nextIP(lastReservedIP)
		endIP = lastReservedIP
	} else {
		startIP = a.start
		endIP = a.end
	}
	return startIP, endIP
}
