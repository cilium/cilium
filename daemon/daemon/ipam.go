//
// Copyright 2016 Authors of Cilium
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
//
package daemon

import (
	"fmt"
	"math/big"
	"net"

	"github.com/cilium/cilium/common/addressing"
	"github.com/cilium/cilium/common/ipam"
	"github.com/cilium/cilium/common/types"

	lnAPI "github.com/docker/libnetwork/ipams/remote/api"
	k8sAPI "k8s.io/kubernetes/pkg/api"
)

// allocateIPCNI allocates an IP for the CNI plugin.
func (d *Daemon) allocateIPCNI(cniReq ipam.IPAMReq) (*ipam.IPAMRep, error) {
	d.ipamConf.AllocatorMutex.Lock()
	defer d.ipamConf.AllocatorMutex.Unlock()

	if cniReq.IP != nil {
		var err error
		if cniReq.IP.To4() != nil {
			if d.conf.IPv4Enabled {
				err = d.ipamConf.IPv4Allocator.Allocate(*cniReq.IP)
			}
		} else {
			err = d.ipamConf.IPv6Allocator.Allocate(*cniReq.IP)
		}
		return nil, err
	}

	ipConf, err := d.ipamConf.IPv6Allocator.AllocateNext()
	if err != nil {
		return nil, err
	}

	v6Routes := []ipam.Route{}
	v4Routes := []ipam.Route{}
	for _, r := range d.ipamConf.IPAMConfig.Routes {
		rt := ipam.NewRoute(r.Dst, r.GW)
		if r.Dst.IP.To4() == nil {
			v6Routes = append(v6Routes, *rt)
		} else {
			v4Routes = append(v4Routes, *rt)
		}
	}

	ipamRep := &ipam.IPAMRep{
		IP6: &ipam.IPConfig{
			Gateway: d.conf.NodeAddress.IPv6Address.IP(),
			IP:      net.IPNet{IP: ipConf, Mask: addressing.ContainerIPv6Mask},
			Routes:  v6Routes,
		},
	}

	if d.ipamConf.IPv4Allocator != nil {
		ip4Conf, err := d.ipamConf.IPv4Allocator.AllocateNext()
		if err != nil {
			return nil, err
		}
		if d.ipamConf.IPv4Allocator != nil {
			ipamRep.IP4 = &ipam.IPConfig{
				Gateway: d.conf.NodeAddress.IPv4Address.IP(),
				IP:      net.IPNet{IP: ip4Conf, Mask: addressing.ContainerIPv4Mask},
				Routes:  v4Routes,
			}
		}
	}
	return ipamRep, nil
}

// releaseIPCNI releases an IP for the CNI plugin.
func (d *Daemon) releaseIPCNI(cniReq ipam.IPAMReq) error {
	d.ipamConf.AllocatorMutex.Lock()
	defer d.ipamConf.AllocatorMutex.Unlock()
	if cniReq.IP != nil {
		if cniReq.IP.To4() != nil {
			if d.conf.IPv4Enabled {
				return d.ipamConf.IPv4Allocator.Release(*cniReq.IP)
			}
		} else {
			return d.ipamConf.IPv6Allocator.Release(*cniReq.IP)
		}
	}
	return nil
}

// allocateIPLibnetwork allocates an IP for the libnetwork plugin.
func (d *Daemon) allocateIPLibnetwork(ln ipam.IPAMReq) (*ipam.IPAMRep, error) {
	d.ipamConf.AllocatorMutex.Lock()
	defer d.ipamConf.AllocatorMutex.Unlock()

	if ln.IP != nil {
		var err error
		if ln.IP.To4() != nil {
			if d.conf.IPv4Enabled {
				err = d.ipamConf.IPv4Allocator.Allocate(*ln.IP)
			}
		} else {
			err = d.ipamConf.IPv6Allocator.Allocate(*ln.IP)
		}
		return nil, err
	}

	switch ln.RequestAddressRequest.PoolID {
	case ipam.LibnetworkDefaultPoolV4:
		if d.ipamConf.IPv4Allocator != nil {
			ipConf, err := d.ipamConf.IPv4Allocator.AllocateNext()
			if err != nil {
				return nil, err
			}
			resp := ipam.IPAMRep{
				IP4: &ipam.IPConfig{
					IP: net.IPNet{IP: ipConf, Mask: addressing.ContainerIPv4Mask},
				},
			}
			log.Debugf("Docker requested us to use IPv4, %+v", resp.IP4.IP)
			return &resp, nil
		}
		return &ipam.IPAMRep{}, nil
	case ipam.LibnetworkDefaultPoolV6:
		ipConf, err := d.ipamConf.IPv6Allocator.AllocateNext()
		if err != nil {
			return nil, err
		}
		resp := ipam.IPAMRep{
			IP6: &ipam.IPConfig{
				IP: net.IPNet{IP: ipConf, Mask: addressing.ContainerIPv6Mask},
			},
		}
		log.Debugf("Docker requested us to use IPv6, %+v", resp.IP6.IP)
		return &resp, nil
	}

	log.Warning("Address request for unknown address pool: %s", ln.RequestAddressRequest.PoolID)

	return nil, nil
}

// releaseIPLibnetwork releases an IP for the libnetwork plugin.
func (d *Daemon) releaseIPLibnetwork(ln ipam.IPAMReq) error {
	log.Debugf("%+v", ln)

	d.ipamConf.AllocatorMutex.Lock()
	defer d.ipamConf.AllocatorMutex.Unlock()

	if ln.IP != nil {
		if ln.IP.To4() != nil {
			if d.conf.IPv4Enabled {
				return d.ipamConf.IPv4Allocator.Release(*ln.IP)
			}
		} else {
			return d.ipamConf.IPv6Allocator.Release(*ln.IP)
		}
	}

	switch ln.ReleaseAddressRequest.PoolID {
	case ipam.LibnetworkDefaultPoolV4:
		if d.conf.IPv4Enabled {
			ip := net.ParseIP(ln.ReleaseAddressRequest.Address)
			return d.ipamConf.IPv4Allocator.Release(ip)
		} else {
			return nil
		}
	case ipam.LibnetworkDefaultPoolV6:
		ip := net.ParseIP(ln.ReleaseAddressRequest.Address)
		return d.ipamConf.IPv6Allocator.Release(ip)
	}
	return nil
}

// AllocateIP allocates and returns a free IPv6 address with plugin configurations
// specific set up.
func (d *Daemon) AllocateIP(ipamType ipam.IPAMType, options ipam.IPAMReq) (*ipam.IPAMRep, error) {
	switch ipamType {
	case ipam.CNIIPAMType:
		return d.allocateIPCNI(options)
	case ipam.LibnetworkIPAMType:
		return d.allocateIPLibnetwork(options)
	}
	return nil, fmt.Errorf("unknown IPAM Type %s", ipamType)
}

// ReleaseIP releases an IP address in use by the specific IPAM type.
func (d *Daemon) ReleaseIP(ipamType ipam.IPAMType, options ipam.IPAMReq) error {
	if options.IP != nil && d.isReservedAddress(*options.IP) {
		return fmt.Errorf("refusing to release reserved IP address: %s", options.IP)
	}

	switch ipamType {
	case ipam.CNIIPAMType:
		return d.releaseIPCNI(options)
	case ipam.LibnetworkIPAMType:
		return d.releaseIPLibnetwork(options)
	}
	return fmt.Errorf("unknown IPAM Type %s", ipamType)
}

// getIPAMConfLibnetwork returns the Libnetwork specific IPAM configuration.
func (d *Daemon) getIPAMConfLibnetwork(ln ipam.IPAMReq) (*ipam.IPAMConfigRep, error) {
	if ln.RequestPoolRequest != nil {
		var poolID, pool, gw string

		if ln.RequestPoolRequest.V6 == false {
			poolID = ipam.LibnetworkDefaultPoolV4
			pool = ipam.LibnetworkDummyV4AllocPool
			gw = ipam.LibnetworkDummyV4Gateway
		} else {
			subnetGo := net.IPNet(d.ipamConf.IPAMConfig.Subnet)
			poolID = ipam.LibnetworkDefaultPoolV6
			pool = subnetGo.String()
			gw = d.ipamConf.IPAMConfig.Gateway.String() + "/128"
		}

		return &ipam.IPAMConfigRep{
			RequestPoolResponse: &lnAPI.RequestPoolResponse{
				PoolID: poolID,
				Pool:   pool,
				Data: map[string]string{
					"com.docker.network.gateway": gw,
				},
			},
		}, nil
	}

	ciliumV6Routes := []ipam.Route{}
	for _, r := range d.ipamConf.IPAMConfig.Routes {
		if r.Dst.IP.To4() == nil {
			ciliumRoute := ipam.NewRoute(r.Dst, r.GW)
			ciliumV6Routes = append(ciliumV6Routes, *ciliumRoute)
		}
	}

	rep := &ipam.IPAMConfigRep{
		IPAMConfig: &ipam.IPAMRep{
			IP6: &ipam.IPConfig{
				Gateway: d.ipamConf.IPAMConfig.Gateway,
				Routes:  ciliumV6Routes,
			},
		},
	}

	if d.conf.IPv4Enabled {
		ciliumV4Routes := []ipam.Route{}
		for _, r := range d.ipamConf.IPAMConfig.Routes {
			if r.Dst.IP.To4() != nil {
				ciliumRoute := ipam.NewRoute(r.Dst, r.GW)
				ciliumV4Routes = append(ciliumV4Routes, *ciliumRoute)
			}
		}

		rep.IPAMConfig.IP4 = &ipam.IPConfig{
			Gateway: d.conf.NodeAddress.IPv4Address.IP(),
			Routes:  ciliumV4Routes,
		}
	}

	return rep, nil
}

// GetIPAMConf returns the IPAM configuration details of the given IPAM type.
func (d *Daemon) GetIPAMConf(ipamType ipam.IPAMType, options ipam.IPAMReq) (*ipam.IPAMConfigRep, error) {
	switch ipamType {
	case ipam.LibnetworkIPAMType:
		return d.getIPAMConfLibnetwork(options)
	}
	return nil, fmt.Errorf("unknown IPAM Type %s", ipamType)
}

func (d *Daemon) isReservedAddress(ip net.IP) bool {
	return d.conf.IPv4Enabled && d.conf.NodeAddress.IPv4Address.IP().Equal(ip)
}

// DumpIPAM dumps in the form of a map, and only if debug is enabled, the list of
// reserved IPv4 and IPv6 addresses.
func (d *Daemon) DumpIPAM() map[string][]string {
	d.conf.OptsMU.RLock()
	isDebugActive := d.conf.Opts.IsEnabled(types.OptionDebug)
	d.conf.OptsMU.RUnlock()
	if !isDebugActive {
		return nil
	}

	d.ipamConf.AllocatorMutex.RLock()
	defer d.ipamConf.AllocatorMutex.RUnlock()

	allocv4 := []string{}
	if d.conf.IPv4Enabled {
		ralv4 := k8sAPI.RangeAllocation{}
		d.ipamConf.IPv4Allocator.Snapshot(&ralv4)
		origIP := big.NewInt(0).SetBytes(d.conf.NodeAddress.IPv4AllocRange().IP)
		v4Bits := big.NewInt(0).SetBytes(ralv4.Data)
		for i := 0; i < v4Bits.BitLen(); i++ {
			if v4Bits.Bit(i) != 0 {
				allocv4 = append(allocv4, net.IP(big.NewInt(0).Add(origIP, big.NewInt(int64(uint(i+1)))).Bytes()).String())
			}
		}
	}

	allocv6 := []string{}
	ralv6 := k8sAPI.RangeAllocation{}
	d.ipamConf.IPv6Allocator.Snapshot(&ralv6)
	origIP := big.NewInt(0).SetBytes(d.conf.NodeAddress.IPv6AllocRange().IP)
	v6Bits := big.NewInt(0).SetBytes(ralv6.Data)
	for i := 0; i < v6Bits.BitLen(); i++ {
		if v6Bits.Bit(i) != 0 {
			allocv6 = append(allocv6, net.IP(big.NewInt(0).Add(origIP, big.NewInt(int64(uint(i+1)))).Bytes()).String())
		}
	}

	return map[string][]string{
		"4": allocv4,
		"6": allocv6,
	}
}
