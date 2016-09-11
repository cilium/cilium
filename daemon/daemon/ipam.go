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
	"net"

	"github.com/cilium/cilium/common/addressing"
	"github.com/cilium/cilium/common/ipam"

	lnAPI "github.com/docker/libnetwork/ipams/remote/api"
)

// allocateIPCNI allocates an IP for the CNI plugin.
func (d *Daemon) allocateIPCNI(cniReq ipam.IPAMReq, ipamConf *ipam.IPAMConfig) (*ipam.IPAMRep, error) {
	ipamConf.AllocatorMutex.Lock()
	defer ipamConf.AllocatorMutex.Unlock()

	if cniReq.IP != nil {
		err := ipamConf.IPv6Allocator.Allocate(*cniReq.IP)
		return nil, err
	}

	ipConf, err := ipamConf.IPv6Allocator.AllocateNext()
	if err != nil {
		return nil, err
	}

	v6Routes := []ipam.Route{}
	v4Routes := []ipam.Route{}
	for _, r := range ipamConf.IPAMConfig.Routes {
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

	if ipamConf.IPv4Allocator != nil {
		ip4Conf, err := ipamConf.IPv4Allocator.AllocateNext()
		if err != nil {
			return nil, err
		}
		if ipamConf.IPv4Allocator != nil {
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
func releaseIPCNI(cniReq ipam.IPAMReq, ipamConf *ipam.IPAMConfig) error {
	ipamConf.AllocatorMutex.Lock()
	defer ipamConf.AllocatorMutex.Unlock()

	return ipamConf.IPv6Allocator.Release(*cniReq.IP)
}

// allocateIPLibnetwork allocates an IP for the libnetwork plugin.
func allocateIPLibnetwork(ln ipam.IPAMReq, ipamConf *ipam.IPAMConfig) (*ipam.IPAMRep, error) {
	ipamConf.AllocatorMutex.Lock()
	defer ipamConf.AllocatorMutex.Unlock()

	if ln.IP != nil {
		err := ipamConf.IPv6Allocator.Allocate(*ln.IP)
		return nil, err
	}

	switch ln.RequestAddressRequest.PoolID {
	case ipam.LibnetworkDefaultPoolV4:
		if ipamConf.IPv4Allocator != nil {
			ipConf, err := ipamConf.IPv4Allocator.AllocateNext()
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
		ipConf, err := ipamConf.IPv6Allocator.AllocateNext()
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
func releaseIPLibnetwork(ln ipam.IPAMReq, ipamConf *ipam.IPAMConfig) error {
	log.Debugf("%+v", ln)

	ipamConf.AllocatorMutex.Lock()
	defer ipamConf.AllocatorMutex.Unlock()

	if ln.IP != nil {
		return ipamConf.IPv6Allocator.Release(*ln.IP)
	}

	switch ln.ReleaseAddressRequest.PoolID {
	case ipam.LibnetworkDefaultPoolV4:
		ip := net.ParseIP(ln.ReleaseAddressRequest.Address)
		return ipamConf.IPv4Allocator.Release(ip)
	case ipam.LibnetworkDefaultPoolV6:
		ip := net.ParseIP(ln.ReleaseAddressRequest.Address)
		return ipamConf.IPv6Allocator.Release(ip)
	}
	return nil
}

// AllocateIP allocates and returns a free IPv6 address with plugin configurations
// specific set up.
func (d *Daemon) AllocateIP(ipamType ipam.IPAMType, options ipam.IPAMReq) (*ipam.IPAMRep, error) {
	switch ipamType {
	case ipam.CNIIPAMType:
		return d.allocateIPCNI(options, d.ipamConf)
	case ipam.LibnetworkIPAMType:
		return allocateIPLibnetwork(options, d.ipamConf)
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
		return releaseIPCNI(options, d.ipamConf)
	case ipam.LibnetworkIPAMType:
		return releaseIPLibnetwork(options, d.ipamConf)
	}
	return fmt.Errorf("unknown IPAM Type %s", ipamType)
}

// getIPAMConfLibnetwork returns the Libnetwork specific IPAM configuration.
func getIPAMConfLibnetwork(ln ipam.IPAMReq, ipamConf *ipam.IPAMConfig) (*ipam.IPAMConfigRep, error) {
	if ln.RequestPoolRequest != nil {
		var poolID, pool, gw string

		if ln.RequestPoolRequest.V6 == false {
			poolID = ipam.LibnetworkDefaultPoolV4
			pool = ipam.LibnetworkDummyV4AllocPool
			gw = ipam.LibnetworkDummyV4Gateway
		} else {
			subnetGo := net.IPNet(ipamConf.IPAMConfig.Subnet)
			poolID = ipam.LibnetworkDefaultPoolV6
			pool = subnetGo.String()
			gw = ipamConf.IPAMConfig.Gateway.String() + "/128"
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

	ciliumRoutes := []ipam.Route{}
	for _, r := range ipamConf.IPAMConfig.Routes {
		ciliumRoute := ipam.NewRoute(r.Dst, r.GW)
		ciliumRoutes = append(ciliumRoutes, *ciliumRoute)
	}

	return &ipam.IPAMConfigRep{
		IPAMConfig: &ipam.IPAMRep{
			IP6: &ipam.IPConfig{
				Gateway: ipamConf.IPAMConfig.Gateway,
				Routes:  ciliumRoutes,
			},
		},
	}, nil
}

// GetIPAMConf returns the IPAM configuration details of the given IPAM type.
func (d *Daemon) GetIPAMConf(ipamType ipam.IPAMType, options ipam.IPAMReq) (*ipam.IPAMConfigRep, error) {
	switch ipamType {
	case ipam.LibnetworkIPAMType:
		return getIPAMConfLibnetwork(options, d.ipamConf)
	}
	return nil, fmt.Errorf("unknown IPAM Type %s", ipamType)
}

func (d *Daemon) isReservedAddress(ip net.IP) bool {
	return d.conf.IPv4Enabled && d.conf.NodeAddress.IPv4Address.IP().Equal(ip)
}
