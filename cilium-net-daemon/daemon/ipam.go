package daemon

import (
	"fmt"
	"net"

	"github.com/noironetworks/cilium-net/common"
	"github.com/noironetworks/cilium-net/common/types"

	lnAPI "github.com/docker/libnetwork/ipams/remote/api"
)

// allocateIPCNI allocates an IP for the CNI plugin.
func allocateIPCNI(cniReq types.IPAMReq, ipamConf *types.IPAMConfig) (*types.IPAMRep, error) {
	ipamConf.IPAllocatorMU.Lock()
	defer ipamConf.IPAllocatorMU.Unlock()
	ipConf, err := ipamConf.IPAllocator.AllocateNext()
	if err != nil {
		return nil, err
	}

	ciliumRoutes := []types.Route{}
	for _, r := range ipamConf.IPAMConfig.Routes {
		ciliumRoute := types.NewRoute(r.Dst, r.GW)
		ciliumRoutes = append(ciliumRoutes, *ciliumRoute)
	}

	return &types.IPAMRep{
		IP6: &types.IPConfig{
			Gateway: ipamConf.IPAMConfig.Gateway,
			IP:      net.IPNet{IP: ipConf, Mask: common.ContainerIPv6Mask},
			Routes:  ciliumRoutes,
		},
	}, nil
}

// releaseIPCNI releases an IP for the CNI plugin.
func releaseIPCNI(cniReq types.IPAMReq, ipamConf *types.IPAMConfig) error {
	ipamConf.IPAllocatorMU.Lock()
	defer ipamConf.IPAllocatorMU.Unlock()
	return ipamConf.IPAllocator.Release(*cniReq.IP)
}

// allocateIPLibnetwork allocates an IP for the libnetwork plugin.
func allocateIPLibnetwork(ln types.IPAMReq, ipamConf *types.IPAMConfig) (*types.IPAMRep, error) {
	ipamConf.IPAllocatorMU.Lock()
	defer ipamConf.IPAllocatorMU.Unlock()
	if ln.RequestAddressRequest.PoolID == types.LibnetworkDefaultPoolV4 {
		log.Warningf("Docker requested us to use legacy IPv4, boooooring...")
	} else {
		ipConf, err := ipamConf.IPAllocator.AllocateNext()
		if err != nil {
			return nil, err
		}
		resp := types.IPAMRep{
			IP6: &types.IPConfig{
				IP: net.IPNet{IP: ipConf, Mask: common.ContainerIPv6Mask},
			},
		}
		log.Debugf("Docker requested us to use legacy IPv6, %+v", resp.IP6.IP)
		return &resp, nil
	}
	return nil, nil
}

// releaseIPLibnetwork releases an IP for the libnetwork plugin.
func releaseIPLibnetwork(ln types.IPAMReq, ipamConf *types.IPAMConfig) error {
	ipamConf.IPAllocatorMU.Lock()
	defer ipamConf.IPAllocatorMU.Unlock()
	if ln.RequestAddressRequest.PoolID == types.LibnetworkDefaultPoolV4 {
		/* Ignore */
	} else {
		return ipamConf.IPAllocator.Release(*ln.IP)
	}
	return nil
}

// AllocateIP allocates and returns a free IPv6 address with plugin configurations
// specific set up.
func (d *Daemon) AllocateIP(ipamType types.IPAMType, options types.IPAMReq) (*types.IPAMRep, error) {
	switch ipamType {
	case types.CNIIPAMType:
		return allocateIPCNI(options, d.ipamConf[types.CNIIPAMType])
	case types.LibnetworkIPAMType:
		return allocateIPLibnetwork(options, d.ipamConf[types.LibnetworkIPAMType])
	}
	return nil, fmt.Errorf("unknown IPAM Type %s", ipamType)
}

// ReleaseIP releases an IP address in use by the specific IPAM type.
func (d *Daemon) ReleaseIP(ipamType types.IPAMType, options types.IPAMReq) error {
	switch ipamType {
	case types.CNIIPAMType:
		return releaseIPCNI(options, d.ipamConf[types.CNIIPAMType])
	case types.LibnetworkIPAMType:
		return releaseIPLibnetwork(options, d.ipamConf[types.LibnetworkIPAMType])
	}
	return fmt.Errorf("unknown IPAM Type %s", ipamType)
}

// getIPAMConfLibnetwork returns the Libnetwork specific IPAM configuration.
func getIPAMConfLibnetwork(ln types.IPAMReq, ipamConf *types.IPAMConfig) (*types.IPAMConfigRep, error) {
	if ln.RequestPoolRequest != nil {
		var poolID, pool, gw string

		if ln.RequestPoolRequest.V6 == false {
			log.Warningf("Docker requested us to use legacy IPv4, boooooring...")
			poolID = types.LibnetworkDefaultPoolV4
			pool = types.LibnetworkDummyV4AllocPool
			gw = types.LibnetworkDummyV4Gateway
		} else {
			subnetGo := net.IPNet(ipamConf.IPAMConfig.Subnet)
			poolID = types.LibnetworkDefaultPoolV6
			pool = subnetGo.String()
			gw = ipamConf.IPAMConfig.Gateway.String() + "/128"
		}

		return &types.IPAMConfigRep{
			RequestPoolResponse: &lnAPI.RequestPoolResponse{
				PoolID: poolID,
				Pool:   pool,
				Data: map[string]string{
					"com.docker.network.gateway": gw,
				},
			},
		}, nil
	}

	ciliumRoutes := []types.Route{}
	for _, r := range ipamConf.IPAMConfig.Routes {
		ciliumRoute := types.NewRoute(r.Dst, r.GW)
		ciliumRoutes = append(ciliumRoutes, *ciliumRoute)
	}

	return &types.IPAMConfigRep{
		IPAMConfig: &types.IPAMRep{
			IP6: &types.IPConfig{
				Gateway: ipamConf.IPAMConfig.Gateway,
				Routes:  ciliumRoutes,
			},
		},
	}, nil
}

// GetIPAMConf returns the IPAM configuration details of the given IPAM type.
func (d *Daemon) GetIPAMConf(ipamType types.IPAMType, options types.IPAMReq) (*types.IPAMConfigRep, error) {
	switch ipamType {
	case types.LibnetworkIPAMType:
		return getIPAMConfLibnetwork(options, d.ipamConf[types.LibnetworkIPAMType])
	}
	return nil, fmt.Errorf("unknown IPAM Type %s", ipamType)
}
