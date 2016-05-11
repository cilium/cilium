package daemon

import (
	"errors"
	"fmt"
	"net"

	"github.com/noironetworks/cilium-net/common/types"

	"github.com/appc/cni/plugins/ipam/host-local/backend"
	hb "github.com/appc/cni/plugins/ipam/host-local/backend"
	"github.com/appc/cni/plugins/ipam/host-local/backend/disk"
)

func allocateIPCNI(cniReq types.IPAMReq, ipamConf hb.IPAMConfig) (*types.IPAMConfig, error) {
	store, err := disk.New(ipamConf.Name)
	if err != nil {
		return nil, err
	}
	defer store.Close()

	allocator, err := backend.NewIPAllocator(&ipamConf, store)
	if err != nil {
		return nil, err
	}

	ipConf, err := allocator.Get(cniReq.ContainerID)
	if err != nil {
		return nil, err
	}

	switch len(ipConf.IP.IP) {
	case net.IPv6len:
		// little workaround for the CIDR returned by the allocator
		ipConf.IP.Mask = net.CIDRMask(128, 128)
		ciliumRoutes := []types.Route{}
		for _, r := range ipamConf.Routes {
			ciliumRoute := types.NewRoute(r.Dst, r.GW)
			ciliumRoutes = append(ciliumRoutes, *ciliumRoute)
		}

		return &types.IPAMConfig{
			IP6: &types.IPConfig{
				Gateway: ipamConf.Gateway,
				IP:      ipConf.IP,
				Routes:  ciliumRoutes,
			},
		}, nil
	}
	allocator.Release(cniReq.ContainerID)
	return nil, errors.New("We don't support IPv4, do we?")
}

func releaseIPCNI(cniReq types.IPAMReq, ipamConf hb.IPAMConfig) error {
	store, err := disk.New(ipamConf.Name)
	if err != nil {
		return err
	}
	defer store.Close()

	allocator, err := backend.NewIPAllocator(&ipamConf, store)
	if err != nil {
		return err
	}
	return allocator.Release(cniReq.ContainerID)
}

// AllocateIPs allocates and returns a free IPv6 address with its routes set up.
func (d *Daemon) AllocateIP(ipamType types.IPAMType, options types.IPAMReq) (*types.IPAMConfig, error) {
	switch ipamType {
	case types.CNIIPAMType:
		return allocateIPCNI(options, d.ipamConf[types.CNIIPAMType])
	}
	return nil, fmt.Errorf("unknown IPAM Type %s", ipamType)
}

// ReleaseIPs Releases the IP being used by containerID.
func (d *Daemon) ReleaseIP(ipamType types.IPAMType, options types.IPAMReq) error {
	switch ipamType {
	case types.CNIIPAMType:
		return releaseIPCNI(options, d.ipamConf[types.CNIIPAMType])
	}
	return fmt.Errorf("unknown IPAM Type %s", ipamType)
}
