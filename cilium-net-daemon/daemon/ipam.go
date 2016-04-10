package daemon

import (
	"errors"
	"net"

	"github.com/noironetworks/cilium-net/common/types"

	"github.com/noironetworks/cilium-net/Godeps/_workspace/src/github.com/appc/cni/plugins/ipam/host-local/backend"
	"github.com/noironetworks/cilium-net/Godeps/_workspace/src/github.com/appc/cni/plugins/ipam/host-local/backend/disk"
)

// AllocateIPs allocates and returns a free IPv6 address with its routes set up.
func (d *Daemon) AllocateIPs(containerID string) (*types.IPAMConfig, error) {
	store, err := disk.New(d.ipamConf.Name)
	if err != nil {
		return nil, err
	}
	defer store.Close()

	allocator, err := backend.NewIPAllocator(&d.ipamConf, store)
	if err != nil {
		return nil, err
	}

	ipConf, err := allocator.Get(containerID)
	if err != nil {
		return nil, err
	}

	switch len(ipConf.IP.IP) {
	case net.IPv6len:
		ciliumRoutes := []types.Route{}
		for _, r := range d.ipamConf.Routes {
			ciliumRoute := types.NewRoute(r.Dst, r.GW)
			ciliumRoutes = append(ciliumRoutes, *ciliumRoute)
		}

		return &types.IPAMConfig{
			IP6: &types.IPConfig{
				Gateway: d.ipamConf.Gateway,
				IP:      ipConf.IP,
				Routes:  ciliumRoutes,
			},
		}, nil
	}
	allocator.Release(containerID)
	return nil, errors.New("We don't support IPv4, do we?")
}

// ReleaseIPs Releases the IP being used by containerID.
func (d *Daemon) ReleaseIPs(containerID string) error {
	store, err := disk.New(d.ipamConf.Name)
	if err != nil {
		return err
	}
	defer store.Close()

	allocator, err := backend.NewIPAllocator(&d.ipamConf, store)
	if err != nil {
		return err
	}

	return allocator.Release(containerID)
}
