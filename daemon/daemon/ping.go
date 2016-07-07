package daemon

import (
	"github.com/noironetworks/cilium-net/common/types"
)

func (d *Daemon) Ping() (*types.PingResponse, error) {
	d.conf.OptsMU.RLock()
	defer d.conf.OptsMU.RUnlock()
	return &types.PingResponse{
		NodeAddress: d.conf.NodeAddress.String(),
		Opts:        d.conf.Opts,
	}, nil
}
