package daemon

import (
	"github.com/noironetworks/cilium-net/common/types"
)

func (d *Daemon) Ping() (*types.PingResponse, error) {
	return &types.PingResponse{
		NodeAddress: d.conf.NodeAddress.String(),
	}, nil
}
