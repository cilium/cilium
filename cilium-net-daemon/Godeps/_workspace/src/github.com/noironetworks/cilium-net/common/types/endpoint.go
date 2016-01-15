package types

import (
	"net"
)

type Endpoint struct {
	ID            string           `json:id`
	LxcMAC        net.HardwareAddr `json:lxc-MAC`
	LxcIP         net.IP           `json:lxc-IP`
	Ifname        string           `json:interface-Name`
	NodeIP        net.IP           `json:node-IP`
	SecCtx        string           `json:sec-Ctx`
	DockerNetwork string           `json:docker-network`
}
