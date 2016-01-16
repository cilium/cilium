package cilium_net_client

import (
	"errors"
)

var ErrConnectionFailed = errors.New("Cannot connect to the cilium-net-daemon. Is the cilium-net-daemon running on this host?")
