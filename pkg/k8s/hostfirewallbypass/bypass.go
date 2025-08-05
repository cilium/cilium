// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package hostfirewallbypass

import (
	"net"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/k8s/client"
)

type k8sHostFirewallBypass struct{}

func NewK8sHostFirewallBypass(params Params) client.ConfigureK8sClientsetDialer {
	if params.DaemonConfig != nil && !params.DaemonConfig.EnableHostFirewall {
		return nil
	}
	if params.LocalConfig.EnableK8sHostFirewallBypass {
		return &k8sHostFirewallBypass{}
	} else {
		return nil
	}
}

// Sets SO_MARK so that connections to kube-apiserver bypass host firewall and DNS proxy
func (*k8sHostFirewallBypass) ConfigureK8sClientsetDialer(dialer *net.Dialer) {
	dialer.Control = setProxyEgressMark
	dialer.Resolver = &net.Resolver{
		PreferGo: true,
		Dial: (&net.Dialer{
			Control: setProxyEgressMark,
		}).DialContext,
	}
}

func setProxyEgressMark(network, address string, c syscall.RawConn) error {
	var soerr error
	if err := c.Control(func(su uintptr) {
		mark := linux_defaults.MakeMagicMark(linux_defaults.MagicMarkEgress, identity.ReservedIdentityHost)
		soerr = unix.SetsockoptUint64(int(su), unix.SOL_SOCKET, unix.SO_MARK, uint64(mark))
	}); err != nil {
		return err
	}
	return soerr
}
