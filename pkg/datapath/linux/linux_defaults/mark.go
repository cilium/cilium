// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package linux_defaults

// The skb mark is used to transmit both identity and special markers to
// identify traffic from and to proxies. The mark field is being used in the
// following way:
//
//	 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
//	+-------------------------------+-------+-------+---------------+
//	|L L L L L L L L L L L L L L L L|R R R R|M M M M|U U U U U U U U|
//	+-------------------------------+-------+-------+---------------+
//	 identity                        k8s     mark    identity
//
// Identity (24 bits):
//
//	+-----------------------------------------------+
//	|U U U U U U U U|L L L L L L L L L L L L L L L L|
//	+-----------------------------------------------+
//	 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4
//
// Kubernetes Mark (4 bits):
// R R R R
// 0 1 0 0  Masquerade
// 1 0 0 0  Drop
//
// Cilium Mark (4 bits):
// M M M M
// (see MARK_MAGIC_* in bpf/lib/common.h)
const (
	// MagicMarkHostMask can be used to fetch the host/proxy-relevant magic
	// bits from a mark.
	MagicMarkHostMask int = 0x0F00
	// MagicMarkProxyMask can be used to fetch the proxy-relevant magic
	// bits from a mark.
	MagicMarkProxyMask int = 0x0E00
	// MagicMarkProxyNoIDMask can be used to fetch the proxy-relevant magic
	// bits from a mark for proxy reply traffic.
	MagicMarkProxyNoIDMask int = 0xFFFFFEFF
	// MagicMarkIsProxyEPID can be used in conjunction with
	// MagicMarkProxyMask to determine whether the mark is indicating that
	// traffic is sourced from a proxy prior to endpoint policy enforcement.
	MagicMarkIsProxyEPID int = 0x0800
	// MagicMarkIsProxy can be used in conjunction with MagicMarkProxyMask
	// to determine whether the mark is indicating that traffic is sourced
	// from a proxy.
	MagicMarkIsProxy int = 0x0A00
	// MagicMarkIsToProxy can be used in conjunction with MagicMarkHostMask
	// to determine whether the mark is indicating that traffic is destined
	// to a proxy.
	MagicMarkIsToProxy uint32 = 0x0200

	// MagicMarkProxyEgressEPID determines that the traffic is sourced from
	// the proxy which is capturing traffic before it is subject to egress
	// policy enforcement that must be done after the proxy. The identity
	// stored in the mark is source Endpoint ID.
	//
	// Note that this is not used from Go code, but is included here to
	// document this pattern. This must match the definition of
	// MARK_MAGIC_PROXY_EGRESS_EPID in the datapath, and the Envoy code in
	// cilium/proxy/cilium/bpf_metadata.cc
	MagicMarkProxyEgressEPID int = 0x0900

	// MagicMarkIngress determines that the traffic is sourced from the
	// proxy which is applying Ingress policy
	MagicMarkIngress int = 0x0A00
	// MagicMarkEgress determines that the traffic is sourced from the
	// proxy which is applying Egress policy
	MagicMarkEgress int = 0x0B00

	// MagicMarkHost determines that the traffic is sourced from the local
	// host and not from a proxy.
	MagicMarkHost int = 0x0C00

	// MagicMarkIdentity determines that the traffic carries a security
	// identity in the skb->mark
	MagicMarkIdentity int = 0x0F00

	// MagicMarkK8sMasq determines that the traffic should be masqueraded
	// by kube-proxy in kubernetes environments.
	MagicMarkK8sMasq int = 0x4000
	// MagicMarkK8sDrop determines that the traffic should be dropped in
	// kubernetes environments.
	MagicMarkK8sDrop int = 0x8000
)

// getMagicMark returns the magic marker with which each packet must be marked.
// The mark is different depending on whether the proxy is injected at ingress
// or egress.
func GetMagicProxyMark(isIngress bool, identity int) int {
	var mark int

	if isIngress {
		mark = MagicMarkIngress
	} else {
		mark = MagicMarkEgress
	}

	if identity != 0 {
		mark |= (identity >> 16) & 0xFF
		mark |= (identity & 0xFFFF) << 16
	}

	return mark
}
