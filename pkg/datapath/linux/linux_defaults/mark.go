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
// Kubernetes Mark (4 bits; see MagicMarkWireGuardEncrypted for usage of some of
// K8s mark space):
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

	MagicMarkSNATDone int = 0x0300

	// MagicMarkOverlay is set by the to-overlay program, and can be used
	// to identify cilium-managed overlay traffic.
	MagicMarkOverlay int = 0x0400

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

	// MagicMarkWireGuardEncrypted is set by the WireGuard tunnel device
	// in order to indicate that a packet has been encrypted, and that there
	// is no need to forward it again to the WG tunnel netdev.
	//
	// The mark invades the K8s mark space described above. This is because
	// some packets might carry a security identity which is indicated with
	// MagicMarkIdentity which takes all 4 bits. The LSB bit which we take
	// from the K8s space is not used, so this is fine). I.e., the LSB bit is
	// 0x1000, and the K8s marks are 0x4000 and 0x8000. So both are not
	// interfering with that bit.
	MagicMarkWireGuardEncrypted int = 0x1E00

	// MagicMarkDecrypt is the packet mark used to indicate the datapath needs
	// to decrypt a packet.
	MagicMarkDecrypt = 0x0D00

	// MagicMarkDecryptedOverlay indicates to the datapath that the packet
	// was IPsec decrypted and now contains a vxlan header.
	//
	// When this mark is present on a packet it indicates that overlay traffic
	// was decrypted by XFRM and should be forwarded to a tunnel device for
	// decapsulation.
	MagicMarkDecryptedOverlay = 0x1D00

	// MagicMarkEncrypt is the packet mark to use to indicate datapath
	// needs to encrypt a packet.
	MagicMarkEncrypt = 0x0E00
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
