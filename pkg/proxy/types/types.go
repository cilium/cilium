// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import "context"

// Proxy is any type which installs rules related to redirecting traffic to
// a proxy.
type Proxy interface {
	ReinstallRoutingRules(ctx context.Context, mtu int, ipsecEnabled, wireguardEnabled bool) error
}

type ProxyType string

const (
	// ProxyTypeHTTP specifies the Envoy HTTP proxy type
	ProxyTypeHTTP ProxyType = "http"
	// ProxyTypeTLS specifies the Envoy TLS proxy type
	ProxyTypeTLS ProxyType = "tls"
	// ProxyTypeDNS specifies the statically configured DNS proxy type
	ProxyTypeDNS ProxyType = "dns"
	// ProxyTypeCRD specifies a proxy configured via CiliumEnvoyConfig CRD
	ProxyTypeCRD ProxyType = "crd"

	DNSProxyName = "cilium-dns-egress"
)

func (p ProxyType) String() string {
	return (string)(p)
}
