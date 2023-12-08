// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

const (
	// ProxyTypeAny represents the case where no proxy type is provided.
	ProxyTypeAny ProxyType = ""
	// ProxyTypeHTTP specifies the Envoy HTTP proxy type
	ProxyTypeHTTP ProxyType = "http"
	// ProxyTypeDNS specifies the statically configured DNS proxy type
	ProxyTypeDNS ProxyType = "dns"
	// ProxyTypeCRD specifies a proxy configured via CiliumEnvoyConfig CRD
	ProxyTypeCRD ProxyType = "crd"

	DNSProxyName = "cilium-dns-egress"
)

type ProxyType string

func (p ProxyType) String() string {
	return (string)(p)
}
