// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package resource

import (
	// Imports for Envoy extensions not used directly from Cilium Agent, but that we want to
	// be registered for use in Cilium Envoy Config CRDs. This can be used for any downstream
	// project that wants to use Cilium Envoy Config CRDs to generate Envoy configs.
	_ "github.com/cilium/proxy/go/envoy/config/cluster/v3"
	_ "github.com/cilium/proxy/go/envoy/config/core/v3"
	_ "github.com/cilium/proxy/go/envoy/config/endpoint/v3"
	_ "github.com/cilium/proxy/go/envoy/config/listener/v3"
	_ "github.com/cilium/proxy/go/envoy/config/route/v3"
	_ "github.com/cilium/proxy/go/envoy/extensions/clusters/dynamic_forward_proxy/v3"
	_ "github.com/cilium/proxy/go/envoy/extensions/filters/http/dynamic_forward_proxy/v3"
	_ "github.com/cilium/proxy/go/envoy/extensions/filters/http/ext_authz/v3"
	_ "github.com/cilium/proxy/go/envoy/extensions/filters/http/local_ratelimit/v3"
	_ "github.com/cilium/proxy/go/envoy/extensions/filters/http/ratelimit/v3"
	_ "github.com/cilium/proxy/go/envoy/extensions/filters/http/set_metadata/v3"
	_ "github.com/cilium/proxy/go/envoy/extensions/filters/network/connection_limit/v3"
	_ "github.com/cilium/proxy/go/envoy/extensions/filters/network/ext_authz/v3"
	_ "github.com/cilium/proxy/go/envoy/extensions/filters/network/http_connection_manager/v3"
	_ "github.com/cilium/proxy/go/envoy/extensions/filters/network/local_ratelimit/v3"
	_ "github.com/cilium/proxy/go/envoy/extensions/filters/network/ratelimit/v3"
	_ "github.com/cilium/proxy/go/envoy/extensions/filters/network/sni_cluster/v3"
	_ "github.com/cilium/proxy/go/envoy/extensions/filters/network/sni_dynamic_forward_proxy/v3"
	_ "github.com/cilium/proxy/go/envoy/extensions/filters/network/tcp_proxy/v3"
	_ "github.com/cilium/proxy/go/envoy/extensions/transport_sockets/tls/v3"
	_ "github.com/cilium/proxy/go/envoy/extensions/upstreams/http/http/v3"
	_ "github.com/cilium/proxy/go/envoy/extensions/upstreams/http/tcp/v3"
)
