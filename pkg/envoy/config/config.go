// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/time"
)

type ProxyConfig struct {
	DisableEnvoyVersionCheck            bool
	ProxyPrometheusPort                 int
	ProxyAdminPort                      int
	EnvoyLog                            string
	EnvoyAccessLogBufferSize            uint
	EnvoyDefaultLogLevel                string
	EnvoyBaseID                         uint64
	EnvoyKeepCapNetbindservice          bool
	ProxyConnectTimeout                 uint
	ProxyInitialFetchTimeout            uint
	ProxyGID                            uint
	ProxyMaxActiveDownstreamConnections int64
	ProxyMaxRequestsPerConnection       int
	ProxyMaxConnectionDurationSeconds   int
	ProxyIdleTimeoutSeconds             int
	ProxyMaxConcurrentRetries           uint32
	ProxyClusterMaxConnections          uint32
	ProxyClusterMaxRequests             uint32
	HTTPNormalizePath                   bool
	HTTPRequestTimeout                  uint
	HTTPIdleTimeout                     uint
	HTTPMaxGRPCTimeout                  uint
	HTTPRetryCount                      uint
	HTTPRetryTimeout                    uint
	HTTPStreamIdleTimeout               uint
	UseFullTLSContext                   bool
	ProxyXffNumTrustedHopsIngress       uint32
	ProxyXffNumTrustedHopsEgress        uint32
	EnvoyPolicyRestoreTimeout           time.Duration
	EnvoyHTTPUpstreamLingerTimeout      int
}

func (r ProxyConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool("disable-envoy-version-check", false, "Do not perform Envoy version check")
	flags.Int("proxy-prometheus-port", 0, "Port to serve Envoy metrics on. Default 0 (disabled).")
	flags.Int("proxy-admin-port", 0, "Port to serve Envoy admin interface on.")
	flags.Uint("envoy-access-log-buffer-size", 4096, "Envoy access log buffer size in bytes")
	flags.String("envoy-log", "", "Path to a separate Envoy log file, if any")
	flags.String("envoy-default-log-level", "", "Default log level of Envoy application log that is configured if Cilium debug / verbose logging isn't enabled. If not defined, the default log level of the Cilium Agent is used.")
	flags.Uint64("envoy-base-id", 0, "Envoy base ID")
	flags.Bool("envoy-keep-cap-netbindservice", false, "Keep capability NET_BIND_SERVICE for Envoy process")
	flags.Uint("proxy-connect-timeout", 2, "Time after which a TCP connect attempt is considered failed unless completed (in seconds)")
	flags.Uint("proxy-initial-fetch-timeout", 30, "Time after which an xDS stream is considered timed out (in seconds)")
	flags.Uint("proxy-gid", 1337, "Group ID for proxy control plane sockets.")
	flags.Int64("proxy-max-active-downstream-connections", 50000, "Set Envoy HTTP option max_active_downstream_connections")
	flags.Int("proxy-max-requests-per-connection", 0, "Set Envoy HTTP option max_requests_per_connection. Default 0 (disable)")
	flags.Int("proxy-max-connection-duration-seconds", 0, "Set Envoy HTTP option max_connection_duration seconds. Default 0 (disable)")
	flags.Int("proxy-idle-timeout-seconds", 60, "Set Envoy upstream HTTP idle connection timeout in seconds. Does not apply to connections with pending requests.")
	flags.Uint32("proxy-max-concurrent-retries", 128, "Maximum number of concurrent retries on Envoy clusters")
	flags.Uint32("proxy-cluster-max-connections", 1024, "Maximum number of connections on Envoy clusters")
	flags.Uint32("proxy-cluster-max-requests", 1024, "Maximum number of requests on Envoy clusters")
	flags.Bool("http-normalize-path", true, "Use Envoy HTTP path normalization options, which currently includes RFC 3986 path normalization, Envoy merge slashes option, and unescaping and redirecting for paths that contain escaped slashes. These are necessary to keep path based access control functional, and should not interfere with normal operation. Set this to false only with caution.")
	flags.Uint("http-request-timeout", 60*60, "Time after which a forwarded HTTP request is considered failed unless completed (in seconds); Use 0 for unlimited")
	flags.Uint("http-idle-timeout", 0, "Time after which a non-gRPC HTTP stream is considered failed unless traffic in the stream has been processed (in seconds); defaults to 0 (unlimited)")
	flags.Uint("http-max-grpc-timeout", 0, "Time after which a forwarded gRPC request is considered failed unless completed (in seconds). A \"grpc-timeout\" header may override this with a shorter value; defaults to 0 (unlimited)")
	flags.Uint("http-retry-count", 3, "Number of retries performed after a forwarded request attempt fails")
	flags.Uint("http-retry-timeout", 0, "Time after which a forwarded but uncompleted request is retried (connection failures are retried immediately); defaults to 0 (never)")
	flags.Uint("http-stream-idle-timeout", 5*60, "Set Envoy the amount of time in seconds that the connection manager will allow a stream to exist with no upstream or downstream activity.")
	// This should default to false in 1.16+ (i.e., we don't implement buggy behaviour) and true in 1.15 and earlier (i.e., we keep compatibility with an existing bug).
	flags.Bool("use-full-tls-context", false, "If enabled, persist ca.crt keys into the Envoy config even in a terminatingTLS block on an L7 Cilium Policy. This is to enable compatibility with previously buggy behaviour. This flag is deprecated and will be removed in a future release.")
	flags.Uint32("proxy-xff-num-trusted-hops-ingress", 0, "Number of trusted hops regarding the x-forwarded-for and related HTTP headers for the ingress L7 policy enforcement Envoy listeners.")
	flags.Uint32("proxy-xff-num-trusted-hops-egress", 0, "Number of trusted hops regarding the x-forwarded-for and related HTTP headers for the egress L7 policy enforcement Envoy listeners.")
	flags.Duration("envoy-policy-restore-timeout", 3*time.Minute, "Maximum time to wait for endpoint policy restoration before starting serving resources to Envoy")
	flags.Int("envoy-http-upstream-linger-timeout", -1, "Time in seconds to block Envoy worker thread while an upstream HTTP connection is closing. "+
		"If set to 0, the connection is closed immediately (with TCP RST). If set to -1, the connection is closed asynchronously in the background.")
}

type SecretSyncConfig struct {
	EnvoySecretsNamespace string

	EnableIngressController bool
	IngressSecretsNamespace string

	EnableGatewayAPI           bool
	GatewayAPISecretsNamespace string
}

func (r SecretSyncConfig) Flags(flags *pflag.FlagSet) {
	flags.String("envoy-secrets-namespace", r.EnvoySecretsNamespace, "EnvoySecretsNamespace is the namespace having secrets used by CEC")
	flags.Bool("enable-ingress-controller", false, "Enables Envoy secret sync for Ingress controller related TLS secrets")
	flags.String("ingress-secrets-namespace", r.IngressSecretsNamespace, "IngressSecretsNamespace is the namespace having tls secrets used by CEC, originating from Ingress controller")
	flags.Bool("enable-gateway-api", false, "Enables Envoy secret sync for Gateway API related TLS secrets")
	flags.String("gateway-api-secrets-namespace", r.GatewayAPISecretsNamespace, "GatewayAPISecretsNamespace is the namespace having tls secrets used by CEC, originating from Gateway API")
}
