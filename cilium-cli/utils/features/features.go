// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package features

import (
	"fmt"
	"strings"

	"golang.org/x/exp/maps"

	"github.com/blang/semver/v4"
	"github.com/cilium/cilium/pkg/versioncheck"
	v1 "k8s.io/api/core/v1"
)

const (
	CNIChaining        Feature = "cni-chaining"
	MonitorAggregation Feature = "monitor-aggregation"
	L7Proxy            Feature = "l7-proxy"
	HostFirewall       Feature = "host-firewall"
	ICMPPolicy         Feature = "icmp-policy"
	Tunnel             Feature = "tunnel"
	EndpointRoutes     Feature = "endpoint-routes"

	KPRMode                Feature = "kpr-mode"
	KPRExternalIPs         Feature = "kpr-external-ips"
	KPRGracefulTermination Feature = "kpr-graceful-termination"
	KPRHostPort            Feature = "kpr-hostport"
	KPRSocketLB            Feature = "kpr-socket-lb"
	KPRNodePort            Feature = "kpr-nodeport"
	KPRSessionAffinity     Feature = "kpr-session-affinity"

	HostPort Feature = "host-port"

	NodeWithoutCilium Feature = "node-without-cilium"

	HealthChecking Feature = "health-checking"

	EncryptionPod  Feature = "encryption-pod"
	EncryptionNode Feature = "encryption-node"

	IPv4 Feature = "ipv4"
	IPv6 Feature = "ipv6"

	Flavor Feature = "flavor"

	SecretBackendK8s Feature = "secret-backend-k8s"

	CNP Feature = "cilium-network-policy"
	KNP Feature = "k8s-network-policy"

	// Whether or not CIDR selectors can match node IPs
	CIDRMatchNodes Feature = "cidr-match-nodes"

	AuthSpiffe Feature = "mutual-auth-spiffe"

	IngressController Feature = "ingress-controller"

	EgressGateway Feature = "enable-ipv4-egress-gateway"
	GatewayAPI    Feature = "enable-gateway-api"

	EnableEnvoyConfig Feature = "enable-envoy-config"

	WireguardEncapsulate Feature = "wireguard-encapsulate"
)

// Feature is the name of a Cilium Feature (e.g. l7-proxy, cni chaining mode etc)
type Feature string

// Status describes the status of a Feature. Some features are either
// turned on or off (c.f. Enabled), while others additionally might include a
// Mode string which provides more information about in what mode a
// particular Feature is running ((e.g. when running with CNI chaining,
// Enabled will be true, and the Mode string will additionally contain the name
// of the chained CNI).
type Status struct {
	Enabled bool
	Mode    string
}

func (s Status) String() string {
	str := "Disabled"
	if s.Enabled {
		str = "Enabled"
	}

	if len(s.Mode) == 0 {
		return str
	}

	return fmt.Sprintf("%s:%s", str, s.Mode)
}

// Set contains the Status of a collection of Features.
type Set map[Feature]Status

// MatchRequirements returns true if the Set fs satisfies all the
// requirements in reqs. Returns true for empty requirements list.
func (fs Set) MatchRequirements(reqs ...Requirement) (bool, string) {
	for _, req := range reqs {
		status := fs[req.Feature]
		if req.requiresEnabled && (req.enabled != status.Enabled) {
			return false, fmt.Sprintf("Feature %s is disabled", req.Feature)
		}
		if req.requiresMode && (req.mode != status.Mode) {
			return false, fmt.Sprintf("requires Feature %s mode %s, got %s", req.Feature, req.mode, status.Mode)
		}
	}

	return true, ""
}

// IPFamilies returns the list of enabled IP families.
func (fs Set) IPFamilies() []IPFamily {
	var families []IPFamily

	if match, _ := fs.MatchRequirements(RequireEnabled(IPv4)); match {
		families = append(families, IPFamilyV4)
	}

	if match, _ := fs.MatchRequirements(RequireEnabled(IPv6)); match {
		families = append(families, IPFamilyV6)
	}

	return families
}

// deriveFeatures derives additional features based on the status of other features
func (fs Set) DeriveFeatures() error {
	fs[HostPort] = Status{
		// HostPort support can either be enabled via KPR, or via CNI chaining with portmap plugin
		Enabled: (fs[CNIChaining].Enabled && fs[CNIChaining].Mode == "portmap" &&
			// cilium/cilium#12541: Host firewall doesn't work with portmap CNI chaining
			!fs[HostFirewall].Enabled) ||
			fs[KPRHostPort].Enabled,
	}

	return nil
}

// Requirement defines a test requirement. A given Set may or
// may not satisfy this requirement
type Requirement struct {
	Feature Feature

	requiresEnabled bool
	enabled         bool

	requiresMode bool
	mode         string
}

// RequireEnabled constructs a Requirement which expects the
// Feature to be enabled
func RequireEnabled(feature Feature) Requirement {
	return Requirement{
		Feature:         feature,
		requiresEnabled: true,
		enabled:         true,
	}
}

// RequireDisabled constructs a Requirement which expects the
// Feature to be disabled
func RequireDisabled(feature Feature) Requirement {
	return Requirement{
		Feature:         feature,
		requiresEnabled: true,
		enabled:         false,
	}
}

// RequireMode constructs a Requirement which expects the Feature
// to be in the given mode
func RequireMode(feature Feature, mode string) Requirement {
	return Requirement{
		Feature:      feature,
		requiresMode: true,
		mode:         mode,
	}
}

// ExtractFromVersionedConfigMap extracts features based on Cilium version and cilium-config
// ConfigMap.
func (fs Set) ExtractFromVersionedConfigMap(ciliumVersion semver.Version, cm *v1.ConfigMap) {
	fs[Tunnel] = ExtractTunnelFeatureFromVersionedConfigMap(ciliumVersion, cm)
}

func ExtractTunnelFeatureFromVersionedConfigMap(ciliumVersion semver.Version, cm *v1.ConfigMap) Status {
	if versioncheck.MustCompile("<1.14.0")(ciliumVersion) {
		enabled, proto := true, "vxlan"
		if v, ok := cm.Data["tunnel"]; ok {
			if enabled = v != "disabled"; enabled {
				proto = v
			}
		}
		return Status{
			Enabled: enabled,
			Mode:    proto,
		}
	}

	mode := "tunnel"
	if v, ok := cm.Data["routing-mode"]; ok {
		mode = v
	}

	tunnelProto := "vxlan"
	if v, ok := cm.Data["tunnel-protocol"]; ok {
		tunnelProto = v
	}

	return Status{
		Enabled: mode != "native",
		Mode:    tunnelProto,
	}
}

// ExtractFromConfigMap extracts features from the Cilium ConfigMap.
// Note that there is no rule regarding if the default value is reflected
// in the ConfigMap or not.
func (fs Set) ExtractFromConfigMap(cm *v1.ConfigMap) {
	// CNI chaining.
	// Note: This value might be overwritten by extractFeaturesFromCiliumStatus
	// if this information is present in `cilium status`
	mode := "none"
	if v, ok := cm.Data["cni-chaining-mode"]; ok {
		mode = v
	}
	fs[CNIChaining] = Status{
		Enabled: mode != "none",
		Mode:    mode,
	}

	fs[IPv4] = Status{
		Enabled: cm.Data["enable-ipv4"] == "true",
	}
	fs[IPv6] = Status{
		Enabled: cm.Data["enable-ipv6"] == "true",
	}

	fs[EndpointRoutes] = Status{
		Enabled: cm.Data["enable-endpoint-routes"] == "true",
	}

	fs[AuthSpiffe] = Status{
		Enabled: cm.Data["mesh-auth-mutual-enabled"] == "true",
	}

	fs[IngressController] = Status{
		Enabled: cm.Data["enable-ingress-controller"] == "true",
	}

	fs[EgressGateway] = Status{
		Enabled: cm.Data["enable-ipv4-egress-gateway"] == "true",
	}

	fs[CIDRMatchNodes] = Status{
		Enabled: strings.Contains(cm.Data["policy-cidr-match-mode"], "nodes"),
	}

	fs[GatewayAPI] = Status{
		Enabled: cm.Data[string(GatewayAPI)] == "true",
	}

	fs[EnableEnvoyConfig] = Status{
		Enabled: cm.Data[string(EnableEnvoyConfig)] == "true",
	}

	fs[WireguardEncapsulate] = Status{
		Enabled: cm.Data[string(WireguardEncapsulate)] == "true",
	}
}

func (fs Set) ExtractFromNodes(nodesWithoutCilium map[string]struct{}) {
	fs[NodeWithoutCilium] = Status{
		Enabled: len(nodesWithoutCilium) != 0,
		Mode:    strings.Join(maps.Keys(nodesWithoutCilium), ","),
	}
}
