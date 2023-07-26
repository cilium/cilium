// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package check

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/versioncheck"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/internal/utils"
	"github.com/cilium/cilium-cli/k8s"
)

// Feature is the name of a Cilium feature (e.g. l7-proxy, cni chaining mode etc)
type Feature string

const (
	FeatureCNIChaining        Feature = "cni-chaining"
	FeatureMonitorAggregation Feature = "monitor-aggregation"
	FeatureL7Proxy            Feature = "l7-proxy"
	FeatureHostFirewall       Feature = "host-firewall"
	FeatureICMPPolicy         Feature = "icmp-policy"
	FeatureTunnel             Feature = "tunnel"
	FeatureEndpointRoutes     Feature = "endpoint-routes"

	FeatureKPRMode                Feature = "kpr-mode"
	FeatureKPRExternalIPs         Feature = "kpr-external-ips"
	FeatureKPRGracefulTermination Feature = "kpr-graceful-termination"
	FeatureKPRHostPort            Feature = "kpr-hostport"
	FeatureKPRSocketLB            Feature = "kpr-socket-lb"
	FeatureKPRNodePort            Feature = "kpr-nodeport"
	FeatureKPRSessionAffinity     Feature = "kpr-session-affinity"

	FeatureHostPort Feature = "host-port"

	FeatureNodeWithoutCilium Feature = "node-without-cilium"

	FeatureHealthChecking Feature = "health-checking"

	FeatureEncryptionPod  Feature = "encryption-pod"
	FeatureEncryptionNode Feature = "encryption-node"

	FeatureIPv4 Feature = "ipv4"
	FeatureIPv6 Feature = "ipv6"

	FeatureFlavor Feature = "flavor"

	FeatureSecretBackendK8s Feature = "secret-backend-k8s"

	FeatureCNP Feature = "cilium-network-policy"
	FeatureKNP Feature = "k8s-network-policy"

	FeatureAuthSpiffe Feature = "mutual-auth-spiffe"

	FeatureIngressController Feature = "ingress-controller"

	FeatureEgressGateway Feature = "enable-ipv4-egress-gateway"
)

// FeatureStatus describes the status of a feature. Some features are either
// turned on or off (c.f. Enabled), while others additionally might include a
// Mode string which provides more information about in what mode a
// particular feature is running ((e.g. when running with CNI chaining,
// Enabled will be true, and the Mode string will additionally contain the name
// of the chained CNI).
type FeatureStatus struct {
	Enabled bool
	Mode    string
}

func (s FeatureStatus) String() string {
	str := "Disabled"
	if s.Enabled {
		str = "Enabled"
	}

	if len(s.Mode) == 0 {
		return str
	}

	return fmt.Sprintf("%s:%s", str, s.Mode)
}

// FeatureSet contains the status
type FeatureSet map[Feature]FeatureStatus

// MatchRequirements returns true if the FeatureSet fs satisfies all the
// requirements in reqs. Returns true for empty requirements list.
func (fs FeatureSet) MatchRequirements(reqs ...FeatureRequirement) bool {
	for _, req := range reqs {
		status := fs[req.feature]
		if req.requiresEnabled && (req.enabled != status.Enabled) {
			return false
		}
		if req.requiresMode && (req.mode != status.Mode) {
			return false
		}
	}

	return true
}

// IPFamilies returns the list of enabled IP families.
func (fs FeatureSet) IPFamilies() []IPFamily {
	var families []IPFamily

	if fs.MatchRequirements(RequireFeatureEnabled(FeatureIPv4)) {
		families = append(families, IPFamilyV4)
	}

	if fs.MatchRequirements(RequireFeatureEnabled(FeatureIPv6)) {
		families = append(families, IPFamilyV6)
	}

	return families
}

// deriveFeatures derives additional features based on the status of other features
func (fs FeatureSet) deriveFeatures() error {
	fs[FeatureHostPort] = FeatureStatus{
		// HostPort support can either be enabled via KPR, or via CNI chaining with portmap plugin
		Enabled: (fs[FeatureCNIChaining].Enabled && fs[FeatureCNIChaining].Mode == "portmap" &&
			// cilium/cilium#12541: Host firewall doesn't work with portmap CNI chaining
			!fs[FeatureHostFirewall].Enabled) ||
			fs[FeatureKPRHostPort].Enabled,
	}

	return nil
}

// FeatureRequirement defines a test requirement. A given FeatureSet may or
// may not satisfy this requirement
type FeatureRequirement struct {
	feature Feature

	requiresEnabled bool
	enabled         bool

	requiresMode bool
	mode         string
}

// RequireFeatureEnabled constructs a FeatureRequirement which expects the
// feature to be enabled
func RequireFeatureEnabled(feature Feature) FeatureRequirement {
	return FeatureRequirement{
		feature:         feature,
		requiresEnabled: true,
		enabled:         true,
	}
}

// RequireFeatureDisabled constructs a FeatureRequirement which expects the
// feature to be disabled
func RequireFeatureDisabled(feature Feature) FeatureRequirement {
	return FeatureRequirement{
		feature:         feature,
		requiresEnabled: true,
		enabled:         false,
	}
}

// RequireFeatureMode constructs a FeatureRequirement which expects the feature
// to be in the given mode
func RequireFeatureMode(feature Feature, mode string) FeatureRequirement {
	return FeatureRequirement{
		feature:      feature,
		requiresMode: true,
		mode:         mode,
	}
}

func parseBoolStatus(s string) bool {
	switch s {
	case "Enabled", "enabled", "True", "true":
		return true
	}

	return false
}

func (ct *ConnectivityTest) extractFeaturesFromConfigMap(ctx context.Context, client *k8s.Client, result FeatureSet) error {
	cm, err := client.GetConfigMap(ctx, ct.params.CiliumNamespace, defaults.ConfigMapName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("unable to retrieve ConfigMap %q: %w", defaults.ConfigMapName, err)
	}
	if cm.Data == nil {
		return fmt.Errorf("ConfigMap %q does not contain any configuration", defaults.ConfigMapName)
	}

	// CNI chaining.
	// Note: This value might be overwritten by extractFeaturesFromCiliumStatus
	// if this information is present in `cilium status`
	mode := "none"
	if v, ok := cm.Data["cni-chaining-mode"]; ok {
		mode = v
	}
	result[FeatureCNIChaining] = FeatureStatus{
		Enabled: mode != "none",
		Mode:    mode,
	}

	if versioncheck.MustCompile("<1.14.0")(ct.CiliumVersion) {
		mode = "vxlan"
		if v, ok := cm.Data["tunnel"]; ok {
			mode = v
		}
		result[FeatureTunnel] = FeatureStatus{
			Enabled: mode != "disabled",
			Mode:    mode,
		}
	} else {
		mode = "tunnel"
		if v, ok := cm.Data["routing-mode"]; ok {
			mode = v
		}

		tunnelProto := "vxlan"
		if mode != "native" {
			if v, ok := cm.Data["tunnel-protocol"]; ok {
				tunnelProto = v
			}
		}

		result[FeatureTunnel] = FeatureStatus{
			Enabled: mode != "native",
			Mode:    tunnelProto,
		}
	}

	result[FeatureIPv4] = FeatureStatus{
		Enabled: cm.Data["enable-ipv4"] == "true",
	}
	result[FeatureIPv6] = FeatureStatus{
		Enabled: cm.Data["enable-ipv6"] == "true",
	}

	result[FeatureEndpointRoutes] = FeatureStatus{
		Enabled: cm.Data["enable-endpoint-routes"] == "true",
	}

	result[FeatureAuthSpiffe] = FeatureStatus{
		Enabled: cm.Data["mesh-auth-mutual-enabled"] == "true",
	}

	result[FeatureIngressController] = FeatureStatus{
		Enabled: cm.Data["enable-ingress-controller"] == "true",
	}

	result[FeatureEgressGateway] = FeatureStatus{
		Enabled: cm.Data["enable-ipv4-egress-gateway"] == "true",
	}

	return nil
}

func (ct *ConnectivityTest) extractFeaturesFromRuntimeConfig(ctx context.Context, ciliumPod Pod, result FeatureSet) error {
	namespace := ciliumPod.Pod.Namespace

	stdout, err := ciliumPod.K8sClient.ExecInPod(ctx, namespace, ciliumPod.Pod.Name,
		defaults.AgentContainerName, []string{"cat", "/var/run/cilium/state/agent-runtime-config.json"})
	if err != nil {
		return fmt.Errorf("failed to fetch cilium runtime config: %w", err)
	}

	cfg := &option.DaemonConfig{}
	if err := json.Unmarshal(stdout.Bytes(), cfg); err != nil {
		return fmt.Errorf("unmarshaling cilium runtime config json: %w", err)
	}

	result[FeatureMonitorAggregation] = FeatureStatus{
		Enabled: cfg.MonitorAggregation != "none",
		Mode:    cfg.MonitorAggregation,
	}

	result[FeatureICMPPolicy] = FeatureStatus{
		Enabled: cfg.EnableICMPRules,
	}

	result[FeatureHealthChecking] = FeatureStatus{
		Enabled: cfg.EnableHealthChecking && cfg.EnableEndpointHealthChecking,
	}

	result[FeatureEncryptionNode] = FeatureStatus{
		Enabled: cfg.EncryptNode,
	}

	isFeatureKNPEnabled, err := ct.isFeatureKNPEnabled(cfg.EnableK8sNetworkPolicy)
	if err != nil {
		return fmt.Errorf("unable to determine if KNP feature is enabled: %w", err)
	}

	result[FeatureKNP] = FeatureStatus{
		Enabled: isFeatureKNPEnabled,
	}

	return nil
}

func (ct *ConnectivityTest) extractFeaturesFromNodes(ctx context.Context, client *k8s.Client, result FeatureSet) error {
	nodeList, err := client.ListNodes(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}

	nodes := []string{}
	ct.nodesWithoutCiliumMap = make(map[string]struct{})
	for _, node := range nodeList.Items {
		node := node
		if !canNodeRunCilium(&node) {
			nodes = append(nodes, node.ObjectMeta.Name)
			ct.nodesWithoutCiliumMap[node.ObjectMeta.Name] = struct{}{}
		}
	}

	result[FeatureNodeWithoutCilium] = FeatureStatus{
		Enabled: len(nodes) != 0,
		Mode:    strings.Join(nodes, ","),
	}
	ct.nodesWithoutCilium = nodes

	return nil
}

func (ct *ConnectivityTest) extractFeaturesFromClusterRole(ctx context.Context, client *k8s.Client, result FeatureSet) error {
	cr, err := client.GetClusterRole(ctx, defaults.AgentClusterRoleName, metav1.GetOptions{})
	if err != nil {
		return err
	}

	result[FeatureSecretBackendK8s] = FeatureStatus{
		Enabled: canAccessK8sResourceSecret(cr),
	}
	return nil
}

func canAccessK8sResourceSecret(cr *rbacv1.ClusterRole) bool {
	for _, rule := range cr.Rules {
		for _, resource := range rule.Resources {
			if resource == "secrets" {
				return true
			}
		}
	}

	return false
}

func (ct *ConnectivityTest) extractFeaturesFromCiliumStatus(ctx context.Context, ciliumPod Pod, result FeatureSet) error {
	stdout, err := ciliumPod.K8sClient.ExecInPod(ctx, ciliumPod.Pod.Namespace, ciliumPod.Pod.Name,
		defaults.AgentContainerName, []string{"cilium", "status", "-o", "json"})
	if err != nil {
		return fmt.Errorf("failed to fetch cilium status: %w", err)
	}

	st := &models.StatusResponse{}
	if err := json.Unmarshal(stdout.Bytes(), st); err != nil {
		return fmt.Errorf("unmarshaling Cilium stdout json: %w", err)
	}

	// CNI chaining
	mode := ""
	if st.CniChaining != nil {
		mode = st.CniChaining.Mode
	} else {
		// Cilium versions prior to v1.12 do not expose the CNI chaining mode in
		// cilium status, it's only available in the ConfigMap, which we
		// inherit here
		mode = result[FeatureCNIChaining].Mode
	}

	result[FeatureCNIChaining] = FeatureStatus{
		Enabled: len(mode) > 0 && mode != "none",
		Mode:    mode,
	}

	// L7 Proxy
	result[FeatureL7Proxy] = FeatureStatus{
		Enabled: st.Proxy != nil,
	}

	// Host Firewall
	status := false
	if hf := st.HostFirewall; hf != nil {
		status = parseBoolStatus(st.HostFirewall.Mode)
	}
	result[FeatureHostFirewall] = FeatureStatus{
		Enabled: status,
	}

	// Kube-Proxy Replacement
	mode = "Disabled"
	if kpr := st.KubeProxyReplacement; kpr != nil {
		mode = kpr.Mode
		if f := kpr.Features; kpr.Mode != "Disabled" && f != nil {
			if f.ExternalIPs != nil {
				result[FeatureKPRExternalIPs] = FeatureStatus{Enabled: f.ExternalIPs.Enabled}
			}
			if f.HostPort != nil {
				result[FeatureKPRHostPort] = FeatureStatus{Enabled: f.HostPort.Enabled}
			}
			if f.GracefulTermination != nil {
				result[FeatureKPRGracefulTermination] = FeatureStatus{Enabled: f.GracefulTermination.Enabled}
			}
			if f.NodePort != nil {
				result[FeatureKPRNodePort] = FeatureStatus{Enabled: f.NodePort.Enabled}
			}
			if f.SessionAffinity != nil {
				result[FeatureKPRSessionAffinity] = FeatureStatus{Enabled: f.SessionAffinity.Enabled}
			}
			if f.SocketLB != nil {
				result[FeatureKPRSocketLB] = FeatureStatus{Enabled: f.SocketLB.Enabled}
			}
		}
	}
	result[FeatureKPRMode] = FeatureStatus{
		Enabled: mode != "Disabled",
		Mode:    mode,
	}

	// encryption
	mode = "disabled"
	if enc := st.Encryption; enc != nil {
		mode = strings.ToLower(enc.Mode)
	}
	result[FeatureEncryptionPod] = FeatureStatus{
		Enabled: mode != "disabled",
		Mode:    mode,
	}

	return nil
}

func (ct *ConnectivityTest) extractFeaturesFromK8sCluster(ctx context.Context, result FeatureSet) {
	flavor := ct.client.AutodetectFlavor(ctx)

	result[FeatureFlavor] = FeatureStatus{
		Enabled: flavor.Kind.String() != "invalid",
		Mode:    strings.ToLower(flavor.Kind.String()),
	}
}

const ciliumNetworkPolicyCRDName = "ciliumnetworkpolicies.cilium.io"

func (ct *ConnectivityTest) extractFeaturesFromCRDs(ctx context.Context, result FeatureSet) error {
	// CNP are deployed by default.
	cnpDeployed := true

	// Check if CRD Cilium Network Policy is deployed.
	_, err := ct.client.GetCRD(ctx, ciliumNetworkPolicyCRDName, metav1.GetOptions{})

	if err != nil {
		if !k8serrors.IsNotFound(err) {
			fmt.Printf("Type of error: %v, %T", err, err)
			return fmt.Errorf("unable to retrieve CRD %s: %w", ciliumNetworkPolicyCRDName, err)
		}

		// Not found it's not deployed.
		cnpDeployed = false
	}

	result[FeatureCNP] = FeatureStatus{
		Enabled: cnpDeployed,
	}

	return nil
}

func (ct *ConnectivityTest) validateFeatureSet(other FeatureSet, source string) {
	for key, found := range other {
		expected, ok := ct.Features[key]
		if !ok {
			ct.Warnf("Cilium feature %q found in pod %s, but not in reference set", key, source)
		} else {
			if expected != found {
				ct.Warnf("Cilium feature %q differs in pod %s. Expected %q, found %q", key, source, expected, found)
			}
		}
	}

	for key := range ct.Features {
		if _, ok := other[key]; !ok {
			ct.Warnf("Cilium feature %q not found in pod %s", key, source)
		}
	}
}

func (ct *ConnectivityTest) detectCiliumVersion(ctx context.Context) error {
	if assumeCiliumVersion := ct.Params().AssumeCiliumVersion; assumeCiliumVersion != "" {
		ct.Warnf("Assuming Cilium version %s for connectivity tests", assumeCiliumVersion)
		var err error
		ct.CiliumVersion, err = utils.ParseCiliumVersion(assumeCiliumVersion)
		if err != nil {
			return err
		}
	} else if minVersion, err := ct.DetectMinimumCiliumVersion(ctx); err != nil {
		ct.Warnf("Unable to detect Cilium version, assuming %v for connectivity tests: %s", defaults.Version, err)
		ct.CiliumVersion, err = utils.ParseCiliumVersion(defaults.Version)
		if err != nil {
			return err
		}
	} else {
		ct.CiliumVersion = *minVersion
	}
	return nil
}

func (ct *ConnectivityTest) detectFeatures(ctx context.Context) error {
	initialized := false
	for _, ciliumPod := range ct.ciliumPods {
		features := FeatureSet{}

		err := ct.extractFeaturesFromConfigMap(ctx, ciliumPod.K8sClient, features)
		if err != nil {
			return err
		}
		err = ct.extractFeaturesFromRuntimeConfig(ctx, ciliumPod, features)
		if err != nil {
			return err
		}
		err = ct.extractFeaturesFromNodes(ctx, ciliumPod.K8sClient, features)
		if err != nil {
			return err
		}
		err = ct.extractFeaturesFromCiliumStatus(ctx, ciliumPod, features)
		if err != nil {
			return err
		}
		err = ct.extractFeaturesFromClusterRole(ctx, ciliumPod.K8sClient, features)
		if err != nil {
			return err
		}
		ct.extractFeaturesFromK8sCluster(ctx, features)
		err = features.deriveFeatures()
		if err != nil {
			return err
		}
		err = ct.extractFeaturesFromCRDs(ctx, features)
		if err != nil {
			return err
		}

		if initialized {
			ct.validateFeatureSet(features, ciliumPod.Name())
		} else {
			ct.Features = features
			initialized = true
		}
	}

	return nil
}

func (ct *ConnectivityTest) UpdateFeaturesFromNodes(ctx context.Context) error {
	return ct.extractFeaturesFromNodes(ctx, ct.client, ct.Features)
}

func (ct *ConnectivityTest) ForceDisableFeature(feature Feature) {
	ct.Features[feature] = FeatureStatus{Enabled: false}
}

// isFeatureKNPEnabled checks if the Kubernetes Network Policy feature is enabled from the configuration.
// Note that the flag appears in Cilium version 1.14, before that it was unable even thought KNPs were present.
func (ct *ConnectivityTest) isFeatureKNPEnabled(enableK8SNetworkPolicy bool) (bool, error) {
	switch {
	case enableK8SNetworkPolicy:
		// Flag is enabled, means the flag exists.
		return true, nil
	case !enableK8SNetworkPolicy && versioncheck.MustCompile("<1.14.0")(ct.CiliumVersion):
		// Flag was always disabled even KNP were activated before Cilium 1.14.
		return true, nil
	case !enableK8SNetworkPolicy && versioncheck.MustCompile(">=1.14.0")(ct.CiliumVersion):
		// Flag is explicitly set to disabled after Cilium 1.14.
		return false, nil
	default:
		return false, fmt.Errorf("cilium version unsupported %s", ct.CiliumVersion.String())
	}
}

func canNodeRunCilium(node *corev1.Node) bool {
	val, ok := node.ObjectMeta.Labels["cilium.io/no-schedule"]
	return !ok || val == "false"
}
