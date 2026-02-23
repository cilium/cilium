// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package check

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/blang/semver/v4"
	rbacv1 "k8s.io/api/rbac/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium/cilium-cli/internal/helm"
	"github.com/cilium/cilium/cilium-cli/k8s"
	"github.com/cilium/cilium/cilium-cli/utils/features"
	slimcorev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/version"
	"github.com/cilium/cilium/pkg/versioncheck"
)

func parseBoolStatus(s string) bool {
	switch s {
	case "Enabled", "enabled", "True", "true":
		return true
	}

	return false
}

// DaemonConfigForFeatDetection is a minimal daemon config used for feature extraction.
//
// The struct is used to work around situations where we want to introduce a breaking
// change to DaemonConfig. CLI is required to work with all stable Cilium versions. So,
// the breaking change could break CLI for some versions.
//
// In any case, it is preferred to NOT do feature detection based on the runtime config,
// as it was never meant to provide a stable "API".
type DaemonConfigForFeatDetection struct {
	MonitorAggregation               string
	EnableICMPRules                  bool
	EnableHealthChecking             bool
	EnableEndpointHealthChecking     bool
	EncryptNode                      bool
	NodeEncryptionOptOutLabelsString string
	EnableK8sNetworkPolicy           bool
}

// extractFeaturesFromRuntimeConfig extracts features from the Cilium runtime config.
func (ct *ConnectivityTest) extractFeaturesFromRuntimeConfig(ctx context.Context, ciliumPod Pod, result features.Set) error {
	namespace := ciliumPod.Pod.Namespace

	stdout, err := ciliumPod.K8sClient.ExecInPod(ctx, namespace, ciliumPod.Pod.Name,
		defaults.AgentContainerName, []string{"cat", "/var/run/cilium/state/agent-runtime-config.json"})
	if err != nil {
		return fmt.Errorf("failed to fetch cilium runtime config: %w", err)
	}

	cfg := &DaemonConfigForFeatDetection{}
	if err := json.Unmarshal(stdout.Bytes(), cfg); err != nil {
		return fmt.Errorf("unmarshaling cilium runtime config json: %w", err)
	}

	result[features.MonitorAggregation] = features.Status{
		Enabled: cfg.MonitorAggregation != "none",
		Mode:    cfg.MonitorAggregation,
	}

	result[features.ICMPPolicy] = features.Status{
		Enabled: cfg.EnableICMPRules,
	}

	result[features.HealthChecking] = features.Status{
		Enabled: cfg.EnableHealthChecking && cfg.EnableEndpointHealthChecking,
	}

	// Before v1.19, NodeEncryptionOptOutLabels are stored in DaemonConfig.
	// See [extractFeaturesFromCiliumStatus] for above versions.
	if ct.CiliumVersion.LT(semver.MustParse("1.19.0")) {
		result[features.EncryptionNode] = features.Status{
			Enabled: cfg.EncryptNode,
			Mode:    cfg.NodeEncryptionOptOutLabelsString,
		}
	}

	result[features.KNP] = features.Status{
		Enabled: cfg.EnableK8sNetworkPolicy,
	}

	return nil
}

func (ct *ConnectivityTest) extractFeaturesFromClusterRole(ctx context.Context, client *k8s.Client, result features.Set) error {
	cr, err := client.GetClusterRole(ctx, defaults.AgentClusterRoleName, metav1.GetOptions{})
	if err != nil {
		return err
	}

	// This could be enabled via configmap check, so only check if it's not enabled already.
	if !result[features.PolicySecretsOnlyFromSecretsNamespace].Enabled {
		result[features.PolicySecretsOnlyFromSecretsNamespace] = features.Status{
			Enabled: canAccessK8sResourceSecret(cr),
		}
	}
	return nil
}

func canAccessK8sResourceSecret(cr *rbacv1.ClusterRole) bool {
	for _, rule := range cr.Rules {
		if slices.Contains(rule.Resources, "secrets") {
			return true
		}
	}
	return false
}

func (ct *ConnectivityTest) extractFeaturesFromCiliumStatus(ctx context.Context, ciliumPod Pod, result features.Set) error {
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
	}

	result[features.CNIChaining] = features.Status{
		Enabled: len(mode) > 0 && mode != "none",
		Mode:    mode,
	}

	// L7 Proxy
	result[features.L7Proxy] = features.Status{
		Enabled: st.Proxy != nil,
	}

	result[features.ExternalEnvoyProxy] = features.Status{
		Enabled: st.Proxy != nil && strings.ToLower(st.Proxy.EnvoyDeploymentMode) == "external",
	}

	// Host Firewall
	status := false
	if hf := st.HostFirewall; hf != nil {
		status = parseBoolStatus(st.HostFirewall.Mode)
	}
	result[features.HostFirewall] = features.Status{
		Enabled: status,
	}

	// Kube-Proxy Replacement
	mode = "false"
	if kpr := st.KubeProxyReplacement; kpr != nil {
		mode = strings.ToLower(kpr.Mode)
		if f := kpr.Features; f != nil {
			if f.SocketLB != nil {
				result[features.KPRSocketLB] = features.Status{Enabled: f.SocketLB.Enabled}
				result[features.KPRSocketLBHostnsOnly] = features.Status{Enabled: f.BpfSocketLBHostnsOnly}
			}
			acceleration := strings.ToLower(f.NodePort.Acceleration)
			result[features.KPRNodePortAcceleration] = features.Status{
				Enabled: mode == "true" && acceleration != "disabled",
				Mode:    acceleration,
			}
		}
	}
	result[features.KPR] = features.Status{
		Enabled: mode == "true",
		Mode:    mode,
	}

	// encryption
	mode = "disabled"
	if enc := st.Encryption; enc != nil {
		mode = strings.ToLower(enc.Mode)

		// After v1.19, NodeEncryptionOptOutLabels are stored in the Wireguard Agent config.
		// See [extractFeaturesFromRuntimeConfig] for below versions.
		if ct.CiliumVersion.GE(semver.MustParse("1.19.0")) {
			// Node-to-node encryption applies only to WireGuard.
			if wg := enc.Wireguard; wg != nil {
				result[features.EncryptionNode] = features.Status{
					Enabled: wg.NodeEncryption != "Disabled",
					Mode:    wg.NodeEncryptOptOutLabels,
				}
			}
		}
	}
	result[features.EncryptionPod] = features.Status{
		Enabled: mode != "disabled",
		Mode:    mode,
	}

	return nil
}

func (ct *ConnectivityTest) extractFeaturesFromUname(ctx context.Context, ciliumPod Pod, result features.Set) error {
	stdout, err := ciliumPod.K8sClient.ExecInPod(ctx, ciliumPod.Pod.Namespace, ciliumPod.Pod.Name,
		defaults.AgentContainerName, []string{"uname", "-r"})
	if err != nil {
		return fmt.Errorf("failed to fetch uname -r: %w", err)
	}

	kernelVersion, err := version.ParseKernelVersion(stdout.String())
	if err != nil {
		return fmt.Errorf("failed to parse kernel version: %w", err)
	}

	result[features.RHEL] = features.Status{
		Enabled: versioncheck.MustCompile("<=4.18.0")(kernelVersion),
	}

	return nil
}

func (ct *ConnectivityTest) extractFeaturesFromK8sCluster(ctx context.Context, result features.Set) {
	flavor := ct.client.AutodetectFlavor(ctx)

	result[features.Flavor] = features.Status{
		Enabled: flavor.Kind.String() != "invalid",
		Mode:    strings.ToLower(flavor.Kind.String()),
	}
}

const (
	ciliumNetworkPolicyCRDName            = "ciliumnetworkpolicies.cilium.io"
	ciliumClusterwideNetworkPolicyCRDName = "ciliumclusterwidenetworkpolicies.cilium.io"
)

func (ct *ConnectivityTest) extractFeaturesFromCRDs(ctx context.Context, result features.Set) error {
	check := func(name string) (features.Status, error) {
		_, err := ct.client.GetCRD(ctx, name, metav1.GetOptions{})
		switch {
		case err == nil:
			return features.Status{Enabled: true}, nil
		case k8serrors.IsNotFound(err):
			return features.Status{Enabled: false}, nil
		default:
			return features.Status{}, fmt.Errorf("unable to retrieve CRD %s: %w", ciliumNetworkPolicyCRDName, err)
		}
	}

	cnp, err := check(ciliumNetworkPolicyCRDName)
	if err != nil {
		return err
	}

	ccnp, err := check(ciliumClusterwideNetworkPolicyCRDName)
	if err != nil {
		return err
	}

	result[features.CNP] = cnp
	result[features.CCNP] = ccnp
	return nil
}

const (
	nodeLocalDNSNamespace                     = "kube-system"
	nodeLocalDNSDaemonSetName                 = "node-local-dns"
	nodeLocalDNSCiliumLocalRedirectPolicyName = "nodelocaldns"
)

func (ct *ConnectivityTest) extractFeaturesFromDNSConfig(ctx context.Context, result features.Set) error {
	_, err := ct.client.GetDaemonSet(ctx, nodeLocalDNSNamespace, nodeLocalDNSDaemonSetName, metav1.GetOptions{})
	if err != nil {
		if k8serrors.IsNotFound(err) {
			result[features.NodeLocalDNS] = features.Status{Enabled: false}
			return nil
		}
		return fmt.Errorf("unable to retrieve DaemonSet %s: %w", nodeLocalDNSDaemonSetName, err)
	}

	_, err = ct.client.GetCiliumLocalRedirectPolicy(ctx, nodeLocalDNSNamespace, nodeLocalDNSCiliumLocalRedirectPolicyName, metav1.GetOptions{})
	if err != nil {
		if k8serrors.IsNotFound(err) {
			result[features.NodeLocalDNS] = features.Status{Enabled: false}
			return nil
		}
		return fmt.Errorf("unable to retrieve CiliumLocalRedirectPolicy %s: %w", nodeLocalDNSCiliumLocalRedirectPolicyName, err)
	}

	result[features.NodeLocalDNS] = features.Status{Enabled: true}
	return nil
}

func (ct *ConnectivityTest) validateFeatureSet(other features.Set, source string) {
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
		ct.CiliumVersion, err = semver.ParseTolerant(assumeCiliumVersion)
		if err != nil {
			return err
		}
	} else if minVersion, err := ct.DetectMinimumCiliumVersion(ctx); err != nil {
		defaultVersion := helm.GetDefaultVersionString()
		ct.Warnf("Unable to detect Cilium version, assuming %v for connectivity tests: %s", defaultVersion, err)
		ct.CiliumVersion, err = semver.ParseTolerant(defaultVersion)
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
	cm, err := ct.client.GetConfigMap(ctx, ct.params.CiliumNamespace, defaults.ConfigMapName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("unable to retrieve ConfigMap %q: %w", defaults.ConfigMapName, err)
	}
	if cm.Data == nil {
		return fmt.Errorf("ConfigMap %q does not contain any configuration", defaults.ConfigMapName)
	}

	// Extract cluster-wide features once outside the loop
	clusterFeatures := features.Set{}
	clusterFeatures.ExtractFromCiliumVersion(ct.CiliumVersion)
	clusterFeatures.ExtractFromConfigMap(cm)
	clusterFeatures.ExtractFromNodes(ct.nodesWithoutCilium)
	ct.extractFeaturesFromK8sCluster(ctx, clusterFeatures)
	err = ct.extractFeaturesFromCRDs(ctx, clusterFeatures)
	if err != nil {
		return err
	}
	err = ct.extractFeaturesFromDNSConfig(ctx, clusterFeatures)
	if err != nil {
		return err
	}
	err = ct.extractFeaturesFromClusterRole(ctx, ct.client, clusterFeatures)
	if err != nil {
		return err
	}

	for _, ciliumPod := range ct.ciliumPods {
		// Start with cluster-wide features
		features := maps.Clone(clusterFeatures)

		// Extract pod-specific features
		err = ct.extractFeaturesFromRuntimeConfig(ctx, ciliumPod, features)
		if err != nil {
			return err
		}
		err = ct.extractFeaturesFromCiliumStatus(ctx, ciliumPod, features)
		if err != nil {
			return err
		}
		err = ct.extractFeaturesFromUname(ctx, ciliumPod, features)
		if err != nil {
			return err
		}
		err = features.DeriveFeatures()
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

	ct.ClusterNameLocal = cmp.Or(cm.Data["cluster-name"], "default")
	ct.ClusterNameRemote = ct.ClusterNameLocal
	if ct.params.MultiCluster != "" {
		cmDst, err := ct.clients.dst.GetConfigMap(ctx, ct.params.CiliumNamespace, defaults.ConfigMapName, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("unable to retrieve dst cluster ConfigMap %q: %w", defaults.ConfigMapName, err)
		}
		ct.ClusterNameRemote = cmp.Or(cmDst.Data["cluster-name"], "default")
	}

	return nil
}

func (ct *ConnectivityTest) ForceDisableFeature(feature features.Feature) {
	ct.Features[feature] = features.Status{Enabled: false}
}

func canNodeRunCilium(node *slimcorev1.Node) bool {
	val, ok := node.ObjectMeta.Labels["cilium.io/no-schedule"]
	return !ok || val == "false"
}

func isControlPlane(node *slimcorev1.Node) bool {
	if node != nil {
		_, ok := node.Labels["node-role.kubernetes.io/control-plane"]
		return ok
	}
	return false
}
