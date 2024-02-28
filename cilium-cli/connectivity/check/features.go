// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package check

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/blang/semver/v4"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/versioncheck"

	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/k8s"
	"github.com/cilium/cilium-cli/utils/features"
)

func parseBoolStatus(s string) bool {
	switch s {
	case "Enabled", "enabled", "True", "true":
		return true
	}

	return false
}

// extractFeaturesFromRuntimeConfig extracts features from the Cilium runtime config.
// The downside of this approach is that the `DaemonConfig` struct is not stable.
// If there are changes to it in the future, we will likely have to maintain
// version-specific copies of the struct in the Cilium-CLI.
func (ct *ConnectivityTest) extractFeaturesFromRuntimeConfig(ctx context.Context, ciliumPod Pod, result features.Set) error {
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

	result[features.EncryptionNode] = features.Status{
		Enabled: cfg.EncryptNode,
	}

	isFeatureKNPEnabled, err := ct.isFeatureKNPEnabled(cfg.EnableK8sNetworkPolicy)
	if err != nil {
		return fmt.Errorf("unable to determine if KNP feature is enabled: %w", err)
	}

	result[features.KNP] = features.Status{
		Enabled: isFeatureKNPEnabled,
	}

	return nil
}

func (ct *ConnectivityTest) extractFeaturesFromClusterRole(ctx context.Context, client *k8s.Client, result features.Set) error {
	cr, err := client.GetClusterRole(ctx, defaults.AgentClusterRoleName, metav1.GetOptions{})
	if err != nil {
		return err
	}

	result[features.SecretBackendK8s] = features.Status{
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
	} else {
		// Cilium versions prior to v1.12 do not expose the CNI chaining mode in
		// cilium status, it's only available in the ConfigMap, which we
		// inherit here
		mode = result[features.CNIChaining].Mode
	}

	result[features.CNIChaining] = features.Status{
		Enabled: len(mode) > 0 && mode != "none",
		Mode:    mode,
	}

	// L7 Proxy
	result[features.L7Proxy] = features.Status{
		Enabled: st.Proxy != nil,
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
	mode = "Disabled"
	if kpr := st.KubeProxyReplacement; kpr != nil {
		mode = kpr.Mode
		if f := kpr.Features; kpr.Mode != "Disabled" && f != nil {
			if f.ExternalIPs != nil {
				result[features.KPRExternalIPs] = features.Status{Enabled: f.ExternalIPs.Enabled}
			}
			if f.HostPort != nil {
				result[features.KPRHostPort] = features.Status{Enabled: f.HostPort.Enabled}
			}
			if f.GracefulTermination != nil {
				result[features.KPRGracefulTermination] = features.Status{Enabled: f.GracefulTermination.Enabled}
			}
			if f.NodePort != nil {
				result[features.KPRNodePort] = features.Status{Enabled: f.NodePort.Enabled}
			}
			if f.SessionAffinity != nil {
				result[features.KPRSessionAffinity] = features.Status{Enabled: f.SessionAffinity.Enabled}
			}
			if f.SocketLB != nil {
				result[features.KPRSocketLB] = features.Status{Enabled: f.SocketLB.Enabled}
			}
		}
	}
	result[features.KPRMode] = features.Status{
		Enabled: mode != "Disabled",
		Mode:    mode,
	}

	// encryption
	mode = "disabled"
	if enc := st.Encryption; enc != nil {
		mode = strings.ToLower(enc.Mode)
	}
	result[features.EncryptionPod] = features.Status{
		Enabled: mode != "disabled",
		Mode:    mode,
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

const ciliumNetworkPolicyCRDName = "ciliumnetworkpolicies.cilium.io"
const ciliumClusterwideNetworkPolicyCRDName = "ciliumclusterwidenetworkpolicies.cilium.io"

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
		ct.Warnf("Unable to detect Cilium version, assuming %v for connectivity tests: %s", defaults.Version, err)
		ct.CiliumVersion, err = semver.ParseTolerant(defaults.Version)
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
	for _, ciliumPod := range ct.ciliumPods {
		features := features.Set{}

		// If unsure from which source to retrieve the information from,
		// prefer "CiliumStatus" over "ConfigMap" over "RuntimeConfig".
		// See the corresponding functions for more information.
		features.ExtractFromVersionedConfigMap(ct.CiliumVersion, cm)
		features.ExtractFromConfigMap(cm)
		err = ct.extractFeaturesFromRuntimeConfig(ctx, ciliumPod, features)
		if err != nil {
			return err
		}
		features.ExtractFromNodes(ct.nodesWithoutCilium)
		err = ct.extractFeaturesFromCiliumStatus(ctx, ciliumPod, features)
		if err != nil {
			return err
		}
		err = ct.extractFeaturesFromClusterRole(ctx, ciliumPod.K8sClient, features)
		if err != nil {
			return err
		}
		ct.extractFeaturesFromK8sCluster(ctx, features)
		err = features.DeriveFeatures()
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

func (ct *ConnectivityTest) ForceDisableFeature(feature features.Feature) {
	ct.Features[feature] = features.Status{Enabled: false}
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

func isControlPlane(node *corev1.Node) bool {
	if node != nil {
		_, ok := node.Labels["node-role.kubernetes.io/control-plane"]
		return ok
	}
	return false
}
