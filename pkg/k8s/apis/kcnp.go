// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package apis

import (
	"context"
	_ "embed"
	"fmt"
	"log/slog"

	"github.com/blang/semver/v4"
	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextensionsclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	policyv1alpha2 "sigs.k8s.io/network-policy-api/apis/v1alpha2"
	"sigs.k8s.io/yaml"

	"github.com/cilium/cilium/pkg/k8s/apis/crdhelpers"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/versioncheck"
)

const (
	// kcnpBundleVersionAnnotation is the annotation holding the version of the
	// upstream network-policy-api release the CRD originates from.
	kcnpBundleVersionAnnotation = "policy.networking.k8s.io/bundle-version"
	// kcnpChannelAnnotation is the annotation holding the upstream release
	// channel (standard or experimental) the CRD originates from.
	kcnpChannelAnnotation = "policy.networking.k8s.io/channel"
)

//go:embed crds/policy.networking.k8s.io_clusternetworkpolicies.yaml
var kcnpCRDBytes []byte

var kcnpGVK = policyv1alpha2.SchemeGroupVersion.WithKind("clusternetworkpolicies")

type kcnpCRDConfig struct {
	// K8sClusterNetworkPolicyInstallCRDs controls whether to automatically
	// install the K8s ClusterNetworkPolicy CRD, conditional on K8s
	// ClusterNetworkPolicy support being enabled.
	K8sClusterNetworkPolicyInstallCRDs bool `mapstructure:"k8s-cluster-network-policy-install-crds"`
}

var defaultKCNPCRDConfig = kcnpCRDConfig{
	K8sClusterNetworkPolicyInstallCRDs: true,
}

func (c kcnpCRDConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool(
		"k8s-cluster-network-policy-install-crds",
		c.K8sClusterNetworkPolicyInstallCRDs,
		"Install and manage the K8s ClusterNetworkPolicy CRD. Only applicable if K8s ClusterNetworkPolicy support is enabled.",
	)
}

type kcnpCRDParams struct {
	cell.In

	DaemonConfig *option.DaemonConfig
	Config       kcnpCRDConfig
}

func newKCNPCRDs(p kcnpCRDParams) RegisterCRDsFuncOut {
	return RegisterCRDsFuncOut{
		Func: func(ctx context.Context, logger *slog.Logger, clientset k8sClient.Clientset) ([]*apiextensionsv1.CustomResourceDefinition, error) {
			if !p.DaemonConfig.EnableK8sClusterNetworkPolicy {
				return nil, nil
			}
			if !p.Config.K8sClusterNetworkPolicyInstallCRDs {
				// The CRD is expected to be installed by other means. Surface
				// a missing CRD early, as the agents would otherwise only
				// fail once they time out waiting for it.
				if err := k8sClient.CheckCRD(ctx, clientset, kcnpGVK); err != nil {
					logger.Error(
						"K8s ClusterNetworkPolicy CRD not found, but its installation by the operator is disabled. "+
							"The agents will not become ready until it is installed, please refer to the documentation for installation instructions",
						logfields.Error, err,
					)
				}
				return nil, nil
			}
			return createKCNPCRD(ctx, logger, clientset)
		},
	}
}

func createKCNPCRD(ctx context.Context, logger *slog.Logger, clientset apiextensionsclient.Interface) ([]*apiextensionsv1.CustomResourceDefinition, error) {
	crd, err := getPregeneratedKCNPCRD()
	if err != nil {
		return nil, err
	}
	installedCRD, err := crdhelpers.CreateUpdateCRD(
		ctx,
		logger,
		clientset,
		&crd,
		crdhelpers.NewDefaultPoller(),
		newNeedsUpdateKCNPFunc(logger),
	)
	if err != nil {
		return nil, fmt.Errorf("Unable to create custom resource definition %s: %w", synced.KCNPCRDName, err)
	}
	if crdhelpers.CRDNeedsMigration(installedCRD) {
		return []*apiextensionsv1.CustomResourceDefinition{installedCRD}, nil
	}
	return nil, nil
}

func getPregeneratedKCNPCRD() (apiextensionsv1.CustomResourceDefinition, error) {
	crd := apiextensionsv1.CustomResourceDefinition{}
	if err := yaml.Unmarshal(kcnpCRDBytes, &crd); err != nil {
		return apiextensionsv1.CustomResourceDefinition{}, fmt.Errorf("error unmarshalling pregenerated CRD %s: %w", synced.KCNPCRDName, err)
	}
	return crd, nil
}

// kcnpBundleVersion returns the version of the upstream network-policy-api
// release the given CRD originates from.
func kcnpBundleVersion(crd *apiextensionsv1.CustomResourceDefinition) (semver.Version, error) {
	v, ok := crd.Annotations[kcnpBundleVersionAnnotation]
	if !ok {
		return semver.Version{}, fmt.Errorf("missing %s annotation on CRD %s", kcnpBundleVersionAnnotation, crd.Name)
	}
	version, err := versioncheck.Version(v)
	if err != nil {
		return semver.Version{}, fmt.Errorf("invalid %s annotation on CRD %s: %w", kcnpBundleVersionAnnotation, crd.Name, err)
	}
	return version, nil
}

func newNeedsUpdateKCNPFunc(logger *slog.Logger) crdhelpers.NeedUpdateCRDFunc {
	return func(targetCRD, currentCRD *apiextensionsv1.CustomResourceDefinition) (bool, error) {
		if currentCRD.Spec.Versions[0].Schema == nil {
			// no validation detected
			return true, nil
		}

		targetVersion, err := kcnpBundleVersion(targetCRD)
		if err != nil {
			return false, err
		}
		currentVersion, err := kcnpBundleVersion(currentCRD)
		if err != nil {
			// version in cluster is either missing or unparsable
			return true, nil
		}

		// Never replace a CRD originating from a different release channel
		// (e.g. experimental), as that could remove fields which are in use.
		// Only warn if it is outdated, so that the user can update it.
		if channel, ok := currentCRD.Annotations[kcnpChannelAnnotation]; ok && channel != targetCRD.Annotations[kcnpChannelAnnotation] {
			if currentVersion.LT(targetVersion) {
				logger.Warn(
					"The installed CRD is outdated, but it is not updated as it originates from a different release channel than the one managed by the operator. "+
						"Please update it manually.",
					logfields.CRDName, currentCRD.Name,
					logfields.ReleaseChannel, channel,
					logfields.CurrentVersion, currentVersion,
					logfields.NewVersion, targetVersion,
				)
			}
			return false, nil
		}

		// Upgrade the CRD only if the in-cluster version is older than the
		// target one, so as to never downgrade it.
		return currentVersion.LT(targetVersion), nil
	}
}
