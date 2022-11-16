// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package check

import (
	"context"
	"fmt"

	"golang.org/x/exp/slices"
	"helm.sh/helm/v3/pkg/chartutil"
	"helm.sh/helm/v3/pkg/cli/values"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/internal/helm"
	"github.com/cilium/cilium-cli/internal/utils"
	"github.com/cilium/cilium-cli/k8s"
	"github.com/cilium/cilium-cli/status"
)

func (ct *ConnectivityTest) generateAgentDaemonSet() *appsv1.DaemonSet {
	dsFile := ct.manifests["templates/cilium-agent/daemonset.yaml"]

	var ds appsv1.DaemonSet
	utils.MustUnmarshalYAML([]byte(dsFile), &ds)
	return &ds
}

func (ct *ConnectivityTest) deleteCiliumPods(ctx context.Context) error {
	ct.Debug("Getting helm state")
	helmState, err := ct.client.GetHelmState(ctx, ct.params.CiliumNamespace, ct.params.HelmValuesSecretName)
	if err != nil {
		// if cilium-cli-helm-values secret was not found (e.g. cilium was not installed with cilium-cli)
		// or the secret parsing failed for whatever reason, then we create a default helm state.
		ct.Logf("Error parsing helm cli secret: %s", err)
		ct.Logf("Proceeding in unknown installation state")
		helmState, err = ct.generateDefaultHelmState(ctx, ct.client, ct.params.CiliumNamespace)
		if err != nil {
			return err
		}
	}

	ct.Debug("Generating manifest with updated node affinity")
	err = ct.generateManifestsNodeAffinity(ctx, helmState)
	if err != nil {
		return err
	}

	// If helm values secret is not present we should not write one to the cluster now
	if helmState.Secret != nil {
		ct.Infof("Storing helm values file in %s/%s Secret", ct.params.CiliumNamespace, ct.params.HelmValuesSecretName)

		helmState.Secret.Data[defaults.HelmValuesSecretKeyName] = []byte(ct.helmYAMLValues)
		if _, err := ct.client.UpdateSecret(ctx, ct.params.CiliumNamespace, helmState.Secret, metav1.UpdateOptions{}); err != nil {
			ct.Logf("Unable to store helm values file %s/%s Secret", ct.params.CiliumNamespace, ct.params.HelmValuesSecretName)
			return err
		}
	}

	ct.Info("Deleting Agent DaemonSet...")
	if err := ct.client.DeleteDaemonSet(ctx, ct.params.CiliumNamespace, defaults.AgentDaemonSetName, metav1.DeleteOptions{}); err != nil {
		ct.Fatalf("Cannot delete %s DaemonSet: %s", defaults.AgentDaemonSetName, err)
		return err
	}
	ct.Info("Re-creating Agent DaemonSet...")
	if _, err := ct.client.CreateDaemonSet(ctx, ct.params.CiliumNamespace, ct.generateAgentDaemonSet(), metav1.CreateOptions{}); err != nil {
		ct.Fatalf("Cannot re-create %s DaemonSet: %s", defaults.AgentDaemonSetName, err)
		return err
	}

	ct.Debugf("Deleting Cilium pods from nodes %v", ct.params.DeleteCiliumOnNodes)
	for _, node := range ct.params.DeleteCiliumOnNodes {
		ct.Infof("  Deleting Cilium pod on node %s by setting label %q", node, defaults.CiliumNoScheduleLabel)
		label := utils.EscapeJSONPatchString(defaults.CiliumNoScheduleLabel)
		labelPatch := fmt.Sprintf(`[{"op":"add","path":"/metadata/labels/%s","value":"true"}]`, label)
		_, err = ct.client.PatchNode(ctx, node, types.JSONPatchType, []byte(labelPatch))
		if err != nil {
			return err
		}
	}

	collector, err := status.NewK8sStatusCollector(ct.client, status.K8sStatusParameters{
		Namespace:       ct.params.CiliumNamespace,
		Wait:            true,
		WaitDuration:    defaults.StatusWaitDuration,
		WarningFreePods: []string{defaults.AgentDaemonSetName, defaults.OperatorDeploymentName},
	})
	if err != nil {
		return err
	}

	s, err := collector.Status(ctx)
	if err != nil {
		fmt.Print(s.Format())
		return err
	}

	// re-initialized list of Cilium pods
	ct.ciliumPods = make(map[string]Pod)
	ct.initCiliumPods(ctx)

	debugLogFeatures := func(header string) {
		if ct.debug() {
			fs := make([]Feature, 0, len(ct.features))
			for f := range ct.features {
				fs = append(fs, f)
			}
			slices.Sort(fs)
			ct.Debug(header)
			for _, f := range fs {
				ct.Debugf("  %s: %s", f, ct.features[f])
			}
		}
	}

	debugLogFeatures("Features before update:")
	// Update list node nodes without Cilium
	ct.UpdateFeaturesFromNodes(ctx)
	// Disable tests requiring L7 proxy to run, the L7 proxy isn't running anymore.
	ct.ForceDisableFeature(FeatureL7Proxy)
	// Disable tests requiring health checking, agent and thus cilium-health isn't running on
	// nodes where Cilium pods were deleted.
	ct.ForceDisableFeature(FeatureHealthChecking)
	debugLogFeatures("Features after update:")

	return nil
}

func (ct *ConnectivityTest) generateManifestsNodeAffinity(ctx context.Context, helmState *helm.State) error {
	helmMapOpts := map[string]string{}

	// Set affinity to prevent Cilium from being scheduled on nodes labeled with
	// "cilium.io/no-schedule=true"
	for k, v := range defaults.CiliumScheduleAffinity {
		helmMapOpts[k] = v
	}

	vals, err := helm.MergeVals(
		values.Options{},
		helmMapOpts,
		helmState.Values,
		nil,
	)
	if err != nil {
		return err
	}

	yamlValues, err := chartutil.Values(vals).YAML()
	if err != nil {
		return err
	}

	k8sVersionStr := ct.Params().K8sVersion
	if k8sVersionStr == "" {
		k8sVersion, err := ct.client.GetServerVersion()
		if err != nil {
			return fmt.Errorf("error getting Kubernetes version, try --k8s-version: %s", err)
		}
		k8sVersionStr = k8sVersion.String()
	}

	manifests, err := helm.GenManifests(
		ctx,
		ct.params.HelmChartDirectory,
		k8sVersionStr,
		helmState.Version,
		ct.params.CiliumNamespace,
		vals,
		[]string{},
	)
	if err != nil {
		return err
	}

	ct.manifests = manifests
	ct.helmYAMLValues = yamlValues
	return nil
}

func (ct *ConnectivityTest) generateDefaultHelmState(ctx context.Context, client *k8s.Client, namespace string) (*helm.State, error) {
	version, err := client.GetRunningCiliumVersion(ctx, namespace)
	if version == "" || err != nil {
		return nil, fmt.Errorf("unable to obtain cilium version, no Cilium pods found in namespace %q", namespace)
	}
	semVer, err := utils.ParseCiliumVersion(version)
	if err != nil {
		return nil, fmt.Errorf("unable to parse cilium version %s: %w", version, err)
	}
	return &helm.State{
		Secret:  nil,
		Version: semVer,
		Values:  chartutil.Values{},
	}, nil
}
