// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package install

import (
	"context"
	"fmt"
	"strings"

	"helm.sh/helm/v3/pkg/cli"
	"helm.sh/helm/v3/pkg/getter"
	appsv1 "k8s.io/api/apps/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"sigs.k8s.io/yaml"

	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/internal/helm"
	"github.com/cilium/cilium-cli/internal/utils"
	"github.com/cilium/cilium-cli/status"
)

func (k *K8sInstaller) Upgrade(ctx context.Context) error {
	k.autodetect(ctx)

	// no need to determine KPR setting on upgrade, keep the setting configured with the old
	// version.
	if err := k.detectDatapathMode(ctx, false); err != nil {
		return err
	}

	daemonSet, err := k.client.GetDaemonSet(ctx, k.params.Namespace, defaults.AgentDaemonSetName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("unable to retrieve DaemonSet of cilium-agent: %s", err)
	}

	deployment, err := k.client.GetDeployment(ctx, k.params.Namespace, defaults.OperatorDeploymentName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("unable to retrieve Deployment of cilium-operator: %s", err)
	}

	var patched int

	if err = upgradeDeployment(ctx, k, upgradeDeploymentParams{
		deployment:         deployment,
		imageIncludeDigest: k.fqOperatorImage(utils.ImagePathIncludeDigest),
		imageExcludeDigest: k.fqOperatorImage(utils.ImagePathExcludeDigest),
		containerName:      defaults.OperatorContainerName,
	}, &patched); err != nil {
		return err
	}

	agentImage := k.fqAgentImage(utils.ImagePathIncludeDigest)
	var containerPatches []string
	for _, c := range daemonSet.Spec.Template.Spec.Containers {
		if c.Image != agentImage {
			containerPatches = append(containerPatches, `{"name":"`+c.Name+`", "image":"`+agentImage+`"}`)
		}
	}
	var initContainerPatches []string
	for _, c := range daemonSet.Spec.Template.Spec.InitContainers {
		if c.Image != agentImage {
			initContainerPatches = append(initContainerPatches, `{"name":"`+c.Name+`", "image":"`+agentImage+`"}`)
		}
	}

	if len(containerPatches) == 0 && len(initContainerPatches) == 0 {
		k.Log("✅ Cilium is already up to date")
	} else {
		k.Log("🚀 Upgrading cilium to version %s...", k.fqAgentImage(utils.ImagePathExcludeDigest))

		patch := []byte(`{"spec":{"template":{"spec":{"containers":[` + strings.Join(containerPatches, ",") + `], "initContainers":[` + strings.Join(initContainerPatches, ",") + `]}}}}`)
		_, err = k.client.PatchDaemonSet(ctx, k.params.Namespace, defaults.AgentDaemonSetName, types.StrategicMergePatchType, patch, metav1.PatchOptions{})
		if err != nil {
			return fmt.Errorf("unable to patch DaemonSet %s with patch %q: %w", defaults.AgentDaemonSetName, patch, err)
		}

		patched++
	}

	hubbleRelayDeployment, err := k.client.GetDeployment(ctx, k.params.Namespace, defaults.RelayDeploymentName, metav1.GetOptions{})
	if err != nil && !k8serrors.IsNotFound(err) {
		return fmt.Errorf("unable to retrieve Deployment of %s: %w", defaults.RelayDeploymentName, err)
	}

	if err == nil { // only update if hubble relay deployment was found on the cluster
		if err = upgradeDeployment(ctx, k, upgradeDeploymentParams{
			deployment:         hubbleRelayDeployment,
			imageIncludeDigest: k.fqRelayImage(utils.ImagePathIncludeDigest),
			imageExcludeDigest: k.fqRelayImage(utils.ImagePathExcludeDigest),
			containerName:      defaults.RelayContainerName,
		}, &patched); err != nil {
			return err
		}
	}

	clustermeshAPIServerDeployment, err := k.client.GetDeployment(ctx, k.params.Namespace, defaults.ClusterMeshDeploymentName, metav1.GetOptions{})
	if err != nil && !k8serrors.IsNotFound(err) {
		return fmt.Errorf("unable to retrieve Deployment of %s: %w", defaults.ClusterMeshDeploymentName, err)
	}

	if err == nil { // only update clustermesh-apiserver if deployment was found on the cluster
		if err = upgradeDeployment(ctx, k, upgradeDeploymentParams{
			deployment:         clustermeshAPIServerDeployment,
			imageIncludeDigest: k.fqClusterMeshAPIImage(utils.ImagePathIncludeDigest),
			imageExcludeDigest: k.fqClusterMeshAPIImage(utils.ImagePathExcludeDigest),
			containerName:      defaults.ClusterMeshContainerName,
		}, &patched); err != nil {
			return err
		}
	}

	if patched > 0 && k.params.Wait {
		k.Log("⌛ Waiting for Cilium to be upgraded...")
		collector, err := status.NewK8sStatusCollector(k.client, status.K8sStatusParameters{
			Namespace:       k.params.Namespace,
			Wait:            true,
			WaitDuration:    k.params.WaitDuration,
			WarningFreePods: []string{defaults.AgentDaemonSetName, defaults.OperatorDeploymentName, defaults.RelayDeploymentName, defaults.ClusterMeshDeploymentName},
		})
		if err != nil {
			return err
		}

		s, err := collector.Status(ctx)
		if err != nil {
			fmt.Print(s.Format())
			return err
		}
	}

	return nil
}

type upgradeDeploymentParams struct {
	deployment         *appsv1.Deployment
	imageIncludeDigest string
	imageExcludeDigest string
	containerName      string
}

func upgradeDeployment(ctx context.Context, k *K8sInstaller, params upgradeDeploymentParams, patched *int) error {
	if params.deployment.Spec.Template.Spec.Containers[0].Image == params.imageIncludeDigest ||
		params.deployment.Spec.Template.Spec.Containers[0].Image == params.imageExcludeDigest {
		k.Log("✅ %s is already up to date", params.deployment.Name)
		return nil
	}

	k.Log("🚀 Upgrading %s to version %s...", params.deployment.Name, params.imageExcludeDigest)
	containerPath := fmt.Sprintf(`{"spec":{"template":{"spec":{"containers":[{"name": "%s", "image":"`, params.containerName)
	patch := []byte(containerPath + params.imageIncludeDigest + `"}]}}}}`)

	_, err := k.client.PatchDeployment(ctx, k.params.Namespace, params.deployment.Name, types.StrategicMergePatchType, patch, metav1.PatchOptions{})
	if err != nil {
		return fmt.Errorf("unable to patch Deployment %s with patch %q: %w", params.deployment.Name, patch, err)
	}

	*patched++
	return nil
}

func (k *K8sInstaller) UpgradeWithHelm(ctx context.Context, k8sClient genericclioptions.RESTClientGetter) error {
	if k.params.ListVersions {
		return k.listVersions()
	}
	if err := k.preinstall(ctx); err != nil {
		return err
	}

	vals, err := k.params.HelmOpts.MergeValues(getter.All(cli.New()))
	if err != nil {
		return err
	}

	upgradeParams := helm.UpgradeParameters{
		Namespace:    k.params.Namespace,
		Name:         defaults.HelmReleaseName,
		Chart:        k.chart, // k.chart was initialized in NewK8sInstaller, based on Version and HelmChartDirectory
		Values:       vals,
		ResetValues:  k.params.HelmResetValues,
		ReuseValues:  k.params.HelmReuseValues,
		Wait:         k.params.Wait,
		WaitDuration: k.params.WaitDuration,

		// In addition to the DryRun i/o, we need to tell Helm not to execute the upgrade
		DryRun:           k.params.DryRun,
		DryRunHelmValues: k.params.DryRunHelmValues,
	}
	release, err := helm.Upgrade(ctx, k8sClient, upgradeParams)

	if k.params.DryRun {
		fmt.Println(release.Manifest)
	}
	if k.params.DryRunHelmValues {
		helmValues, err := yaml.Marshal(release.Config)
		if err != nil {
			return err
		}
		fmt.Println(string(helmValues))
	}

	return err
}
