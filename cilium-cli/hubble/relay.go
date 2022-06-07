// SPDX-License-Identifier: Apache-2.0
// Copyright 2020-2021 Authors of Cilium

package hubble

import (
	"context"
	"fmt"

	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/internal/utils"

	"github.com/cilium/cilium/pkg/versioncheck"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (k *K8sHubble) generateRelayService() (*corev1.Service, error) {
	var (
		svcFilename string
	)

	ciliumVer := k.helmState.Version
	switch {
	case versioncheck.MustCompile(">1.10.99")(ciliumVer):
		svcFilename = "templates/hubble-relay/service.yaml"
	case versioncheck.MustCompile(">1.8.99")(ciliumVer):
		svcFilename = "templates/hubble-relay-service.yaml"
	default:
		return nil, fmt.Errorf("cilium version unsupported %s", ciliumVer.String())
	}

	svcFile := k.manifests[svcFilename]

	var svc corev1.Service
	utils.MustUnmarshalYAML([]byte(svcFile), &svc)
	return &svc, nil
}

func (k *K8sHubble) generateRelayDeployment() (*appsv1.Deployment, error) {
	var (
		deployFilename string
	)

	ciliumVer := k.helmState.Version
	switch {
	case versioncheck.MustCompile(">1.10.99")(ciliumVer):
		deployFilename = "templates/hubble-relay/deployment.yaml"
	case versioncheck.MustCompile(">1.8.99")(ciliumVer):
		deployFilename = "templates/hubble-relay-deployment.yaml"
	default:
		return nil, fmt.Errorf("cilium version unsupported %s", ciliumVer.String())
	}

	deploymentFile := k.manifests[deployFilename]

	var deploy appsv1.Deployment
	utils.MustUnmarshalYAML([]byte(deploymentFile), &deploy)
	return &deploy, nil
}

func (k *K8sHubble) generateRelayConfigMap() (*corev1.ConfigMap, error) {
	var (
		cmFilename string
	)

	ciliumVer := k.helmState.Version
	switch {
	case versioncheck.MustCompile(">1.10.99")(ciliumVer):
		cmFilename = "templates/hubble-relay/configmap.yaml"
	case versioncheck.MustCompile(">1.8.99")(ciliumVer):
		cmFilename = "templates/hubble-relay-configmap.yaml"
	default:
		return nil, fmt.Errorf("cilium version unsupported %s", ciliumVer.String())
	}

	cmFile := k.manifests[cmFilename]

	var cm corev1.ConfigMap
	utils.MustUnmarshalYAML([]byte(cmFile), &cm)
	return &cm, nil
}

func (k *K8sHubble) disableRelay(ctx context.Context) error {
	k.Log("🔥 Deleting Relay...")

	relaySvc, err := k.generateRelayService()
	if err != nil {
		return err
	}
	k.client.DeleteService(ctx, relaySvc.GetNamespace(), relaySvc.GetName(), metav1.DeleteOptions{})

	relayDeployment, err := k.generateRelayDeployment()
	if err != nil {
		return err
	}
	k.client.DeleteDeployment(ctx, relayDeployment.GetNamespace(), relayDeployment.GetName(), metav1.DeleteOptions{})

	crb := k.NewClusterRoleBinding(defaults.RelayClusterRoleName)
	k.client.DeleteClusterRoleBinding(ctx, crb.GetName(), metav1.DeleteOptions{})

	cr := k.NewClusterRole(defaults.RelayClusterRoleName)
	k.client.DeleteClusterRole(ctx, cr.GetName(), metav1.DeleteOptions{})

	sa := k.NewServiceAccount(defaults.RelayServiceAccountName)
	k.client.DeleteServiceAccount(ctx, sa.GetNamespace(), sa.GetName(), metav1.DeleteOptions{})

	relayConfigMap, err := k.generateRelayConfigMap()
	if err != nil {
		return err
	}
	k.client.DeleteConfigMap(ctx, relayConfigMap.GetNamespace(), relayConfigMap.GetName(), metav1.DeleteOptions{})

	return k.deleteRelayCertificates(ctx)
}

func (k *K8sHubble) enableRelay(ctx context.Context) (string, error) {
	relayDeployment, err := k.generateRelayDeployment()
	if err != nil {
		return "", err
	}

	_, err = k.client.GetDeployment(ctx, relayDeployment.GetNamespace(), relayDeployment.GetName(), metav1.GetOptions{})
	if err == nil {
		k.Log("✅ Relay is already deployed")
		return relayDeployment.GetName(), nil
	}

	k.Log("✨ Generating certificates...")

	if err := k.createRelayCertificates(ctx); err != nil {
		return "", err
	}

	relayCm, err := k.generateRelayConfigMap()
	if err != nil {
		return "", err
	}
	k.Log("✨ Deploying Relay...")
	if _, err := k.client.CreateConfigMap(ctx, relayCm.GetNamespace(), relayCm, metav1.CreateOptions{}); err != nil {
		return "", err
	}

	sa := k.NewServiceAccount(defaults.RelayServiceAccountName)
	if _, err := k.client.CreateServiceAccount(ctx, sa.GetNamespace(), sa, metav1.CreateOptions{}); err != nil {
		return "", err
	}

	if _, err := k.client.CreateDeployment(ctx, relayDeployment.GetNamespace(), relayDeployment, metav1.CreateOptions{}); err != nil {
		return "", err
	}

	relaySvc, err := k.generateRelayService()
	if err != nil {
		return "", err
	}
	if _, err := k.client.CreateService(ctx, relaySvc.GetNamespace(), relaySvc, metav1.CreateOptions{}); err != nil {
		return "", err
	}

	return relayDeployment.GetName(), nil
}

func (k *K8sHubble) deleteRelayCertificates(ctx context.Context) error {
	k.Log("🔥 Deleting Relay certificates...")
	secret, err := k.generateRelayCertificate(defaults.RelayServerSecretName)
	if err != nil {
		return err
	}

	k.client.DeleteSecret(ctx, secret.GetNamespace(), secret.GetName(), metav1.DeleteOptions{})

	secret, err = k.generateRelayCertificate(defaults.RelayClientSecretName)
	if err != nil {
		return err
	}
	k.client.DeleteSecret(ctx, secret.GetNamespace(), secret.GetName(), metav1.DeleteOptions{})
	return nil
}

func (k *K8sHubble) createRelayCertificates(ctx context.Context) error {
	k.Log("🔑 Generating certificates for Relay...")
	// TODO we won't generate hubble-ui certificates because we don't want
	//  to give a bad UX for hubble-cli (which connects to hubble-relay)
	// if err := k.createRelayServerCertificate(ctx); err != nil {
	// 	return err
	// }

	return k.createRelayClientCertificate(ctx)
}

// TODO we won't generate hubble-ui certificates because we don't want
//  to give a bad UX for hubble-cli (which connects to hubble-relay)
// func (k *K8sHubble) createRelayServerCertificate(ctx context.Context) error {
// 	secret, err := k.generateRelayCertificate(defaults.RelayServerSecretName)
// 	if err != nil {
// 		return err
// 	}
//
// 	_, err = k.client.CreateSecret(ctx, secret.GetNamespace(), &secret, metav1.CreateOptions{})
// 	if err != nil {
// 		return fmt.Errorf("unable to create secret %s/%s: %w", secret.GetNamespace(), secret.GetName(), err)
// 	}
//
// 	return nil
// }

func (k *K8sHubble) createRelayClientCertificate(ctx context.Context) error {
	secret, err := k.generateRelayCertificate(defaults.RelayClientSecretName)
	if err != nil {
		return err
	}

	_, err = k.client.CreateSecret(ctx, secret.GetNamespace(), &secret, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("unable to create secret %s/%s: %w", secret.GetNamespace(), secret.GetName(), err)
	}

	return nil
}

func (k *K8sHubble) generateRelayCertificate(name string) (corev1.Secret, error) {
	var (
		relaySecretFilename string
	)

	ciliumVer := k.helmState.Version

	switch {
	case versioncheck.MustCompile(">1.10.99")(ciliumVer):
		switch name {
		case defaults.RelayServerSecretName:
			relaySecretFilename = "templates/hubble/tls-helm/relay-server-secret.yaml"
		case defaults.RelayClientSecretName:
			relaySecretFilename = "templates/hubble/tls-helm/relay-client-secret.yaml"
		}
	case versioncheck.MustCompile(">1.8.99")(ciliumVer):
		switch name {
		case defaults.RelayServerSecretName:
			relaySecretFilename = "templates/hubble-relay-tls-server-secret.yaml"
		case defaults.RelayClientSecretName:
			relaySecretFilename = "templates/hubble-relay-client-tls-secret.yaml"
		}
	}

	relayFile := k.manifests[relaySecretFilename]

	var secret corev1.Secret
	utils.MustUnmarshalYAML([]byte(relayFile), &secret)
	return secret, nil
}

func (k *K8sHubble) PortForwardCommand(ctx context.Context) error {
	helmState, err := k.client.GetHelmState(ctx, k.params.Namespace, k.params.HelmValuesSecretName)
	if err != nil {
		return err
	}

	// Generate the manifests has if hubble was being enabled so that we can
	// retrieve all UI and Relay's resource names.
	k.params.UI = true
	k.params.Relay = true
	err = k.generateManifestsEnable(ctx, false, helmState.Values)
	if err != nil {
		return err
	}

	relaySvc, err := k.generateRelayService()
	if err != nil {
		return err
	}
	args := []string{
		"port-forward",
		"-n", k.params.Namespace,
		"svc/hubble-relay",
		"--address", "0.0.0.0",
		"--address", "::",
		fmt.Sprintf("%d:%d", k.params.PortForward, relaySvc.Spec.Ports[0].Port)}

	if k.params.Context != "" {
		args = append([]string{"--context", k.params.Context}, args...)
	}

	_, err = utils.Exec(k, "kubectl", args...)
	return err
}
