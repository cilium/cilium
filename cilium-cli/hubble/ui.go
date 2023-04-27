// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package hubble

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/internal/utils"

	"github.com/cilium/cilium/pkg/versioncheck"
	"github.com/pkg/browser"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (k *K8sHubble) generateHubbleUIService() (*corev1.Service, error) {
	var (
		svcFilename string
	)

	ciliumVer := k.helmState.Version
	switch {
	case versioncheck.MustCompile(">1.10.99")(ciliumVer):
		svcFilename = "templates/hubble-ui/service.yaml"
	case versioncheck.MustCompile(">1.8.99")(ciliumVer):
		svcFilename = "templates/hubble-ui-service.yaml"
	default:
		return nil, fmt.Errorf("cilium version unsupported %s", ciliumVer.String())
	}

	svcFile := k.manifests[svcFilename]

	var svc corev1.Service
	utils.MustUnmarshalYAML([]byte(svcFile), &svc)
	return &svc, nil
}

func (k *K8sHubble) generateHubbleUIConfigMap() (*corev1.ConfigMap, error) {
	var (
		cmFilename string
	)

	ciliumVer := k.helmState.Version
	switch {
	case versioncheck.MustCompile(">1.10.99")(ciliumVer):
		cmFilename = "templates/hubble-ui/configmap.yaml"
	case versioncheck.MustCompile(">1.8.99")(ciliumVer):
		cmFilename = "templates/hubble-ui-configmap.yaml"
	default:
		return nil, fmt.Errorf("cilium version unsupported %s", ciliumVer.String())
	}

	cmFile := k.manifests[cmFilename]

	var cm corev1.ConfigMap
	utils.MustUnmarshalYAML([]byte(cmFile), &cm)
	return &cm, nil
}

func (k *K8sHubble) generateHubbleUIDeployment() (*appsv1.Deployment, error) {
	var (
		deployFilename string
	)

	ciliumVer := k.helmState.Version
	switch {
	case versioncheck.MustCompile(">1.10.99")(ciliumVer):
		deployFilename = "templates/hubble-ui/deployment.yaml"
	case versioncheck.MustCompile(">1.8.99")(ciliumVer):
		deployFilename = "templates/hubble-ui-deployment.yaml"
	default:
		return nil, fmt.Errorf("cilium version unsupported %s", ciliumVer.String())
	}

	deploymentFile := k.manifests[deployFilename]

	var deploy appsv1.Deployment
	utils.MustUnmarshalYAML([]byte(deploymentFile), &deploy)
	return &deploy, nil
}

func (k *K8sHubble) disableUI(ctx context.Context) error {
	k.Log("🔥 Deleting Hubble UI...")

	hubbleUISvc, err := k.generateHubbleUIService()
	if err != nil {
		return err
	}
	k.client.DeleteService(ctx, hubbleUISvc.GetNamespace(), hubbleUISvc.GetName(), metav1.DeleteOptions{})

	hubbleUIDeploy, err := k.generateHubbleUIDeployment()
	if err != nil {
		return err
	}
	k.client.DeleteDeployment(ctx, hubbleUIDeploy.GetNamespace(), hubbleUIDeploy.GetName(), metav1.DeleteOptions{})

	crb := k.NewClusterRoleBinding(defaults.HubbleUIClusterRoleName)
	k.client.DeleteClusterRoleBinding(ctx, crb.GetName(), metav1.DeleteOptions{})

	cr := k.NewClusterRole(defaults.HubbleUIClusterRoleName)
	k.client.DeleteClusterRole(ctx, cr.GetName(), metav1.DeleteOptions{})

	sa := k.NewServiceAccount(defaults.HubbleUIServiceAccountName)
	k.client.DeleteServiceAccount(ctx, sa.GetNamespace(), sa.GetName(), metav1.DeleteOptions{})

	hubbleUICM, err := k.generateHubbleUIConfigMap()
	if err != nil {
		return err
	}
	k.client.DeleteConfigMap(ctx, hubbleUICM.GetNamespace(), hubbleUICM.GetName(), metav1.DeleteOptions{})

	return k.deleteUICertificates()
}

func (k *K8sHubble) deleteUICertificates() error {
	// TODO we won't generate hubble-ui certificates because we don't want
	//  to give a bad UX for hubble-cli (which connects to hubble-relay)
	// k.Log("🔥 Deleting Hubble UI certificates...")
	// secret, err := k.generateUICertificate(defaults.HubbleUIClientSecretName)
	// if err != nil {
	// 	return err
	// }
	//
	// k.client.DeleteSecret(ctx, secret.GetNamespace(), secret.GetName(), metav1.DeleteOptions{})

	return nil
}

func (k *K8sHubble) enableUI(ctx context.Context) (string, error) {
	hubbleUIDeploy, err := k.generateHubbleUIDeployment()
	if err != nil {
		return "", err
	}

	_, err = k.client.GetDeployment(ctx, hubbleUIDeploy.GetNamespace(), hubbleUIDeploy.GetName(), metav1.GetOptions{})
	if err == nil {
		k.Log("✅ Hubble UI is already deployed")
		return hubbleUIDeploy.GetName(), nil
	}

	// TODO we won't generate hubble-ui certificates because we don't want
	//  to give a bad UX for hubble-cli (which connects to hubble-relay)
	// k.Log("✨ Generating certificates...")
	//
	// if err := k.createUICertificates(ctx); err != nil {
	// 	return "", err
	// }

	hubbleUICM, err := k.generateHubbleUIConfigMap()
	if err != nil {
		return "", err
	}

	k.Log("✨ Deploying Hubble UI and Hubble UI Backend...")
	if _, err := k.client.CreateConfigMap(ctx, hubbleUICM.GetNamespace(), hubbleUICM, metav1.CreateOptions{}); err != nil {
		return "", err
	}

	sa := k.NewServiceAccount(defaults.HubbleUIServiceAccountName)
	if _, err := k.client.CreateServiceAccount(ctx, sa.GetNamespace(), sa, metav1.CreateOptions{}); err != nil {
		return "", err
	}

	if _, err := k.client.CreateClusterRole(ctx, k.NewClusterRole(defaults.HubbleUIClusterRoleName), metav1.CreateOptions{}); err != nil {
		return "", err
	}

	if _, err := k.client.CreateClusterRoleBinding(ctx, k.NewClusterRoleBinding(defaults.HubbleUIClusterRoleName), metav1.CreateOptions{}); err != nil {
		return "", err
	}

	if _, err := k.client.CreateDeployment(ctx, hubbleUIDeploy.GetNamespace(), hubbleUIDeploy, metav1.CreateOptions{}); err != nil {
		return "", err
	}

	hubbleUISvc, err := k.generateHubbleUIService()
	if err != nil {
		return "", err
	}
	if _, err := k.client.CreateService(ctx, hubbleUISvc.GetNamespace(), hubbleUISvc, metav1.CreateOptions{}); err != nil {
		return "", err
	}

	return hubbleUIDeploy.GetName(), nil
}

// TODO we won't generate hubble-ui certificates because we don't want
//  to give a bad UX for hubble-cli (which connects to hubble-relay)
// func (k *K8sHubble) createUICertificates(ctx context.Context) error {
// 	k.Log("🔑 Generating certificates for UI...")
// 	secret, err := k.generateUICertificate(defaults.HubbleUIClientSecretName)
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

// TODO we won't generate hubble-ui certificates because we don't want
//  to give a bad UX for hubble-cli (which connects to hubble-relay)
// func (k *K8sHubble) generateUICertificate(name string) (corev1.Secret, error) {
// 	var (
// 		relaySecretFilename string
// 	)
//
// 	ciliumVer := k.semVerCiliumVersion
//
// 	switch {
// 	case versioncheck.MustCompile(">1.10.99")(ciliumVer):
// 		switch name {
// 		case defaults.HubbleUIClientSecretName:
// 			relaySecretFilename = "templates/hubble/tls-helm/ui-client-certs.yaml"
// 		}
// 	}
//
// 	relayFile := k.manifests[relaySecretFilename]
//
// 	var secret corev1.Secret
// 	utils.MustUnmarshalYAML([]byte(relayFile), &secret)
// 	return secret, nil
// }

func (p *Parameters) UIPortForwardCommand() error {
	args := []string{
		"port-forward",
		"-n", p.Namespace,
		"svc/hubble-ui",
		"--address", "127.0.0.1",
		fmt.Sprintf("%d:80", p.UIPortForward)}

	if p.Context != "" {
		args = append([]string{"--context", p.Context}, args...)
	}

	go func() {
		time.Sleep(5 * time.Second)
		url := fmt.Sprintf("http://localhost:%d", p.UIPortForward)

		if p.UIOpenBrowser {
			// avoid cluttering stdout/stderr when opening the browser
			browser.Stdout = io.Discard
			browser.Stderr = io.Discard
			p.Log("ℹ️  Opening %q in your browser...", url)
			browser.OpenURL(url)
		} else {
			p.Log("ℹ️  Hubble UI is available at %q", url)
		}
	}()

	_, err := utils.Exec(p, "kubectl", args...)
	return err
}
