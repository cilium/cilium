// SPDX-License-Identifier: Apache-2.0
// Copyright 2020 Authors of Cilium

package hubble

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/internal/certs"
	"github.com/cilium/cilium-cli/internal/helm"
	"github.com/cilium/cilium-cli/internal/utils"
	"github.com/cilium/cilium-cli/status"

	"github.com/blang/semver/v4"
	"github.com/cilium/cilium/api/v1/models"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/versioncheck"
	"github.com/spf13/pflag"
	"helm.sh/helm/v3/pkg/chartutil"
	"helm.sh/helm/v3/pkg/cli/values"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	configNameEnableHubble  = "enable-hubble"
	configNameListenAddress = "hubble-listen-address"
)

type k8sHubbleImplementation interface {
	CreateSecret(ctx context.Context, namespace string, secret *corev1.Secret, opts metav1.CreateOptions) (*corev1.Secret, error)
	UpdateSecret(ctx context.Context, namespace string, secret *corev1.Secret, opts metav1.UpdateOptions) (*corev1.Secret, error)
	DeleteSecret(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error
	GetSecret(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*corev1.Secret, error)
	CreateServiceAccount(ctx context.Context, namespace string, account *corev1.ServiceAccount, opts metav1.CreateOptions) (*corev1.ServiceAccount, error)
	DeleteServiceAccount(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error
	CreateClusterRole(ctx context.Context, role *rbacv1.ClusterRole, opts metav1.CreateOptions) (*rbacv1.ClusterRole, error)
	DeleteClusterRole(ctx context.Context, name string, opts metav1.DeleteOptions) error
	CreateClusterRoleBinding(ctx context.Context, role *rbacv1.ClusterRoleBinding, opts metav1.CreateOptions) (*rbacv1.ClusterRoleBinding, error)
	DeleteClusterRoleBinding(ctx context.Context, name string, opts metav1.DeleteOptions) error
	CreateConfigMap(ctx context.Context, namespace string, config *corev1.ConfigMap, opts metav1.CreateOptions) (*corev1.ConfigMap, error)
	DeleteConfigMap(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error
	GetConfigMap(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*corev1.ConfigMap, error)
	UpdateConfigMap(ctx context.Context, configMap *corev1.ConfigMap, opts metav1.UpdateOptions) (*corev1.ConfigMap, error)
	CreateDeployment(ctx context.Context, namespace string, deployment *appsv1.Deployment, opts metav1.CreateOptions) (*appsv1.Deployment, error)
	GetDeployment(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*appsv1.Deployment, error)
	DeleteDeployment(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error
	CreateService(ctx context.Context, namespace string, service *corev1.Service, opts metav1.CreateOptions) (*corev1.Service, error)
	DeleteService(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error
	DeletePodCollection(ctx context.Context, namespace string, opts metav1.DeleteOptions, listOpts metav1.ListOptions) error
	ListPods(ctx context.Context, namespace string, options metav1.ListOptions) (*corev1.PodList, error)
	GetDaemonSet(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*appsv1.DaemonSet, error)
	CiliumStatus(ctx context.Context, namespace, pod string) (*models.StatusResponse, error)
	ListCiliumEndpoints(ctx context.Context, namespace string, opts metav1.ListOptions) (*ciliumv2.CiliumEndpointList, error)
	GetServerVersion() (*semver.Version, error)
	GetHelmState(ctx context.Context, namespace string, secretName string) (*helm.State, error)
}

type K8sHubble struct {
	client         k8sHubbleImplementation
	params         Parameters
	certManager    *certs.CertManager
	manifests      map[string]string
	helmYAMLValues string
	helmState      *helm.State
}

var (
	// FlagsToHelmOpts maps the deprecated install flags to the helm
	// options
	FlagsToHelmOpts = map[string][]string{
		"relay-image":      {"hubble.relay.image.override"},
		"relay-version":    {"hubble.relay.image.tag"},
		"ui-image":         {"hubble.ui.frontend.image.override"},
		"ui-backend-image": {"hubble.ui.backend.image.override"},
		"ui-version":       {"hubble.ui.frontend.image.tag", "hubble.ui.backend.image.tag"},
	}
	// FlagValues maps all FlagsToHelmOpts keys to their values
	FlagValues = map[string]pflag.Value{}
)

type Parameters struct {
	Namespace        string
	Relay            bool
	RelayImage       string
	RelayVersion     string
	RelayServiceType string
	PortForward      int
	CreateCA         bool
	UI               bool
	UIImage          string
	UIBackendImage   string
	UIVersion        string
	UIPortForward    int
	Writer           io.Writer
	Context          string // Only for 'kubectl' pass-through commands
	Wait             bool
	WaitDuration     time.Duration

	// K8sVersion is the Kubernetes version that will be used to generate the
	// kubernetes manifests. If the auto-detection fails, this flag can be used
	// as a workaround.
	K8sVersion string
	// HelmChartDirectory points to the location of a helm chart directory.
	// Useful to test from upstream where a helm release is not available yet.
	HelmChartDirectory string

	// HelmOpts are all the options the user used to pass into the Cilium cli
	// template.
	HelmOpts values.Options

	// HelmGenValuesFile points to the file that will store the generated helm
	// options.
	HelmGenValuesFile string

	// HelmValuesSecretName is the name of the secret where helm values will be
	// stored.
	HelmValuesSecretName string

	// RedactHelmCertKeys does not print helm certificate keys into the terminal.
	RedactHelmCertKeys bool
}

func (p *Parameters) Log(format string, a ...interface{}) {
	fmt.Fprintf(p.Writer, format+"\n", a...)
}

func (p *Parameters) validateParams() error {
	if p.RelayImage == defaults.RelayImage {
		if !utils.CheckVersion(p.RelayVersion) && p.RelayVersion != "" {
			return fmt.Errorf("invalid syntax %q for image tag", p.RelayVersion)
		}
	}
	if p.UIImage == defaults.HubbleUIImage || p.UIBackendImage == defaults.HubbleUIBackendImage {
		if !utils.CheckVersion(p.UIVersion) && p.UIVersion != "" {
			return fmt.Errorf("invalid syntax %q for image tag", p.UIVersion)
		}
	}
	return nil
}

func NewK8sHubble(ctx context.Context, client k8sHubbleImplementation, p Parameters) (*K8sHubble, error) {
	cm := certs.NewCertManager(client, certs.Parameters{Namespace: p.Namespace})
	helmState, err := client.GetHelmState(ctx, p.Namespace, p.HelmValuesSecretName)
	if err != nil {
		return nil, err
	}
	return &K8sHubble{
		client:      client,
		params:      p,
		certManager: cm,
		helmState:   helmState,
	}, nil
}

func (k *K8sHubble) Log(format string, a ...interface{}) {
	if k.params.RedactHelmCertKeys {
		formattedString := fmt.Sprintf(format+"\n", a...)
		for _, certKey := range []string{
			certs.EncodeCertBytes(k.certManager.CAKeyBytes()),
		} {
			if certKey != "" {
				formattedString = strings.ReplaceAll(formattedString, certKey, "[--- REDACTED WHEN PRINTING TO TERMINAL (USE --redact-helm-certificate-keys=false TO PRINT) ---]")
			}
		}
		fmt.Fprint(k.params.Writer, formattedString)
		return
	}
	fmt.Fprintf(k.params.Writer, format+"\n", a...)
}

func (k *K8sHubble) generatePeerService() *corev1.Service {
	var (
		svcFilename string
	)
	ciliumVer := k.helmState.Version
	switch {
	case versioncheck.MustCompile(">=1.11.0")(ciliumVer):
		svcFilename = "templates/hubble/peer-service.yaml"
	case versioncheck.MustCompile(">=1.9.0")(ciliumVer):
		svcFilename = "templates/hubble-peer-service.yaml"
	}
	if svcFilename == "" {
		return nil
	}

	svcFile, ok := k.manifests[svcFilename]
	if !ok || len(strings.TrimSpace(svcFile)) == 0 {
		return nil
	}

	var svc corev1.Service
	utils.MustUnmarshalYAML([]byte(svcFile), &svc)
	return &svc
}

func (k *K8sHubble) Validate(ctx context.Context) error {
	var failures int
	k.Log("✨ Validating cluster configuration...")

	cm, err := k.client.GetConfigMap(ctx, k.params.Namespace, defaults.ConfigMapName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("unable to retrieve ConfigMap %q: %w", defaults.ConfigMapName, err)
	}

	if cm.Data == nil {
		return fmt.Errorf("ConfigMap %q does not contain any configuration", defaults.ConfigMapName)
	}

	enableHubble, ok := cm.Data[configNameEnableHubble]
	if !ok {
		k.Log("❌ Hubble is not enabled in ConfigMap, %q is not set", configNameEnableHubble)
		failures++
	}

	if strings.ToLower(enableHubble) != "true" {
		k.Log("❌ Hubble is not enabled in ConfigMap, %q=%q must be set to true", configNameEnableHubble, enableHubble)
		failures++
	}

	_, ok = cm.Data[configNameListenAddress]
	if !ok {
		k.Log("❌ Hubble is not configured to listen on a network port, %q is not set", configNameListenAddress)
		failures++
	}

	if failures > 0 {
		return fmt.Errorf("%d validation errors", failures)
	}

	k.Log("✅ Valid configuration found")

	return nil

}

func (k *K8sHubble) disableHubble(ctx context.Context) error {
	k.Log("✨ Patching ConfigMap %s to disable Hubble...", defaults.ConfigMapName)

	return k.updateConfigMap(ctx)
}

func (k *K8sHubble) Disable(ctx context.Context) error {
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

	if err := k.disableUI(ctx); err != nil {
		return err
	}

	if err := k.disableRelay(ctx); err != nil {
		return err
	}

	if peerSvc := k.generatePeerService(); peerSvc != nil {
		k.Log("🔥 Deleting Peer Service...")
		k.client.DeleteService(ctx, peerSvc.GetNamespace(), peerSvc.GetName(), metav1.DeleteOptions{})
	}

	// Now that we have delete all UI and Relay's resource names then we can
	// generate the manifests with UI and Relay disabled.
	err = k.generateManifestsDisable(ctx, helmState.Values)
	if err != nil {
		return err
	}

	if err := k.disableHubble(ctx); err != nil {
		return err
	}

	k.Log("ℹ️  Storing helm values file in %s/%s Secret", k.params.Namespace, k.params.HelmValuesSecretName)

	helmState.Secret.Data[defaults.HelmValuesSecretKeyName] = []byte(k.helmYAMLValues)
	if _, err := k.client.UpdateSecret(ctx, k.params.Namespace, helmState.Secret, metav1.UpdateOptions{}); err != nil {
		k.Log("❌ Unable to store helm values file %s/%s Secret", k.params.Namespace, k.params.HelmValuesSecretName)
		return err
	}

	k.Log("✅ Hubble was successfully disabled.")

	return nil
}

func (k *K8sHubble) generateConfigMap() (*corev1.ConfigMap, error) {
	var (
		cmFilename string
	)

	ciliumVer := k.helmState.Version
	switch {
	case versioncheck.MustCompile(">=1.9.0")(ciliumVer):
		cmFilename = "templates/cilium-configmap.yaml"
	default:
		return nil, fmt.Errorf("cilium version unsupported %s", ciliumVer.String())
	}

	cmFile := k.manifests[cmFilename]

	var cm corev1.ConfigMap
	utils.MustUnmarshalYAML([]byte(cmFile), &cm)
	k.Log("🚀 Creating ConfigMap for Cilium version %s...", ciliumVer.String())

	return &cm, nil
}

func (k *K8sHubble) enableHubble(ctx context.Context) error {
	k.Log("✨ Patching ConfigMap %s to enable Hubble...", defaults.ConfigMapName)

	return k.updateConfigMap(ctx)
}

func (k *K8sHubble) updateConfigMap(ctx context.Context) error {
	cm, err := k.generateConfigMap()
	if err != nil {
		return err
	}

	_, err = k.client.UpdateConfigMap(ctx, cm, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("unable to patch ConfigMap %s with %s: %w", defaults.ConfigMapName, cm, err)
	}

	if err := k.client.DeletePodCollection(ctx, k.params.Namespace, metav1.DeleteOptions{}, metav1.ListOptions{LabelSelector: defaults.CiliumPodSelector}); err != nil {
		k.Log("⚠️  Unable to restart Cilium pods: %s", err)
	} else {
		k.Log("♻️  Restarted Cilium pods")
	}
	return nil
}

func (k *K8sHubble) generateManifestsEnable(ctx context.Context, printHelmTemplate bool, helmValues chartutil.Values) error {
	ciliumVer := k.helmState.Version

	helmMapOpts := map[string]string{}

	switch {
	// It's likely that certain helm options have changed since 1.9.0
	// These were tested for the >=1.11.0. In case something breaks for versions
	// older than 1.11.0 we will fix it afterwards.
	case versioncheck.MustCompile(">=1.9.0")(ciliumVer):
		// case versioncheck.MustCompile(">=1.11.0")(ciliumVer):

		// Pre-define all deprecated flags as helm options
		for flagName, helmOpts := range FlagsToHelmOpts {
			if v, ok := FlagValues[flagName]; ok {
				if val := v.String(); val != "" {
					for _, helmOpt := range helmOpts {
						helmMapOpts[helmOpt] = val
						switch helmOpt {
						// If the images or tag are overwritten then we need
						// to disable 'useDigest'
						case "hubble.relay.image.override", "hubble.relay.image.tag":
							helmMapOpts["hubble.relay.image.useDigest"] = "false"
						}
					}
				}
			}
		}

		helmMapOpts["hubble.enabled"] = "true"
		helmMapOpts["hubble.tls.ca.cert"] = certs.EncodeCertBytes(k.certManager.CACertBytes())
		helmMapOpts["hubble.tls.ca.key"] = certs.EncodeCertBytes(k.certManager.CAKeyBytes())

		if k.params.UI {
			helmMapOpts["hubble.ui.enabled"] = "true"
			// See for https://github.com/cilium/cilium/pull/19338 more details
			switch {
			case versioncheck.MustCompile(">=1.11.4")(ciliumVer):
			default:
				helmMapOpts["hubble.ui.securityContext.enabled"] = "false"
			}
		}
		if k.params.Relay {
			helmMapOpts["hubble.relay.enabled"] = "true"
			// TODO we won't generate hubble-ui certificates because we don't want
			//  to give a bad UX for hubble-cli (which connects to hubble-relay)
			// helmMapOpts["hubble.relay.tls.server.enabled"] = "true"
		}

	default:
		return fmt.Errorf("cilium version unsupported %s", ciliumVer.String())
	}

	return k.genManifests(ctx, printHelmTemplate, helmValues, helmMapOpts, ciliumVer)
}

func (k *K8sHubble) generateManifestsDisable(ctx context.Context, helmValues chartutil.Values) error {
	ciliumVer := k.helmState.Version

	helmMapOpts := map[string]string{}

	switch {
	// It's likely that certain helm options have changed since 1.9.0
	// These were tested for the >=1.11.0. In case something breaks for versions
	// older than 1.11.0 we will fix it afterwards.
	case versioncheck.MustCompile(">=1.9.0")(ciliumVer):
		// case versioncheck.MustCompile(">=1.11.0")(ciliumVer):
		helmMapOpts["hubble.enabled"] = "false"
		helmMapOpts["hubble.ui.enabled"] = "false"
		helmMapOpts["hubble.relay.enabled"] = "false"

	default:
		return fmt.Errorf("cilium version unsupported %s", ciliumVer.String())
	}

	return k.genManifests(ctx, false, helmValues, helmMapOpts, ciliumVer)
}

func (k *K8sHubble) genManifests(ctx context.Context, printHelmTemplate bool, prevHelmValues chartutil.Values, helmMapOpts map[string]string, ciliumVer semver.Version) error {
	// Store all the options passed by --config into helm extraConfig
	vals, err := helm.MergeVals(k, printHelmTemplate, k.params.HelmOpts, helmMapOpts, prevHelmValues, nil, k.params.HelmChartDirectory, ciliumVer.String(), k.params.Namespace)
	if err != nil {
		return err
	}

	yamlValue, err := chartutil.Values(vals).YAML()
	if err != nil {
		return err
	}

	if k.params.HelmGenValuesFile != "" {
		return os.WriteFile(k.params.HelmGenValuesFile, []byte(yamlValue), 0o600)
	}

	k8sVersionStr := k.params.K8sVersion
	if k8sVersionStr == "" {
		k8sVersion, err := k.client.GetServerVersion()
		if err != nil {
			return fmt.Errorf("error getting Kubernetes version, try --k8s-version: %s", err)
		}
		k8sVersionStr = k8sVersion.String()
	}

	manifests, err := helm.GenManifests(ctx, k.params.HelmChartDirectory, k8sVersionStr, ciliumVer.String(), k.params.Namespace, vals)
	if err != nil {
		return err
	}

	k.manifests = manifests
	k.helmYAMLValues = yamlValue
	return nil
}

func (k *K8sHubble) Enable(ctx context.Context) error {
	if err := k.params.validateParams(); err != nil {
		return err
	}

	caSecret, created, err := k.certManager.GetOrCreateCASecret(ctx, defaults.CASecretName, k.params.CreateCA)
	if err != nil {
		k.Log("❌ Unable to get or create the Cilium CA Secret: %s", err)
		return err
	}

	if caSecret != nil {
		err = k.certManager.LoadCAFromK8s(ctx, caSecret)
		if err != nil {
			k.Log("❌ Unable to load Cilium CA: %s", err)
			return err
		}
		if created {
			k.Log("🔑 Created CA in secret %s", caSecret.Name)
		} else {
			k.Log("🔑 Found CA in secret %s", caSecret.Name)
		}
	}

	helmState, err := k.client.GetHelmState(ctx, k.params.Namespace, k.params.HelmValuesSecretName)
	if err != nil {
		return err
	}

	err = k.generateManifestsEnable(ctx, true, helmState.Values)
	if err != nil {
		return err
	}

	if err := k.enableHubble(ctx); err != nil {
		return err
	}

	var dur time.Duration
	if k.params.Relay || k.params.UI {
		start := time.Now()
		k.Log("⌛ Waiting for Cilium to become ready before deploying other Hubble component(s)...")
		collector, err := status.NewK8sStatusCollector(k.client, status.K8sStatusParameters{
			Namespace:       k.params.Namespace,
			Wait:            true,
			WaitDuration:    k.params.WaitDuration,
			WarningFreePods: []string{defaults.AgentDaemonSetName, defaults.OperatorDeploymentName},
		})
		if err != nil {
			return err
		}
		dur = time.Since(start)

		s, err := collector.Status(ctx)
		if err != nil {
			fmt.Println(s.Format())
			return err
		}
	}

	if peerSvc := k.generatePeerService(); peerSvc != nil {
		k.Log("🚀 Creating Peer Service...")
		if _, err := k.client.CreateService(ctx, k.params.Namespace, peerSvc, metav1.CreateOptions{}); err != nil {
			return err
		}
	}

	var warnFreePods []string
	if k.params.Relay {
		podsName, err := k.enableRelay(ctx)
		if err != nil {
			return err
		}

		warnFreePods = append(warnFreePods, podsName)
	}

	if k.params.UI {
		podsName, err := k.enableUI(ctx)
		if err != nil {
			return err
		}

		warnFreePods = append(warnFreePods, podsName)
	}

	if k.params.Wait {
		k.Log("⌛ Waiting for Hubble to be installed...")
		collector, err := status.NewK8sStatusCollector(k.client, status.K8sStatusParameters{
			Namespace:       k.params.Namespace,
			Wait:            true,
			WaitDuration:    k.params.WaitDuration - dur,
			WarningFreePods: warnFreePods,
		})
		if err != nil {
			return err
		}

		s, err := collector.Status(ctx)
		if err != nil {
			fmt.Println(s.Format())
			return err
		}
	}

	k.Log("ℹ️  Storing helm values file in %s/%s Secret", k.params.Namespace, k.params.HelmValuesSecretName)

	helmState.Secret.Data[defaults.HelmValuesSecretKeyName] = []byte(k.helmYAMLValues)
	if _, err := k.client.UpdateSecret(ctx, k.params.Namespace, helmState.Secret, metav1.UpdateOptions{}); err != nil {
		k.Log("❌ Unable to store helm values file %s/%s Secret", k.params.Namespace, k.params.HelmValuesSecretName)
		return err
	}

	k.Log("✅ Hubble was successfully enabled!")

	return nil
}

func (k *K8sHubble) NewServiceAccount(name string) *corev1.ServiceAccount {
	var (
		saFileName string
	)

	ciliumVer := k.helmState.Version
	switch {
	case versioncheck.MustCompile(">1.10.99")(ciliumVer):
		switch name {
		case defaults.RelayServiceAccountName:
			saFileName = "templates/hubble-relay/serviceaccount.yaml"
		case defaults.HubbleUIServiceAccountName:
			saFileName = "templates/hubble-ui/serviceaccount.yaml"
		}
	case versioncheck.MustCompile(">=1.9.0")(ciliumVer):
		switch name {
		case defaults.RelayServiceAccountName:
			saFileName = "templates/hubble-relay-serviceaccount.yaml"
		case defaults.HubbleUIServiceAccountName:
			saFileName = "templates/hubble-ui-serviceaccount.yaml"
		}
	}

	saFile := k.manifests[saFileName]

	var sa corev1.ServiceAccount
	utils.MustUnmarshalYAML([]byte(saFile), &sa)
	return &sa
}

func (k *K8sHubble) NewClusterRole(name string) *rbacv1.ClusterRole {
	var (
		crFileName string
	)

	ciliumVer := k.helmState.Version
	switch {
	case versioncheck.MustCompile(">1.10.99")(ciliumVer):
		switch name {
		case defaults.RelayClusterRoleName:
			crFileName = "templates/hubble-relay/clusterrole.yaml"
		case defaults.HubbleUIClusterRoleName:
			crFileName = "templates/hubble-ui/clusterrole.yaml"
		}
	case versioncheck.MustCompile(">=1.9.0")(ciliumVer):
		switch name {
		case defaults.RelayClusterRoleName:
			crFileName = "templates/hubble-relay-clusterrole.yaml"
		case defaults.HubbleUIClusterRoleName:
			crFileName = "templates/hubble-ui-clusterrole.yaml"
		}
	}

	crFile := k.manifests[crFileName]

	var cr rbacv1.ClusterRole
	utils.MustUnmarshalYAML([]byte(crFile), &cr)
	return &cr
}

func (k *K8sHubble) NewClusterRoleBinding(crbName string) *rbacv1.ClusterRoleBinding {
	var (
		crbFileName string
	)

	ciliumVer := k.helmState.Version
	switch {
	case versioncheck.MustCompile(">1.10.99")(ciliumVer):
		switch crbName {
		case defaults.RelayClusterRoleName:
			crbFileName = "templates/hubble-relay/clusterrolebinding.yaml"
		case defaults.HubbleUIClusterRoleName:
			crbFileName = "templates/hubble-ui/clusterrolebinding.yaml"
		}
	case versioncheck.MustCompile(">=1.9.0")(ciliumVer):
		switch crbName {
		case defaults.RelayClusterRoleName:
			crbFileName = "templates/hubble-relay-clusterrolebinding.yaml"
		case defaults.HubbleUIClusterRoleName:
			crbFileName = "templates/hubble-ui-clusterrolebinding.yaml"
		}
	}

	crbFile := k.manifests[crbFileName]

	var crb rbacv1.ClusterRoleBinding
	utils.MustUnmarshalYAML([]byte(crbFile), &crb)
	return &crb
}
