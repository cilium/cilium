// Copyright 2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"fmt"
	"strings"

	"github.com/cilium/cilium/certgen/defaults"
	"github.com/cilium/cilium/certgen/generate"
	"github.com/cilium/cilium/certgen/option"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/version"

	cfsslLog "github.com/cloudflare/cfssl/log"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const binaryName = "cilium-certgen"

func New() *cobra.Command {
	vp := viper.New()
	rootCmd := &cobra.Command{
		Use:           binaryName + " [flags]",
		Short:         binaryName,
		Long:          binaryName + " bootstraps TLS certificates and stores them as K8s secrets",
		SilenceErrors: true,
		Version:       version.Version,
		Run: func(cmd *cobra.Command, args []string) {
			option.Config.PopulateFrom(vp)
			if option.Config.Debug {
				logging.SetLogLevel(logrus.DebugLevel)
			}
			cfsslLog.SetLogger(&sysLogger{
				l: logging.DefaultLogger.WithField(logfields.LogSubsys, "cfssl"),
			})
			log := logging.DefaultLogger.WithField(logfields.LogSubsys, binaryName)
			log.Infof("%s %s", binaryName, version.Version)
			if err := generateCertificates(); err != nil {
				log.Fatal(err)
			}
		},
	}
	rootCmd.SetVersionTemplate("{{with .Name}}{{printf \"%s \" .}}{{end}}{{printf \"v%s\" .Version}}\n")

	flags := rootCmd.PersistentFlags()
	flags.BoolP(option.Debug, "D", defaults.Debug, "Enable debug messages")

	flags.String(option.K8sKubeConfigPath, "", "Path to the K8s kubeconfig file. If absent, the in-cluster config is used.")
	flags.Duration(option.K8sRequestTimeout, defaults.K8sRequestTimeout, "Timeout for K8s API requests")

	flags.String(option.HubbleCACertFile, "", "Path to provided Hubble CA certificate file (required if Hubble CA is not generated)")
	flags.String(option.HubbleCAKeyFile, "", "Path to provided Hubble CA key file (required if Hubble CA is not generated)")

	flags.Bool(option.HubbleCAGenerate, defaults.HubbleCAGenerate, "Generate and store Hubble CA certificate")
	flags.String(option.HubbleCACommonName, defaults.HubbleCACommonName, "Hubble CA common name")
	flags.Duration(option.HubbleCAValidityDuration, defaults.HubbleCAValidityDuration, "Hubble CA validity duration")
	flags.String(option.HubbleCAConfigMapName, defaults.HubbleCAConfigMapName, "Name of the K8s ConfigMap where the Hubble CA cert is stored in")
	flags.String(option.HubbleCAConfigMapNamespace, defaults.HubbleCAConfigMapNamespace, "Namespace of the ConfigMap where the Hubble CA cert is stored in")

	flags.Bool(option.HubbleRelayClientCertGenerate, defaults.HubbleRelayClientCertGenerate, "Generate and store Hubble Relay client certificate")
	flags.String(option.HubbleRelayClientCertCommonName, defaults.HubbleRelayClientCertCommonName, "Hubble Relay client certificate common name")
	flags.Duration(option.HubbleRelayClientCertValidityDuration, defaults.HubbleRelayClientCertValidityDuration, "Hubble Relay client certificate validity duration")
	flags.String(option.HubbleRelayClientCertSecretName, defaults.HubbleRelayClientCertSecretName, "Name of the K8s Secret where the Hubble Relay client cert and key are stored in")
	flags.String(option.HubbleRelayClientCertSecretNamespace, defaults.HubbleRelayClientCertSecretNamespace, "Namespace of the K8s Secret where the Hubble Relay client cert and key are stored in")

	flags.Bool(option.HubbleRelayServerCertGenerate, defaults.HubbleRelayServerCertGenerate, "Generate and store Hubble Relay server certificate")
	flags.String(option.HubbleRelayServerCertCommonName, defaults.HubbleRelayServerCertCommonName, "Hubble Relay server certificate common name")
	flags.Duration(option.HubbleRelayServerCertValidityDuration, defaults.HubbleRelayServerCertValidityDuration, "Hubble Relay server certificate validity duration")
	flags.String(option.HubbleRelayServerCertSecretName, defaults.HubbleRelayServerCertSecretName, "Name of the K8s Secret where the Hubble Relay server cert and key are stored in")
	flags.String(option.HubbleRelayServerCertSecretNamespace, defaults.HubbleRelayServerCertSecretNamespace, "Namespace of the K8s Secret where the Hubble Relay server cert and key are stored in")

	flags.Bool(option.HubbleServerCertGenerate, defaults.HubbleServerCertGenerate, "Generate and store Hubble server certificate")
	flags.String(option.HubbleServerCertCommonName, defaults.HubbleServerCertCommonName, "Hubble server certificate common name")
	flags.Duration(option.HubbleServerCertValidityDuration, defaults.HubbleServerCertValidityDuration, "Hubble server certificate validity duration")
	flags.String(option.HubbleServerCertSecretName, defaults.HubbleServerCertSecretName, "Name of the K8s Secret where the Hubble server cert and key are stored in")
	flags.String(option.HubbleServerCertSecretNamespace, defaults.HubbleServerCertSecretNamespace, "Namespace of the K8s Secret where the Hubble server cert and key are stored in")

	// Sets up viper to read in flags via CILIUM_CERTGEN_ env variables
	vp.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	vp.SetEnvPrefix(binaryName)
	vp.AutomaticEnv()
	vp.BindPFlags(flags)

	return rootCmd
}

// Execute runs the root command. This is called by main.main().
func Execute() error {
	return New().Execute()
}

// k8sConfig creates a new Kubernetes config either based on the provided
// kubeconfig file or alternatively the in-cluster configuration.
func k8sConfig(kubeconfig string) (*kubernetes.Clientset, error) {
	var config *rest.Config
	var err error
	if kubeconfig == "" {
		config, err = rest.InClusterConfig()
	} else {
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
	}

	if err != nil {
		return nil, err
	}
	return kubernetes.NewForConfig(config)
}

// generateCertificates runs the main code to generate and store certificate
func generateCertificates() error {
	k8sClient, err := k8sConfig(option.Config.K8sKubeConfigPath)
	if err != nil {
		return fmt.Errorf("failed initialize kubernetes client: %w", err)
	}

	hubbleCA := generate.NewCA(option.Config.HubbleCAConfigMapName, option.Config.HubbleCAConfigMapNamespace)
	if option.Config.HubbleCAGenerate {
		err = hubbleCA.Generate(option.Config.HubbleCACommonName, option.Config.HubbleCAValidityDuration)
		if err != nil {
			return fmt.Errorf("failed to generate Hubble CA: %w", err)
		}
	} else {
		err = hubbleCA.LoadFromFile(option.Config.HubbleCACertFile, option.Config.HubbleCAKeyFile)
		if err != nil {
			return fmt.Errorf("failed to load Hubble CA: %w", err)
		}
	}

	var hubbleServerCert *generate.Cert
	if option.Config.HubbleServerCertGenerate {
		hubbleServerCert = generate.NewCert(
			option.Config.HubbleServerCertCommonName,
			option.Config.HubbleServerCertValidityDuration,
			defaults.HubbleServerCertUsage,
			option.Config.HubbleServerCertSecretName,
			option.Config.HubbleServerCertSecretNamespace,
		)
		err := hubbleServerCert.Generate(hubbleCA.CACert, hubbleCA.CAKey)
		if err != nil {
			return fmt.Errorf("failed to generate Hubble server cert: %w", err)
		}
	}

	var hubbleRelayClientCert *generate.Cert
	if option.Config.HubbleRelayClientCertGenerate {
		hubbleRelayClientCert = generate.NewCert(
			option.Config.HubbleRelayClientCertCommonName,
			option.Config.HubbleRelayClientCertValidityDuration,
			defaults.HubbleRelayClientCertUsage,
			option.Config.HubbleRelayClientCertSecretName,
			option.Config.HubbleRelayClientCertSecretNamespace,
		)
		err := hubbleRelayClientCert.Generate(hubbleCA.CACert, hubbleCA.CAKey)
		if err != nil {
			return fmt.Errorf("failed to generate Hubble Relay client cert: %w", err)
		}
	}

	var hubbleRelayServerCert *generate.Cert
	if option.Config.HubbleRelayServerCertGenerate {
		hubbleRelayServerCert = generate.NewCert(
			option.Config.HubbleRelayServerCertCommonName,
			option.Config.HubbleRelayServerCertValidityDuration,
			defaults.HubbleRelayServerCertUsage,
			option.Config.HubbleRelayServerCertSecretName,
			option.Config.HubbleRelayServerCertSecretNamespace,
		)
		err := hubbleRelayServerCert.Generate(hubbleCA.CACert, hubbleCA.CAKey)
		if err != nil {
			return fmt.Errorf("failed to generate Hubble Relay server cert: %w", err)
		}
	}

	if option.Config.HubbleCAGenerate {
		if err := hubbleCA.StoreAsConfigMap(k8sClient); err != nil {
			return fmt.Errorf("failed to create configmap for Hubble CA: %w", err)
		}
	}

	if option.Config.HubbleServerCertGenerate {
		if err := hubbleServerCert.StoreAsSecret(k8sClient); err != nil {
			return fmt.Errorf("failed to create secret for Hubble server cert: %w", err)
		}
	}

	if option.Config.HubbleRelayClientCertGenerate {
		if err := hubbleRelayClientCert.StoreAsSecret(k8sClient); err != nil {
			return fmt.Errorf("failed to create secret for Hubble Relay client cert: %w", err)
		}
	}

	if option.Config.HubbleRelayServerCertGenerate {
		if err := hubbleRelayServerCert.StoreAsSecret(k8sClient); err != nil {
			return fmt.Errorf("failed to create secret for Hubble Relay server cert: %w", err)
		}
	}

	return nil
}
