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
	"context"
	"fmt"
	"os"
	"time"

	"github.com/cilium/cilium/pkg/k8s"
	v2_validation "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2/validator"
	"github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/scheme"
	k8sconfig "github.com/cilium/cilium/pkg/k8s/config"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/option"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	apiextensionsclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

var validateCNP = &cobra.Command{
	Use:   "validate-cnp",
	Short: "Validate Cilium Network Policies deployed in the cluster",
	Long: `Before upgrading Cilium it is recommended to run this validation checker
to make sure the policies deployed are valid. The validator will verify if all policies
deployed in the cluster are valid, in case they are not, an error is printed and the
has an exit code -1 is returned.`,
	Run: func(cmd *cobra.Command, args []string) {
		err := validateCNPs()
		if err != nil {
			log.Error(err)
			os.Exit(-1)
		}
	},
}

const (
	validateK8sPoliciesTimeout = 5 * time.Minute
	ciliumGroup                = "cilium.io"
)

func validateCNPs() error {
	// The internal packages log things. Make sure they follow the setup of of
	// the CLI tool.
	logging.DefaultLogger.SetFormatter(log.Formatter)

	log.Info("Setting up Kubernetes client")

	k8sClientQPSLimit := viper.GetFloat64(option.K8sClientQPSLimit)
	k8sClientBurst := viper.GetInt(option.K8sClientBurst)

	k8s.Configure(k8sAPIServer, k8sKubeConfigPath, float32(k8sClientQPSLimit), k8sClientBurst)

	if err := k8s.Init(k8sconfig.NewDefaultConfiguration()); err != nil {
		log.WithError(err).Fatal("Unable to connect to Kubernetes apiserver")
	}

	restConfig, err := k8s.CreateConfig()
	if err != nil {
		return fmt.Errorf("Unable to create rest configuration for k8s CRD: %w", err)
	}
	apiExtensionsClient, err := apiextensionsclient.NewForConfig(restConfig)
	if err != nil {
		return fmt.Errorf("Unable to create API extensions clientset for k8s CRD: %w", err)
	}

	npValidator, err := v2_validation.NewNPValidator()
	if err != nil {
		return err
	}

	ctx, initCancel := context.WithTimeout(context.Background(), validateK8sPoliciesTimeout)
	defer initCancel()
	cnpErr := validateNPResources(ctx, apiExtensionsClient, npValidator.ValidateCNP, "ciliumnetworkpolicies", "CiliumNetworkPolicy")

	ctx, initCancel2 := context.WithTimeout(context.Background(), validateK8sPoliciesTimeout)
	defer initCancel2()
	ccnpErr := validateNPResources(ctx, apiExtensionsClient, npValidator.ValidateCCNP, "ciliumclusterwidenetworkpolicies", "CiliumClusterwideNetworkPolicy")

	if cnpErr != nil {
		return cnpErr
	}
	if ccnpErr != nil {
		return ccnpErr
	}
	log.Info("All CCNPs and CNPs valid!")
	return nil
}

func validateNPResources(
	ctx context.Context,
	apiExtensionsClient apiextensionsclient.Interface,
	validator func(cnp *unstructured.Unstructured) error,
	name,
	shortName string,
) error {
	// check if the crd is installed at all
	_, err := apiExtensionsClient.ApiextensionsV1beta1().CustomResourceDefinitions().Get(ctx, name+"."+ciliumGroup, metav1.GetOptions{})
	switch {
	case err == nil:
	case k8sErrors.IsNotFound(err):
		return nil
	default:
		return err
	}

	var (
		policyErr error
		cnps      unstructured.UnstructuredList
		cnpName   string
	)
	for {
		opts := metav1.ListOptions{
			Limit:    25,
			Continue: cnps.GetContinue(),
		}
		err = k8s.CiliumClient().
			Interface.
			CiliumV2().
			RESTClient().
			Get().
			VersionedParams(&opts, scheme.ParameterCodec).
			Resource(name).
			Do(ctx).
			Into(&cnps)
		if err != nil {
			return err
		}

		for _, cnp := range cnps.Items {
			if cnp.GetNamespace() != "" {
				cnpName = fmt.Sprintf("%s/%s", cnp.GetNamespace(), cnp.GetName())
			} else {
				cnpName = cnp.GetName()
			}
			if err := validator(&cnp); err != nil {
				log.WithField(shortName, cnpName).WithError(err).Error("Unexpected validation error")
				policyErr = fmt.Errorf("Found invalid %s", shortName)
			} else {
				log.WithField(shortName, cnpName).Info("Validation OK!")
			}
		}
		if cnps.GetContinue() == "" {
			break
		}
	}
	return policyErr
}
