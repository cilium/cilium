// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	v2_validation "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2/validator"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/scheme"
	k8sversion "github.com/cilium/cilium/pkg/k8s/version"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/option"
)

func validateCNPCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "validate-cnp",
		Short: "Validate Cilium Network Policies deployed in the cluster",
		Long: `Before upgrading Cilium it is recommended to run this validation checker
to make sure the policies deployed are valid. The validator will verify if all policies
deployed in the cluster are valid, in case they are not, an error is printed and the
has an exit code 1 is returned.`,
	}

	hive := hive.New(
		k8sClient.Cell,

		cell.Invoke(func(lc hive.Lifecycle, clientset k8sClient.Clientset, shutdowner hive.Shutdowner) {
			lc.Append(hive.Hook{
				OnStart: func(hive.HookContext) error { return validateCNPs(clientset, shutdowner) },
			})
		}),
	)
	hive.SetTimeouts(validateK8sPoliciesTimeout, validateK8sPoliciesTimeout)
	hive.RegisterFlags(cmd.Flags())

	cmd.Run = func(cmd *cobra.Command, args []string) {
		// The internal packages log things. Make sure they follow the setup of of
		// the CLI tool.
		logging.DefaultLogger.SetFormatter(log.Formatter)

		if err := hive.Run(); err != nil {
			log.Fatal(err)
		}
	}
	return cmd
}

const (
	validateK8sPoliciesTimeout = 5 * time.Minute
	ciliumGroup                = "cilium.io"
)

func validateCNPs(clientset k8sClient.Clientset, shutdowner hive.Shutdowner) error {
	defer shutdowner.Shutdown()

	if !clientset.IsEnabled() {
		return fmt.Errorf("Kubernetes client not configured. Please provide configuration via --%s or --%s",
			option.K8sAPIServer, option.K8sKubeConfigPath)
	}

	npValidator, err := v2_validation.NewNPValidator()
	if err != nil {
		return err
	}

	ctx, initCancel := context.WithTimeout(context.Background(), validateK8sPoliciesTimeout)
	defer initCancel()
	cnpErr := validateNPResources(ctx, clientset, npValidator.ValidateCNP, "ciliumnetworkpolicies", "CiliumNetworkPolicy")

	ctx, initCancel2 := context.WithTimeout(context.Background(), validateK8sPoliciesTimeout)
	defer initCancel2()
	ccnpErr := validateNPResources(ctx, clientset, npValidator.ValidateCCNP, "ciliumclusterwidenetworkpolicies", "CiliumClusterwideNetworkPolicy")

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
	clientset k8sClient.Clientset,
	validator func(cnp *unstructured.Unstructured) error,
	name,
	shortName string,
) error {
	// Check if the crd is installed at all.
	var err error
	if k8sversion.Capabilities().APIExtensionsV1CRD {
		_, err = clientset.ApiextensionsV1().CustomResourceDefinitions().Get(
			ctx,
			name+"."+ciliumGroup,
			metav1.GetOptions{},
		)
	} else {
		_, err = clientset.ApiextensionsV1beta1().CustomResourceDefinitions().Get(
			ctx,
			name+"."+ciliumGroup,
			metav1.GetOptions{},
		)
	}
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
		err = clientset.
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
