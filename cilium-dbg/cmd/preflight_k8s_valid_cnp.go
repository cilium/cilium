// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/spf13/cobra"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/cilium/cilium/pkg/hive"
	v2_validation "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2/validator"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/scheme"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
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

		cell.Invoke(func(logger *slog.Logger, lc cell.Lifecycle, clientset k8sClient.Clientset, shutdowner hive.Shutdowner) {
			lc.Append(cell.Hook{
				OnStart: func(cell.HookContext) error { return validateCNPs(logger, clientset, shutdowner) },
			})
		}),
	)
	hive.RegisterFlags(cmd.Flags())

	cmd.Run = func(cmd *cobra.Command, args []string) {
		if err := hive.Run(logging.DefaultSlogLogger); err != nil {
			logging.Fatal(log, err.Error())
		}
	}
	return cmd
}

const (
	validateK8sPoliciesTimeout = 5 * time.Minute
	ciliumGroup                = "cilium.io"
)

func validateCNPs(logger *slog.Logger, clientset k8sClient.Clientset, shutdowner hive.Shutdowner) error {
	defer shutdowner.Shutdown()

	if !clientset.IsEnabled() {
		return fmt.Errorf("Kubernetes client not configured. Please provide configuration via --%s or --%s",
			option.K8sAPIServer, option.K8sKubeConfigPath)
	}

	npValidator, err := v2_validation.NewNPValidator(logger)
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
	_, err := clientset.ApiextensionsV1().CustomResourceDefinitions().Get(
		ctx,
		name+"."+ciliumGroup,
		metav1.GetOptions{},
	)
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
				log.Error("Unexpected validation error",
					logfields.Error, err,
					logfields.Type, shortName,
					logfields.Name, cnpName,
				)
				policyErr = fmt.Errorf("Found invalid %s", shortName)
			} else {
				log.Info("Validation OK!",
					logfields.Type, shortName,
					logfields.Name, cnpName,
				)
			}
		}
		if cnps.GetContinue() == "" {
			break
		}
	}
	return policyErr
}
