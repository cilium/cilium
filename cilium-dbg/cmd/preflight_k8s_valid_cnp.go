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
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/cilium/cilium/pkg/hive"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v2_validation "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2/validator"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/scheme"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/labelsfilter"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/api"
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
		if err := hive.Run(log); err != nil {
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
			option.K8sAPIServerURLs, option.K8sKubeConfigPath)
	}

	npValidator, err := v2_validation.NewNPValidator(logger)
	if err != nil {
		return err
	}

	// Initialize the label filter with the built-in defaults so we can warn
	// about policy selectors referencing labels excluded from the security
	// identity.
	if err := labelsfilter.ParseLabelPrefixCfg(logger, nil, nil, ""); err != nil {
		return err
	}

	ctx, initCancel := context.WithTimeout(context.Background(), validateK8sPoliciesTimeout)
	defer initCancel()
	cnpExcluded, cnpErr := validateNPResources(ctx, clientset, npValidator.ValidateCNP, "ciliumnetworkpolicies", "CiliumNetworkPolicy")

	ctx, initCancel2 := context.WithTimeout(context.Background(), validateK8sPoliciesTimeout)
	defer initCancel2()
	ccnpExcluded, ccnpErr := validateNPResources(ctx, clientset, npValidator.ValidateCCNP, "ciliumclusterwidenetworkpolicies", "CiliumClusterwideNetworkPolicy")

	if cnpErr != nil {
		return cnpErr
	}
	if ccnpErr != nil {
		return ccnpErr
	}
	log.Info("All CCNPs and CNPs valid!")

	if cnpExcluded || ccnpExcluded {
		log.Warn("Some policies reference identity-excluded labels!")
	}
	return nil
}

func validateNPResources(
	ctx context.Context,
	clientset k8sClient.Clientset,
	validator func(cnp *unstructured.Unstructured) error,
	name,
	shortName string,
) (bool, error) {
	// Check if the crd is installed at all.
	_, err := clientset.ApiextensionsV1().CustomResourceDefinitions().Get(
		ctx,
		name+"."+ciliumGroup,
		metav1.GetOptions{},
	)
	switch {
	case err == nil:
	case k8sErrors.IsNotFound(err):
		return false, nil
	default:
		return false, err
	}

	var (
		policyErr error
		excluded  bool
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
			return false, err
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

			rules, err := cnpRules(cnp)
			if err != nil {
				log.Warn("Unable to parse policy for identity-label check",
					logfields.Error, err,
					logfields.Type, shortName,
					logfields.Name, cnpName,
				)
			} else if warnExcludedIdentityLabels(rules, shortName, cnpName) {
				excluded = true
			}
		}
		if cnps.GetContinue() == "" {
			break
		}
	}
	return excluded, policyErr
}

func cnpRules(rawCNP unstructured.Unstructured) (api.Rules, error) {
	rules := api.Rules{}
	if rawCNP.GetNamespace() != "" {
		var cnp cilium_v2.CiliumNetworkPolicy
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(rawCNP.Object, &cnp); err != nil {
			return nil, err
		}
		if cnp.Spec != nil {
			rules = append(rules, cnp.Spec)
		}
		rules = append(rules, cnp.Specs...)
	} else {
		var ccnp cilium_v2.CiliumClusterwideNetworkPolicy
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(rawCNP.Object, &ccnp); err != nil {
			return nil, err
		}
		if ccnp.Spec != nil {
			rules = append(rules, ccnp.Spec)
		}
		rules = append(rules, ccnp.Specs...)
	}

	return rules, nil
}

// warnExcludedIdentityLabels logs an advisory warning for every endpoint-selector
// label key that the label filter would drop from the security identity. It
// returns true if the policy referenced at least one such label.
func warnExcludedIdentityLabels(rules api.Rules, shortName, cnpName string) bool {
	excluded := false
	for _, rule := range rules {
		for _, sel := range endpointSelectors(rule) {
			for _, key := range excludedSelectorKeys(sel) {
				log.Warn(
					"Policy selector references a label excluded from the security identity; "+
						"it will not match endpoints unless --label-prefix-file overrides",
					logfields.Type, shortName,
					logfields.Name, cnpName,
					logfields.Labels, key,
				)
				excluded = true
			}
		}
	}
	return excluded
}

// endpointSelectors returns the rule's EndpointSelectors that are matched against
// endpoint identities.
func endpointSelectors(rule *api.Rule) []api.EndpointSelector {
	sels := []api.EndpointSelector{rule.EndpointSelector}
	for _, ing := range rule.Ingress {
		sels = append(sels, ing.FromEndpoints...)
	}
	for _, ing := range rule.IngressDeny {
		sels = append(sels, ing.FromEndpoints...)
	}
	for _, egr := range rule.Egress {
		sels = append(sels, egr.ToEndpoints...)
	}
	for _, egr := range rule.EgressDeny {
		sels = append(sels, egr.ToEndpoints...)
	}
	return sels
}

// excludedSelectorKeys returns the selector's label keys that the identity label
// filter would drop. Keys are evaluated as Kubernetes labels (source k8s), as pod
// labels are presented to the filter.
func excludedSelectorKeys(sel api.EndpointSelector) []string {
	if sel.LabelSelector == nil {
		return nil
	}

	lbls := labels.Labels{}
	for k, v := range sel.MatchLabels {
		l := labels.NewLabel(k, string(v), labels.LabelSourceK8s)
		lbls[l.Key] = l
	}
	for _, req := range sel.MatchExpressions {
		l := labels.NewLabel(req.Key, "", labels.LabelSourceK8s)
		lbls[l.Key] = l
	}
	if len(lbls) == 0 {
		return nil
	}

	identity, _ := labelsfilter.Filter(lbls)

	var excluded []string
	for k, l := range lbls {
		if _, kept := identity[k]; !kept {
			excluded = append(excluded, l.Key)
		}
	}
	return excluded
}
