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
	cnpExcluded, cnpErr := validateNPResources(
		ctx,
		clientset,
		npValidator.ValidateCNP,
		parseCNPRules,
		"ciliumnetworkpolicies",
		"CiliumNetworkPolicy",
	)

	ctx, initCancel2 := context.WithTimeout(context.Background(), validateK8sPoliciesTimeout)
	defer initCancel2()
	ccnpExcluded, ccnpErr := validateNPResources(
		ctx,
		clientset,
		npValidator.ValidateCCNP,
		parseCCNPRules,
		"ciliumclusterwidenetworkpolicies",
		"CiliumClusterwideNetworkPolicy",
	)

	if cnpErr != nil {
		return cnpErr
	}
	if ccnpErr != nil {
		return ccnpErr
	}

	if cnpExcluded || ccnpExcluded {
		log.Warn("All CCNPs and CNPs are valid, but some policies reference identity-excluded labels!")
		return nil
	}

	log.Info("All CCNPs and CNPs valid!")
	return nil
}

type policyLister func(ctx context.Context, cont string) (*unstructured.UnstructuredList, error)

// validateNPResources checks that the resource's CRD is installed and, if so,
// validates all of its objects via the validatePolicies core.
func validateNPResources(
	ctx context.Context,
	clientset k8sClient.Clientset,
	validate func(cnp *unstructured.Unstructured) error,
	parse func(cnp *unstructured.Unstructured) (api.Rules, error),
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

	list := func(ctx context.Context, cont string) (*unstructured.UnstructuredList, error) {
		var cnps unstructured.UnstructuredList
		err := clientset.
			CiliumV2().
			RESTClient().
			Get().
			VersionedParams(&metav1.ListOptions{Limit: 25, Continue: cont}, scheme.ParameterCodec).
			Resource(name).
			Do(ctx).
			Into(&cnps)
		return &cnps, err
	}

	return validatePolicies(ctx, list, validate, parse, shortName)
}

// validatePolicies validates every policy returned by list and warns about
// selectors referencing labels excluded from the security identity. It returns
// whether any policy referenced such a label.
func validatePolicies(
	ctx context.Context,
	list policyLister,
	validate func(cnp *unstructured.Unstructured) error,
	parse func(cnp *unstructured.Unstructured) (api.Rules, error),
	shortName string,
) (bool, error) {
	var (
		policyErr error
		excluded  bool
		cont      string
	)
	for {
		cnps, err := list(ctx, cont)
		if err != nil {
			return false, err
		}

		for _, cnp := range cnps.Items {
			cnpName := cnp.GetName()
			if ns := cnp.GetNamespace(); ns != "" {
				cnpName = ns + "/" + cnpName
			}

			if err := validate(&cnp); err != nil {
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

			rules, err := parse(&cnp)
			if err != nil {
				log.Error("Unable to parse policy for identity-label check",
					logfields.Error, err,
					logfields.Type, shortName,
					logfields.Name, cnpName,
				)
				policyErr = fmt.Errorf("Found invalid %s", shortName)
			} else if warnExcludedIdentityLabels(rules, shortName, cnpName) {
				excluded = true
			}
		}

		cont = cnps.GetContinue()
		if cont == "" {
			break
		}
	}
	return excluded, policyErr
}

func parseCNPRules(rawCNP *unstructured.Unstructured) (api.Rules, error) {
	var cnp cilium_v2.CiliumNetworkPolicy
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(rawCNP.Object, &cnp); err != nil {
		return nil, err
	}
	return cnp.Parse(log, "")
}

func parseCCNPRules(rawCNP *unstructured.Unstructured) (api.Rules, error) {
	var ccnp cilium_v2.CiliumClusterwideNetworkPolicy
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(rawCNP.Object, &ccnp); err != nil {
		return nil, err
	}
	return ccnp.Parse(log, "")
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
// filter would drop. Selectors here come from Parse(), whose keys are source
// encoded (e.g. "any:topology.kubernetes.io/zone"); Map2Labels/NewLabel strip
// that source prefix, recovering the bare key the filter matches against.
func excludedSelectorKeys(sel api.EndpointSelector) []string {
	if sel.LabelSelector == nil {
		return nil
	}

	lbls := labels.Map2Labels(sel.MatchLabels, labels.LabelSourceAny)
	for _, req := range sel.MatchExpressions {
		l := labels.NewLabel(req.Key, "", labels.LabelSourceAny)
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
