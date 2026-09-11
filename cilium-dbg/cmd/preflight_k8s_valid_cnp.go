// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
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
	"github.com/cilium/cilium/pkg/slices"
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

// errExcludedLabels flags a policy selector referencing labels that are excluded
// from the security identity.
var errExcludedLabels = errors.New("selector references labels excluded from the security identity")

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

	// Initialize the label filter with the built-in defaults so we can warn about
	// selectors referencing labels excluded from the security identity.
	if err := labelsfilter.ParseLabelPrefixCfg(logger, nil, nil, ""); err != nil {
		return err
	}

	ctx, initCancel := context.WithTimeout(context.Background(), validateK8sPoliciesTimeout)
	defer initCancel()
	cnpExcluded, cnpErr := validateNPResources(ctx, clientset,
		validate(npValidator.ValidateCNP, checkCNPExcludedLabels),
		"ciliumnetworkpolicies", "CiliumNetworkPolicy")

	ctx, initCancel2 := context.WithTimeout(context.Background(), validateK8sPoliciesTimeout)
	defer initCancel2()
	ccnpExcluded, ccnpErr := validateNPResources(ctx, clientset,
		validate(npValidator.ValidateCCNP, checkCCNPExcludedLabels),
		"ciliumclusterwidenetworkpolicies", "CiliumClusterwideNetworkPolicy")

	if err := errors.Join(cnpErr, ccnpErr); err != nil {
		return err
	}
	if !cnpExcluded && !ccnpExcluded {
		log.Info("All CCNPs and CNPs valid!")
	}
	return nil
}

// policyValidator inspects a single policy object. Validators are composed with
// validate() and share the unstructured representation returned by the lister.
type policyValidator func(*unstructured.Unstructured) error

func validate(validators ...policyValidator) policyValidator {
	return func(policy *unstructured.Unstructured) error {
		for _, v := range validators {
			if err := v(policy); err != nil {
				return err
			}
		}
		return nil
	}
}

// validateNPResources runs validate against every policy of the given resource,
// reporting whether any of them referenced identity-excluded labels.
func validateNPResources(
	ctx context.Context,
	clientset k8sClient.Clientset,
	validate policyValidator,
	name,
	shortName string,
) (bool, error) {
	// Check if the crd is installed at all.
	if _, err := clientset.ApiextensionsV1().CustomResourceDefinitions().Get(
		ctx,
		name+"."+ciliumGroup,
		metav1.GetOptions{},
	); err != nil {
		if k8sErrors.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}

	var (
		policyErr error
		excluded  bool
		nps       unstructured.UnstructuredList
		npName    string
	)
	for {
		opts := metav1.ListOptions{
			Limit:    25,
			Continue: nps.GetContinue(),
		}
		if err := clientset.
			CiliumV2().
			RESTClient().
			Get().
			VersionedParams(&opts, scheme.ParameterCodec).
			Resource(name).
			Do(ctx).
			Into(&nps); err != nil {
			return false, err
		}

		for _, np := range nps.Items {
			if np.GetNamespace() != "" {
				npName = fmt.Sprintf("%s/%s", np.GetNamespace(), np.GetName())
			} else {
				npName = np.GetName()
			}

			switch err := validate(&np); {
			case err == nil:
				log.Info("Validation OK!",
					logfields.Type, shortName,
					logfields.Name, npName,
				)
			case errors.Is(err, errExcludedLabels):
				log.Warn("Policy selector references labels excluded from the security identity; "+
					"it will not match endpoints unless overridden via --label-prefix-file",
					logfields.Error, err,
					logfields.Type, shortName,
					logfields.Name, npName,
				)
				excluded = true
			default:
				log.Error("Unexpected validation error",
					logfields.Error, err,
					logfields.Type, shortName,
					logfields.Name, npName,
				)
				policyErr = fmt.Errorf("Found invalid %s", shortName)
			}
		}
		if nps.GetContinue() == "" {
			break
		}
	}

	if excluded {
		log.Warn(fmt.Sprintf("Detected %s resources with selectors referencing identity-excluded labels; "+
			"see the warnings above. Such selectors will not match endpoints unless overridden "+
			"via --label-prefix-file.", shortName))
	}

	return excluded, policyErr
}

// parseable extracts a policy's rules. It is implemented by both
// CiliumNetworkPolicy and CiliumClusterwideNetworkPolicy.
type parseable interface {
	Parse(logger *slog.Logger, clusterName string) (api.Rules, error)
}

func checkCNPExcludedLabels(rawCNP *unstructured.Unstructured) error {
	var cnp cilium_v2.CiliumNetworkPolicy
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(rawCNP.Object, &cnp); err != nil {
		return err
	}
	return checkExcludedLabels(&cnp)
}

func checkCCNPExcludedLabels(rawCCNP *unstructured.Unstructured) error {
	var ccnp cilium_v2.CiliumClusterwideNetworkPolicy
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(rawCCNP.Object, &ccnp); err != nil {
		return err
	}
	return checkExcludedLabels(&ccnp)
}

// checkExcludedLabels returns errExcludedLabels listing the policy's selector
// label keys that the identity label filter would drop, or nil if there is none.
func checkExcludedLabels(policy parseable) error {
	rules, err := policy.Parse(log, "")
	if err != nil {
		return err
	}

	var keys []string
	for _, rule := range rules {
		for _, sel := range endpointSelectors(rule) {
			keys = append(keys, excludedSelectorKeys(sel)...)
		}
	}
	if len(keys) == 0 {
		return nil
	}
	return fmt.Errorf("%w: %s", errExcludedLabels, strings.Join(slices.Unique(keys), ", "))
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
