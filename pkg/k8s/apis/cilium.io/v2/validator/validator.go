// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package validator

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/sirupsen/logrus"
	apiextensionsinternal "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apiextensions-apiserver/pkg/apiserver/validation"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/kube-openapi/pkg/validation/validate"

	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/client"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy/api"
)

// NPValidator is a validator structure used to validate CNP and CCNP.
type NPValidator struct {
	cnpValidator  *validate.SchemaValidator
	ccnpValidator *validate.SchemaValidator
}

func NewNPValidator() (*NPValidator, error) {
	// There are some default variables set by the CustomResourceValidation
	// Marshaller so we need to marshal and unmarshal the CNPCRV to have those
	// default values, the same way k8s api-server has it.
	cnpCRVJSONBytes, err := json.Marshal(
		client.GetPregeneratedCRD(client.CNPCRDName).Spec.Versions[0].Schema,
	)
	if err != nil {
		return nil, fmt.Errorf("BUG: unable to marshall CNPCRV: %w", err)
	}
	var cnpCRV apiextensionsv1.CustomResourceValidation
	err = json.Unmarshal(cnpCRVJSONBytes, &cnpCRV)
	if err != nil {
		return nil, fmt.Errorf("BUG: unable to unmarshall CNPCRV: %w", err)
	}

	var cnpInternal apiextensionsinternal.CustomResourceValidation
	err = apiextensionsv1.Convert_v1_CustomResourceValidation_To_apiextensions_CustomResourceValidation(
		&cnpCRV,
		&cnpInternal,
		nil,
	)
	if err != nil {
		return nil, err
	}
	cnpValidator, _, err := validation.NewSchemaValidator(&cnpInternal)
	if err != nil {
		return nil, err
	}

	// There are some default variables set by the CustomResourceValidation
	// Marshaller so we need to marshal and unmarshal the CCNPCRV to have those
	// default values, the same way k8s api-server has it.
	ccnpCRVJSONBytes, err := json.Marshal(
		client.GetPregeneratedCRD(client.CCNPCRDName).Spec.Versions[0].Schema,
	)
	if err != nil {
		return nil, fmt.Errorf("BUG: unable to marshall CCNPCRV: %w", err)
	}
	var ccnpCRV apiextensionsv1.CustomResourceValidation
	err = json.Unmarshal(ccnpCRVJSONBytes, &ccnpCRV)
	if err != nil {
		return nil, fmt.Errorf("BUG: unable to unmarshall CCNPCRV: %w", err)
	}

	var ccnpInternal apiextensionsinternal.CustomResourceValidation
	err = apiextensionsv1.Convert_v1_CustomResourceValidation_To_apiextensions_CustomResourceValidation(
		&ccnpCRV,
		&ccnpInternal,
		nil,
	)
	if err != nil {
		return nil, err
	}
	ccnpValidator, _, err := validation.NewSchemaValidator(&ccnpInternal)
	if err != nil {
		return nil, err
	}

	return &NPValidator{
		cnpValidator:  cnpValidator,
		ccnpValidator: ccnpValidator,
	}, nil
}

// ValidateCNP validates the given CNP accordingly the CNP validation schema.
func (n *NPValidator) ValidateCNP(cnp *unstructured.Unstructured) error {
	if errs := validation.ValidateCustomResource(nil, &cnp, n.cnpValidator); len(errs) > 0 {
		return errs.ToAggregate()
	}

	if err := detectUnknownFields(cnp); err != nil {
		return err
	}

	return nil
}

var (
	// We can remove the check for this warning once 1.9 is the oldest supported Cilium version.
	errWildcardToFromEndpointMessage = "It seems you have a CiliumClusterwideNetworkPolicy " +
		"with a wildcard to/from endpoint selector. The behavior of this selector has been " +
		"changed. The selector now only allows traffic to/from Cilium managed K8s endpoints, " +
		"instead of acting as a truly empty endpoint selector allowing all traffic. To " +
		"ensure that the policy behavior does not affect your workloads, consider adding " +
		"another policy that allows traffic to/from world and cluster entities. For a more " +
		"detailed discussion on the topic, see https://github.com/cilium/cilium/issues/12844"

	logOnce sync.Once
)

// ValidateCCNP validates the given CCNP accordingly the CCNP validation schema.
func (n *NPValidator) ValidateCCNP(ccnp *unstructured.Unstructured) error {
	if errs := validation.ValidateCustomResource(nil, &ccnp, n.ccnpValidator); len(errs) > 0 {
		return errs.ToAggregate()
	}

	if err := detectUnknownFields(ccnp); err != nil {
		return err
	}

	if err := checkWildCardToFromEndpoint(ccnp); err != nil {
		return err
	}

	return nil
}

func checkWildCardToFromEndpoint(ccnp *unstructured.Unstructured) error {
	logger := log.WithFields(logrus.Fields{
		logfields.CiliumClusterwideNetworkPolicyName: ccnp.GetName(),
	})

	// At this point we have validated the custom resource with the new CRV.
	// We can try converting it to the new CCNP type.
	// This should not fail, so we are not returning any errors, just logging
	// a warning.
	ccnpBytes, err := ccnp.MarshalJSON()
	if err != nil {
		return err
	}

	resCCNP := cilium_v2.CiliumClusterwideNetworkPolicy{}
	err = json.Unmarshal(ccnpBytes, &resCCNP)
	if err != nil {
		return err
	}

	// Print the warninig only once per CCNP.
	if resCCNP.Spec != nil {
		if containsWildcardToFromEndpoint(resCCNP.Spec) {
			logOnce.Do(func() {
				logger.Error(errWildcardToFromEndpointMessage)
			})
			return fmt.Errorf("use of empty toEndpoints/fromEndpoints selector")
		}
	}

	if resCCNP.Specs != nil {
		for _, rule := range resCCNP.Specs {
			if containsWildcardToFromEndpoint(rule) {
				logOnce.Do(func() {
					logger.Error(errWildcardToFromEndpointMessage)
				})
				return fmt.Errorf("use of empty toEndpoints/fromEndpoints selector")
			}
		}
	}

	return nil
}

// containsWildcardToFromEndpoint returns true if a CCNP contains an empty endpoint selector
// in ingress/egress rules.
// For more information - https://github.com/cilium/cilium/issues/12844#issuecomment-672074170
func containsWildcardToFromEndpoint(rule *api.Rule) bool {
	if len(rule.Ingress) > 0 {
		for _, r := range rule.Ingress {
			// We only check for the presence of wildcard to/fromEndpoints
			// in the network policy spec.
			if len(r.FromEndpoints) > 0 {
				for _, epSel := range r.FromEndpoints {
					if epSel.IsWildcard() {
						return true
					}
				}
			}
		}
	}

	if len(rule.Egress) > 0 {
		for _, r := range rule.Egress {
			if len(r.ToEndpoints) > 0 {
				for _, epSel := range r.ToEndpoints {
					if epSel.IsWildcard() {
						return true
					}
				}
			}
		}
	}

	return false
}
