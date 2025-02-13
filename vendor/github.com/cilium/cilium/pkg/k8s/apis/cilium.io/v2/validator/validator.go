// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package validator

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/client"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/sirupsen/logrus"
	apiextensionsinternal "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apiextensions-apiserver/pkg/apiserver/validation"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

var (
	// We can remove the check for this warning once 1.15 is the oldest supported Cilium version.
	logInitPolicyCNP = "It seems you have a CiliumNetworkPolicy with a " +
		"match on the 'reserved:init' labels. This label is not " +
		"supported in CiliumNetworkPolicy any more. If you wish to " +
		"define a policy for endpoints before they receive a full " +
		"security identity, change the resource type for the policy " +
		"to CiliumClusterwideNetworkPolicy."
	errInitPolicyCNP = fmt.Errorf("CiliumNetworkPolicy incorrectly matches reserved:init label")
	logOnce          sync.Once
)

// NPValidator is a validator structure used to validate CNP and CCNP.
type NPValidator struct {
	cnpValidator  validation.SchemaCreateValidator
	ccnpValidator validation.SchemaCreateValidator
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
	cnpValidator, _, err := validation.NewSchemaValidator(cnpInternal.OpenAPIV3Schema)
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
	ccnpValidator, _, err := validation.NewSchemaValidator(ccnpInternal.OpenAPIV3Schema)
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

	if err := checkInitLabelsPolicy(cnp); err != nil {
		return err
	}

	return nil
}

// ValidateCCNP validates the given CCNP accordingly the CCNP validation schema.
func (n *NPValidator) ValidateCCNP(ccnp *unstructured.Unstructured) error {
	if errs := validation.ValidateCustomResource(nil, &ccnp, n.ccnpValidator); len(errs) > 0 {
		return errs.ToAggregate()
	}

	if err := detectUnknownFields(ccnp); err != nil {
		return err
	}

	return nil
}

func checkInitLabelsPolicy(cnp *unstructured.Unstructured) error {
	cnpBytes, err := cnp.MarshalJSON()
	if err != nil {
		return err
	}

	resCNP := cilium_v2.CiliumNetworkPolicy{}
	err = json.Unmarshal(cnpBytes, &resCNP)
	if err != nil {
		return err
	}

	for _, spec := range append(resCNP.Specs, resCNP.Spec) {
		if spec == nil {
			continue
		}
		podInitLbl := labels.LabelSourceReservedKeyPrefix + labels.IDNameInit
		if spec.EndpointSelector.HasKey(podInitLbl) {
			logOnce.Do(func() {
				log.WithFields(logrus.Fields{
					logfields.CiliumNetworkPolicyName: cnp.GetName(),
				}).Error(logInitPolicyCNP)
			})
			return errInitPolicyCNP
		}
	}

	return nil
}
