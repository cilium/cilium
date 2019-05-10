// Copyright 2017 Authors of Cilium
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

package v2

import (
	goerrors "errors"
	"fmt"
	"time"

	k8sconst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"

	apiextensionsv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	apiextensionsclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/hashicorp/go-version"
)

const (
	// CustomResourceDefinitionGroup is the name of the third party resource group
	CustomResourceDefinitionGroup = k8sconst.GroupName

	// CustomResourceDefinitionVersion is the current version of the resource
	CustomResourceDefinitionVersion = "v2"

	// CustomResourceDefinitionSchemaVersion is semver-conformant version of CRD schema
	// Used to determine if CRD needs to be updated in cluster
	CustomResourceDefinitionSchemaVersion = "1.14"

	// CustomResourceDefinitionSchemaVersionKey is key to label which holds the CRD schema version
	CustomResourceDefinitionSchemaVersionKey = "io.cilium.k8s.crd.schema.version"

	// CNPKindDefinition is the kind name for Cilium Network Policy
	CNPKindDefinition = "CiliumNetworkPolicy"

	fqdnNameRegex = `^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])\.?$`

	fqdnPatternRegex = `^(([a-zA-Z0-9\*]|[a-zA-Z0-9\*][a-zA-Z0-9\-\*]*[a-zA-Z0-9\*])\.)*([A-Za-z0-9\*]|[A-Za-z0-9\*][A-Za-z0-9\-\*]*[A-Za-z0-9\*])\.?$`
)

// SchemeGroupVersion is group version used to register these objects
var SchemeGroupVersion = schema.GroupVersion{
	Group:   CustomResourceDefinitionGroup,
	Version: CustomResourceDefinitionVersion,
}

// Resource takes an unqualified resource and returns a Group qualified GroupResource
func Resource(resource string) schema.GroupResource {
	return SchemeGroupVersion.WithResource(resource).GroupResource()
}

var (
	// SchemeBuilder is needed by DeepCopy generator.
	SchemeBuilder runtime.SchemeBuilder
	// localSchemeBuilder and AddToScheme will stay in k8s.io/kubernetes.
	localSchemeBuilder = &SchemeBuilder

	// AddToScheme adds all types of this clientset into the given scheme.
	// This allows composition of clientsets, like in:
	//
	//   import (
	//     "k8s.io/client-go/kubernetes"
	//     clientsetscheme "k8s.io/client-go/kuberentes/scheme"
	//     aggregatorclientsetscheme "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset/scheme"
	//   )
	//
	//   kclientset, _ := kubernetes.NewForConfig(c)
	//   aggregatorclientsetscheme.AddToScheme(clientsetscheme.Scheme)
	AddToScheme = localSchemeBuilder.AddToScheme

	comparableCRDSchemaVersion *version.Version
)

func init() {
	comparableCRDSchemaVersion = version.Must(
		version.NewVersion(CustomResourceDefinitionSchemaVersion))

	// We only register manually written functions here. The registration of the
	// generated functions takes place in the generated files. The separation
	// makes the code compile even when the generated files are missing.
	localSchemeBuilder.Register(addKnownTypes)
}

// Adds the list of known types to api.Scheme.
func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(SchemeGroupVersion,
		&CiliumNetworkPolicy{},
		&CiliumNetworkPolicyList{},
		&CiliumEndpoint{},
		&CiliumNode{},
		&CiliumNodeList{},
	)
	metav1.AddToGroupVersion(scheme, SchemeGroupVersion)
	return nil
}

// CreateCustomResourceDefinitions creates our CRD objects in the kubernetes
// cluster
func CreateCustomResourceDefinitions(clientset apiextensionsclient.Interface) error {
	if err := createCNPCRD(clientset); err != nil {
		return err
	}

	if err := createCEPCRD(clientset); err != nil {
		return err
	}

	if err := createNodeCRD(clientset); err != nil {
		return err
	}

	return nil
}

// createCNPCRD creates and updates the CiliumNetworkPolicies CRD. It should be called
// on agent startup but is idempotent and safe to call again.
func createCNPCRD(clientset apiextensionsclient.Interface) error {
	var (
		// CustomResourceDefinitionSingularName is the singular name of custom resource definition
		CustomResourceDefinitionSingularName = "ciliumnetworkpolicy"

		// CustomResourceDefinitionPluralName is the plural name of custom resource definition
		CustomResourceDefinitionPluralName = "ciliumnetworkpolicies"

		// CustomResourceDefinitionShortNames are the abbreviated names to refer to this CRD's instances
		CustomResourceDefinitionShortNames = []string{"cnp", "ciliumnp"}

		// CustomResourceDefinitionKind is the Kind name of custom resource definition
		CustomResourceDefinitionKind = CNPKindDefinition

		CRDName = CustomResourceDefinitionPluralName + "." + SchemeGroupVersion.Group
	)

	res := &apiextensionsv1beta1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: CRDName,
			Labels: map[string]string{
				CustomResourceDefinitionSchemaVersionKey: CustomResourceDefinitionSchemaVersion,
			},
		},
		Spec: apiextensionsv1beta1.CustomResourceDefinitionSpec{
			Group:   SchemeGroupVersion.Group,
			Version: SchemeGroupVersion.Version,
			Names: apiextensionsv1beta1.CustomResourceDefinitionNames{
				Plural:     CustomResourceDefinitionPluralName,
				Singular:   CustomResourceDefinitionSingularName,
				ShortNames: CustomResourceDefinitionShortNames,
				Kind:       CustomResourceDefinitionKind,
			},
			Subresources: &apiextensionsv1beta1.CustomResourceSubresources{
				Status: &apiextensionsv1beta1.CustomResourceSubresourceStatus{},
			},
			Scope:      apiextensionsv1beta1.NamespaceScoped,
			Validation: &cnpCRV,
		},
	}

	return createUpdateCRD(clientset, "CiliumNetworkPolicy/v2", res)
}

// createCEPCRD creates and updates the CiliumEndpoint CRD. It should be called
// on agent startup but is idempotent and safe to call again.
func createCEPCRD(clientset apiextensionsclient.Interface) error {
	var (
		// CustomResourceDefinitionSingularName is the singular name of custom resource definition
		CustomResourceDefinitionSingularName = "ciliumendpoint"

		// CustomResourceDefinitionPluralName is the plural name of custom resource definition
		CustomResourceDefinitionPluralName = "ciliumendpoints"

		// CustomResourceDefinitionShortNames are the abbreviated names to refer to this CRD's instances
		CustomResourceDefinitionShortNames = []string{"cep", "ciliumep"}

		// CustomResourceDefinitionKind is the Kind name of custom resource definition
		CustomResourceDefinitionKind = "CiliumEndpoint"

		CRDName = CustomResourceDefinitionPluralName + "." + SchemeGroupVersion.Group
	)

	res := &apiextensionsv1beta1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: CRDName,
		},
		Spec: apiextensionsv1beta1.CustomResourceDefinitionSpec{
			Group:   SchemeGroupVersion.Group,
			Version: SchemeGroupVersion.Version,
			Names: apiextensionsv1beta1.CustomResourceDefinitionNames{
				Plural:     CustomResourceDefinitionPluralName,
				Singular:   CustomResourceDefinitionSingularName,
				ShortNames: CustomResourceDefinitionShortNames,
				Kind:       CustomResourceDefinitionKind,
			},
			AdditionalPrinterColumns: []apiextensionsv1beta1.CustomResourceColumnDefinition{
				{
					Name:        "Endpoint ID",
					Type:        "integer",
					Description: "Cilium endpoint id",
					JSONPath:    ".status.id",
				},
				{
					Name:        "Identity ID",
					Type:        "integer",
					Description: "Cilium identity id",
					JSONPath:    ".status.identity.id",
				},
				{
					Name:        "Ingress Enforcement",
					Type:        "boolean",
					Description: "Ingress enforcement in the endpoint",
					JSONPath:    ".status.policy.ingress.enforcing",
				},
				{
					Name:        "Egress Enforcement",
					Type:        "boolean",
					Description: "Egress enforcement in the endpoint",
					JSONPath:    ".status.policy.egress.enforcing",
				},
				{
					Name:        "Endpoint State",
					Type:        "string",
					Description: "Endpoint current state",
					JSONPath:    ".status.state",
				},
				{
					Name:        "IPv4",
					Type:        "string",
					Description: "Endpoint IPv4 address",
					JSONPath:    ".status.networking.addressing[0].ipv4",
				},
				{
					Name:        "IPv6",
					Type:        "string",
					Description: "Endpoint IPv6 address",
					JSONPath:    ".status.networking.addressing[0].ipv6",
				},
			},
			Subresources: &apiextensionsv1beta1.CustomResourceSubresources{
				Status: &apiextensionsv1beta1.CustomResourceSubresourceStatus{},
			},
			Scope:      apiextensionsv1beta1.NamespaceScoped,
			Validation: &cepCRV,
		},
	}

	return createUpdateCRD(clientset, "v2.CiliumEndpoint", res)
}

// createNodECRD creates and updates the CiliumNode CRD. It should be called on
// agent startup but is idempotent and safe to call again.
func createNodeCRD(clientset apiextensionsclient.Interface) error {
	res := &apiextensionsv1beta1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: "ciliumnodes." + SchemeGroupVersion.Group,
		},
		Spec: apiextensionsv1beta1.CustomResourceDefinitionSpec{
			Group:   SchemeGroupVersion.Group,
			Version: SchemeGroupVersion.Version,
			Names: apiextensionsv1beta1.CustomResourceDefinitionNames{
				Plural:     "ciliumnodes",
				Singular:   "ciliumnode",
				ShortNames: []string{"cn"},
				Kind:       "CiliumNode",
			},
			Subresources: &apiextensionsv1beta1.CustomResourceSubresources{
				Status: &apiextensionsv1beta1.CustomResourceSubresourceStatus{},
			},
			Scope: apiextensionsv1beta1.ClusterScoped,
		},
	}

	return createUpdateCRD(clientset, "v2.CiliumNode", res)
}

// createUpdateCRD ensures the CRD object is installed into the k8s cluster. It
// will create or update the CRD and it's validation when needed
func createUpdateCRD(clientset apiextensionsclient.Interface, CRDName string, crd *apiextensionsv1beta1.CustomResourceDefinition) error {
	scopedLog := log.WithField("name", CRDName)

	clusterCRD, err := clientset.ApiextensionsV1beta1().CustomResourceDefinitions().Get(crd.ObjectMeta.Name, metav1.GetOptions{})
	if errors.IsNotFound(err) {
		scopedLog.Info("Creating CRD (CustomResourceDefinition)...")
		clusterCRD, err = clientset.ApiextensionsV1beta1().CustomResourceDefinitions().Create(crd)
		// This occurs when multiple agents race to create the CRD. Since another has
		// created it, it will also update it, hence the non-error return.
		if errors.IsAlreadyExists(err) {
			return nil
		}
	}
	if err != nil {
		return err
	}

	scopedLog.Debug("Checking if CRD (CustomResourceDefinition) needs update...")
	if needsUpdate(clusterCRD) {
		scopedLog.Info("Updating CRD (CustomResourceDefinition)...")
		// Update the CRD with the validation schema.
		err = wait.Poll(500*time.Millisecond, 60*time.Second, func() (bool, error) {
			clusterCRD, err = clientset.ApiextensionsV1beta1().
				CustomResourceDefinitions().Get(crd.ObjectMeta.Name, metav1.GetOptions{})

			if err != nil {
				return false, err
			}

			// This seems too permissive but we only get here if the version is
			// different per needsUpdate above. If so, we want to update on any
			// validation change including adding or removing validation.
			if needsUpdate(clusterCRD) {
				scopedLog.Debug("CRD validation is different, updating it...")
				clusterCRD.ObjectMeta.Labels = crd.ObjectMeta.Labels
				clusterCRD.Spec = crd.Spec
				_, err = clientset.ApiextensionsV1beta1().CustomResourceDefinitions().Update(clusterCRD)
				if err == nil {
					return true, nil
				}
				scopedLog.WithError(err).Debug("Unable to update CRD validation")
				return false, err
			}

			return true, nil
		})
		if err != nil {
			scopedLog.WithError(err).Error("Unable to update CRD")
			return err
		}
	}

	// wait for the CRD to be established
	scopedLog.Debug("Waiting for CRD (CustomResourceDefinition) to be available...")
	err = wait.Poll(500*time.Millisecond, 60*time.Second, func() (bool, error) {
		crd, err := clientset.ApiextensionsV1beta1().CustomResourceDefinitions().Get(crd.ObjectMeta.Name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		for _, cond := range crd.Status.Conditions {
			switch cond.Type {
			case apiextensionsv1beta1.Established:
				if cond.Status == apiextensionsv1beta1.ConditionTrue {
					return true, err
				}
			case apiextensionsv1beta1.NamesAccepted:
				if cond.Status == apiextensionsv1beta1.ConditionFalse {
					scopedLog.WithError(goerrors.New(cond.Reason)).Error("Name conflict for CRD")
					return false, err
				}
			}
		}
		return false, err
	})
	if err != nil {
		deleteErr := clientset.ApiextensionsV1beta1().CustomResourceDefinitions().Delete(crd.ObjectMeta.Name, nil)
		if deleteErr != nil {
			return fmt.Errorf("unable to delete k8s %s CRD %s. Deleting CRD due: %s", CRDName, deleteErr, err)
		}
		return err
	}

	scopedLog.Info("CRD (CustomResourceDefinition) is installed and up-to-date")
	return nil
}

func needsUpdate(clusterCRD *apiextensionsv1beta1.CustomResourceDefinition) bool {

	if clusterCRD.Spec.Validation == nil {
		// no validation detected
		return true
	}
	v, ok := clusterCRD.Labels[CustomResourceDefinitionSchemaVersionKey]
	if !ok {
		// no schema version detected
		return true
	}
	clusterVersion, err := version.NewVersion(v)
	if err != nil || clusterVersion.LessThan(comparableCRDSchemaVersion) {
		// version in cluster is either unparsable or smaller than current version
		return true
	}
	return false
}

func getStr(str string) *string {
	return &str
}

func getInt64(i int64) *int64 {
	return &i
}

var (
	// cepCRV is a minimal validation for CEP objects. Since only the agent is
	// creating them, it is better to be permissive and have some data, if buggy,
	// than to have no data in k8s.
	cepCRV = apiextensionsv1beta1.CustomResourceValidation{
		OpenAPIV3Schema: &apiextensionsv1beta1.JSONSchemaProps{},
	}

	cnpCRV = apiextensionsv1beta1.CustomResourceValidation{
		OpenAPIV3Schema: &apiextensionsv1beta1.JSONSchemaProps{
			Properties: properties,
		},
	}

	properties = map[string]apiextensionsv1beta1.JSONSchemaProps{
		"CIDR":                     CIDR,
		"CIDRRule":                 CIDRRule,
		"EgressRule":               EgressRule,
		"EndpointSelector":         EndpointSelector,
		"IngressRule":              IngressRule,
		"K8sServiceNamespace":      K8sServiceNamespace,
		"L7Rules":                  L7Rules,
		"Label":                    Label,
		"LabelSelector":            LabelSelector,
		"LabelSelectorRequirement": LabelSelectorRequirement,
		"PortProtocol":             PortProtocol,
		"PortRule":                 PortRule,
		"PortRuleHTTP":             PortRuleHTTP,
		"PortRuleKafka":            PortRuleKafka,
		"PortRuleL7":               PortRuleL7,
		"Rule":                     Rule,
		"Service":                  Service,
		"ServiceSelector":          ServiceSelector,
		"spec":                     spec,
		"specs":                    specs,
	}

	CIDR = apiextensionsv1beta1.JSONSchemaProps{
		Description: "CIDR is a CIDR prefix / IP Block.",
		Type:        "string",
		OneOf: []apiextensionsv1beta1.JSONSchemaProps{
			{
				// IPv4 CIDR
				Type: "string",
				Pattern: `^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4]` +
					`[0-9]|[01]?[0-9][0-9]?)\/([0-9]|[1-2][0-9]|3[0-2])$`,
			},
			{
				// IPv6 CIDR
				Type: "string",
				Pattern: `^s*((([0-9A-Fa-f]{1,4}:){7}(:|([0-9A-Fa-f]{1,4})))` +
					`|(([0-9A-Fa-f]{1,4}:){6}:([0-9A-Fa-f]{1,4})?)` +
					`|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){0,1}):([0-9A-Fa-f]{1,4})?))` +
					`|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){0,2}):([0-9A-Fa-f]{1,4})?))` +
					`|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){0,3}):([0-9A-Fa-f]{1,4})?))` +
					`|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){0,4}):([0-9A-Fa-f]{1,4})?))` +
					`|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){0,5}):([0-9A-Fa-f]{1,4})?))` +
					`|(:(:|((:[0-9A-Fa-f]{1,4}){1,7}))))` +
					`(%.+)?s*/([0-9]|[1-9][0-9]|1[0-1][0-9]|12[0-8])$`,
			},
		},
	}

	CIDRRule = apiextensionsv1beta1.JSONSchemaProps{
		Description: "CIDRRule is a rule that specifies a CIDR prefix to/from which outside " +
			"communication is allowed, along with an optional list of subnets within that CIDR " +
			"prefix to/from which outside communication is not allowed.",
		Required: []string{
			"cidr",
		},
		Properties: map[string]apiextensionsv1beta1.JSONSchemaProps{
			"cidr": CIDR,
			"except": {
				Description: "ExceptCIDRs is a list of IP blocks which the endpoint subject to " +
					"the rule is not allowed to initiate connections to. These CIDR prefixes " +
					"should be contained within Cidr. These exceptions are only applied to the " +
					"Cidr in this CIDRRule, and do not apply to any other CIDR prefixes in any " +
					"other CIDRRules.",
				Type: "array",
				Items: &apiextensionsv1beta1.JSONSchemaPropsOrArray{
					Schema: &CIDR,
				},
			},
		},
	}

	EgressRule = apiextensionsv1beta1.JSONSchemaProps{
		Description: "EgressRule contains all rule types which can be applied at egress, i.e. " +
			"network traffic that originates inside the endpoint and exits the endpoint " +
			"selected by the endpointSelector.\n\n- All members of this structure are optional. " +
			"If omitted or empty, the\n  member will have no effect on the rule.\n\n- For now, " +
			"combining ToPorts and ToCIDR in the same rule is not supported\n  and such rules " +
			"will be rejected. In the future, this will be supported and\n  if if multiple " +
			"members of the structure are specified, then all members\n  must match in order " +
			"for the rule to take effect.",
		Properties: map[string]apiextensionsv1beta1.JSONSchemaProps{
			"toCIDR": {
				Description: "ToCIDR is a list of IP blocks which the endpoint subject to the " +
					"rule is allowed to initiate connections. This will match on the " +
					"destination IP address of outgoing connections. Adding a prefix into " +
					"ToCIDR or into ToCIDRSet with no ExcludeCIDRs is equivalent. Overlaps are " +
					"allowed between ToCIDR and ToCIDRSet.\n\nExample: Any endpoint with the " +
					"label \"app=database-proxy\" is allowed to initiate connections to " +
					"10.2.3.0/24",
				Type: "array",
				Items: &apiextensionsv1beta1.JSONSchemaPropsOrArray{
					Schema: &CIDR,
				},
			},
			"toCIDRSet": {
				Description: "ToCIDRSet is a list of IP blocks which the endpoint subject to " +
					"the rule is allowed to initiate connections to in addition to connections " +
					"which are allowed via FromEndpoints, along with a list of subnets " +
					"contained within their corresponding IP block to which traffic should not " +
					"be allowed. This will match on the destination IP address of outgoing " +
					"connections. Adding a prefix into ToCIDR or into ToCIDRSet with no " +
					"ExcludeCIDRs is equivalent. Overlaps are allowed between ToCIDR and " +
					"ToCIDRSet.\n\nExample: Any endpoint with the label \"app=database-proxy\" " +
					"is allowed to initiate connections to 10.2.3.0/24 except from IPs in " +
					"subnet 10.2.3.0/28.",
				Type: "array",
				Items: &apiextensionsv1beta1.JSONSchemaPropsOrArray{
					Schema: &CIDRRule,
				},
			},
			"toEntities": {
				Description: "ToEntities is a list of special entities to which the endpoint " +
					"subject to the rule is allowed to initiate connections. Supported " +
					"entities are `world`, `cluster` and `host`",
				Type: "array",
				Items: &apiextensionsv1beta1.JSONSchemaPropsOrArray{
					Schema: &apiextensionsv1beta1.JSONSchemaProps{
						Type: "string",
					},
				},
			},
			"toPorts": {
				Description: "ToPorts is a list of destination ports identified by port number " +
					"and protocol which the endpoint subject to the rule is allowed to connect " +
					"to.\n\nExample: Any endpoint with the label \"role=frontend\" is allowed " +
					"to initiate connections to destination port 8080/tcp",
				Type: "array",
				Items: &apiextensionsv1beta1.JSONSchemaPropsOrArray{
					Schema: &PortRule,
				},
			},
			"toServices": {
				Description: "ToServices is a list of services to which the endpoint subject " +
					"to the rule is allowed to initiate connections.\n\nExample: Any endpoint " +
					"with the label \"app=backend-app\" is allowed to initiate connections to " +
					"all cidrs backing the \"external-service\" service",
				Type: "array",
				Items: &apiextensionsv1beta1.JSONSchemaPropsOrArray{
					Schema: &Service,
				},
			},
			"toEndpoints": {
				Description: "ToEndpoints is a list of endpoints identified by an " +
					"EndpointSelector to which the endpoint subject to the rule" +
					"is allowed to communicate.\n\nExample: Any endpoint with the label " +
					"\"role=frontend\" can be consumed by any endpoint carrying the label " +
					"\"role=backend\".",
				Type: "array",
				Items: &apiextensionsv1beta1.JSONSchemaPropsOrArray{
					Schema: &EndpointSelector,
				},
			},
			"toRequires": {
				Description: "ToRequires is a list of additional constraints which must be " +
					"met in order for the selected endpoints to be able to reach other " +
					"endpoints. These additional constraints do not by themselves grant access " +
					"privileges and must always be accompanied with at least one matching " +
					"FromEndpoints.\n\nExample: Any Endpoint with the label \"team=A\" " +
					"requires any endpoint to which it communicates to also carry the label " +
					"\"team=A\".",
				Type: "array",
				Items: &apiextensionsv1beta1.JSONSchemaPropsOrArray{
					Schema: &EndpointSelector,
				},
			},
			"toGroups": {
				Description: `ToGroups is a list of constraints that will
				gather data from third-party providers and create a new
				derived policy.`,
				Properties: map[string]apiextensionsv1beta1.JSONSchemaProps{
					"AWS": AWSGroup,
				},
			},
			"toFQDNs": {
				Description: `ToFQDNs is a list of rules matching fqdns that endpoint
				is allowed to communicate with`,
				Type: "array",
				Items: &apiextensionsv1beta1.JSONSchemaPropsOrArray{
					Schema: &FQDNRule,
				},
			},
		},
	}

	FQDNRule = apiextensionsv1beta1.JSONSchemaProps{
		Description: `FQDNRule is a rule that specifies an fully qualified domain name to which outside communication is allowed`,
		Properties: map[string]apiextensionsv1beta1.JSONSchemaProps{
			"matchName":    MatchFQDNName,
			"matchPattern": MatchFQDNPattern,
		},
	}

	MatchFQDNName = apiextensionsv1beta1.JSONSchemaProps{
		Description: `MatchName matches fqdn name`,
		Type:        "string",
		Pattern:     fqdnNameRegex,
	}

	MatchFQDNPattern = apiextensionsv1beta1.JSONSchemaProps{
		Description: `MatchPattern matches fqdn by pattern`,
		Type:        "string",
		Pattern:     fqdnPatternRegex,
	}

	AWSGroup = apiextensionsv1beta1.JSONSchemaProps{
		Description: "",
		Properties: map[string]apiextensionsv1beta1.JSONSchemaProps{
			"SecurityGroupsIds": {
				Description: `SecurityGroupsIds is the list of AWS security
				group IDs that will filter the instances IPs from the AWS API`,
				Type: "array",
			},
			"SecurityGroupsNames": {
				Description: `SecurityGroupsNames is the list of  AWS security
				group names that will filter the instances IPs from the AWS API`,
				Type: "array",
			},
			"Region": {
				Description: `Region is the key that will filter the AWS EC2
				instances in the given region`,
				Type: "string",
			},
		},
	}
	EndpointSelector = *LabelSelector.DeepCopy()

	IngressRule = apiextensionsv1beta1.JSONSchemaProps{
		Description: "IngressRule contains all rule types which can be applied at ingress, " +
			"i.e. network traffic that originates outside of the endpoint and is entering " +
			"the endpoint selected by the endpointSelector.\n\n- All members of this structure " +
			"are optional. If omitted or empty, the\n  member will have no effect on the rule." +
			"\n\n- If multiple members are set, all of them need to match in order for\n  " +
			"the rule to take effect. The exception to this rule is FromRequires field;\n  " +
			"the effects of any Requires field in any rule will apply to all other\n  rules " +
			"as well.\n\n- For now, combining ToPorts, FromCIDR, and FromEndpoints in the same " +
			"rule\n  is not supported and any such rules will be rejected. In the future, " +
			"this\n  will be supported and if multiple members of this structure are specified," +
			"\n then all members must match in order for the rule to take effect. The\n  " +
			"exception to this rule is the Requires field, the effects of any Requires\n  " +
			"field in any rule will apply to all other rules as well.",
		Properties: map[string]apiextensionsv1beta1.JSONSchemaProps{
			"fromCIDR": {
				Description: "FromCIDR is a list of IP blocks which the endpoint subject to " +
					"the rule is allowed to receive connections from. This will match on the " +
					"source IP address of incoming connections. Adding  a prefix into FromCIDR " +
					"or into FromCIDRSet with no ExcludeCIDRs is  equivalent. Overlaps are " +
					"allowed between FromCIDR and FromCIDRSet.\n\nExample: Any endpoint with " +
					"the label \"app=my-legacy-pet\" is allowed to receive connections from " +
					"10.3.9.1",
				Type: "array",
				Items: &apiextensionsv1beta1.JSONSchemaPropsOrArray{
					Schema: &CIDR,
				},
			},
			"fromCIDRSet": {
				Description: "FromCIDRSet is a list of IP blocks which the endpoint subject to " +
					"the rule is allowed to receive connections from in addition to " +
					"FromEndpoints, along with a list of subnets contained within their " +
					"corresponding IP block from which traffic should not be allowed. This " +
					"will match on the source IP address of incoming connections. Adding a " +
					"prefix into FromCIDR or into FromCIDRSet with no ExcludeCIDRs is " +
					"equivalent. Overlaps are allowed between FromCIDR and FromCIDRSet." +
					"\n\nExample: Any endpoint with the label \"app=my-legacy-pet\" is allowed " +
					"to receive connections from 10.0.0.0/8 except from IPs in subnet " +
					"10.96.0.0/12.",
				Type: "array",
				Items: &apiextensionsv1beta1.JSONSchemaPropsOrArray{
					Schema: &CIDRRule,
				},
			},
			"fromEndpoints": {
				Description: "FromEndpoints is a list of endpoints identified by an " +
					"EndpointSelector which are allowed to communicate with the endpoint " +
					"subject to the rule.\n\nExample: Any endpoint with the label " +
					"\"role=backend\" can be consumed by any endpoint carrying the label " +
					"\"role=frontend\".",
				Type: "array",
				Items: &apiextensionsv1beta1.JSONSchemaPropsOrArray{
					Schema: &EndpointSelector,
				},
			},
			"fromEntities": {
				Description: "FromEntities is a list of special entities which the endpoint " +
					"subject to the rule is allowed to receive connections from. Supported " +
					"entities are `world`, `cluster`, `host`, and `init`",
				Type: "array",
				Items: &apiextensionsv1beta1.JSONSchemaPropsOrArray{
					Schema: &apiextensionsv1beta1.JSONSchemaProps{
						Type: "string",
					},
				},
			},
			"fromRequires": {
				Description: "FromRequires is a list of additional constraints which must be " +
					"met in order for the selected endpoints to be reachable. These additional " +
					"constraints do no by itself grant access privileges and must always be " +
					"accompanied with at least one matching FromEndpoints.\n\nExample: Any " +
					"Endpoint with the label \"team=A\" requires consuming endpoint to also " +
					"carry the label \"team=A\".",
				Type: "array",
				Items: &apiextensionsv1beta1.JSONSchemaPropsOrArray{
					Schema: &EndpointSelector,
				},
			},
			"toPorts": {
				Description: "ToPorts is a list of destination ports identified by port number " +
					"and protocol which the endpoint subject to the rule is allowed to receive " +
					"connections on.\n\nExample: Any endpoint with the label \"app=httpd\" can " +
					"only accept incoming connections on port 80/tcp.",
				Type: "array",
				Items: &apiextensionsv1beta1.JSONSchemaPropsOrArray{
					Schema: &PortRule,
				},
			},
		},
	}

	K8sServiceNamespace = apiextensionsv1beta1.JSONSchemaProps{
		Description: "K8sServiceNamespace is an abstraction for the k8s service + namespace " +
			"types.",
		Properties: map[string]apiextensionsv1beta1.JSONSchemaProps{
			"namespace": {
				Type: "string",
			},
			"serviceName": {
				Type: "string",
			},
		},
	}

	L7Rules = apiextensionsv1beta1.JSONSchemaProps{
		Description: "L7Rules is a union of port level rule types. Mixing of different port " +
			"level rule types is disallowed, so exactly one of the following must be set. If " +
			"none are specified, then no additional port level rules are applied.",
		Properties: map[string]apiextensionsv1beta1.JSONSchemaProps{
			"http": {
				Description: "HTTP specific rules.",
				Type:        "array",
				Items: &apiextensionsv1beta1.JSONSchemaPropsOrArray{
					Schema: &PortRuleHTTP,
				},
			},
			"kafka": {
				Description: "Kafka-specific rules.",
				Type:        "array",
				Items: &apiextensionsv1beta1.JSONSchemaPropsOrArray{
					Schema: &PortRuleKafka,
				},
			},
			"l7proto": {
				Description: "Parser type name that uses Key-Value pair rules.",
				Type:        "string",
			},
			"l7": {
				Description: "Generic Key-Value pair rules.",
				Type:        "array",
				Items: &apiextensionsv1beta1.JSONSchemaPropsOrArray{
					Schema: &PortRuleL7,
				},
			},
			"dns": {
				Description: "DNS specific rules",
				Type:        "array",
				Items: &apiextensionsv1beta1.JSONSchemaPropsOrArray{
					Schema: &PortRuleDNS,
				},
			},
		},
	}

	PortRuleDNS = apiextensionsv1beta1.JSONSchemaProps{
		Description: `FQDNRule is a rule that specifies an fully qualified domain name to which outside communication is allowed`,
		Properties: map[string]apiextensionsv1beta1.JSONSchemaProps{
			"matchName":    MatchFQDNName,
			"matchPattern": MatchFQDNPattern,
		},
	}

	Label = apiextensionsv1beta1.JSONSchemaProps{
		Description: "Label is the cilium's representation of a container label.",
		Required: []string{
			"key",
		},
		Properties: map[string]apiextensionsv1beta1.JSONSchemaProps{
			"key": {
				Type: "string",
			},
			"source": {
				Description: "Source can be one of the values present in const.go " +
					"(e.g.: LabelSourceContainer)",
				Type: "string",
			},
			"value": {
				Type: "string",
			},
		},
	}

	LabelSelector = apiextensionsv1beta1.JSONSchemaProps{
		Description: "A label selector is a label query over a set of resources. The result " +
			"of matchLabels and matchExpressions are ANDed. An empty label selector matches " +
			"all objects. A null label selector matches no objects.",
		Properties: map[string]apiextensionsv1beta1.JSONSchemaProps{
			"matchLabels": {
				Description: "matchLabels is a map of {key,value} pairs. A single {key,value} " +
					"in the matchLabels map is equivalent to an element of matchExpressions, " +
					"whose key field is \"key\", the operator is \"In\", and the values array " +
					"contains only \"value\". The requirements are ANDed.",
				Type: "object",
			},
			"matchExpressions": {
				Description: "matchExpressions is a list of label selector requirements. " +
					"The requirements are ANDed.",
				Type: "array",
				Items: &apiextensionsv1beta1.JSONSchemaPropsOrArray{
					Schema: &LabelSelectorRequirement,
				},
			},
		},
	}

	LabelSelectorRequirement = apiextensionsv1beta1.JSONSchemaProps{
		Description: "A label selector requirement is a selector that contains values, a key, " +
			"and an operator that relates the key and values.",
		Properties: map[string]apiextensionsv1beta1.JSONSchemaProps{
			"key": {
				Description: "key is the label key that the selector applies to.",
				Type:        "string",
			},
			"operator": {
				Description: "operator represents a key's relationship to a set of values. " +
					"Valid operators are In, NotIn, Exists and DoesNotExist.",
				Type: "string",
				Enum: []apiextensionsv1beta1.JSON{
					{
						Raw: []byte(`"In"`),
					},
					{
						Raw: []byte(`"NotIn"`),
					},
					{
						Raw: []byte(`"Exists"`),
					},
					{
						Raw: []byte(`"DoesNotExist"`),
					},
				},
			},
			"values": {
				Description: "values is an array of string values. If the operator is In or " +
					"NotIn, the values array must be non-empty. If the operator is Exists or " +
					"DoesNotExist, the values array must be empty. This array is replaced " +
					"during a strategic merge patch.",
				Type: "array",
				Items: &apiextensionsv1beta1.JSONSchemaPropsOrArray{
					Schema: &apiextensionsv1beta1.JSONSchemaProps{
						Type: "string",
					},
				},
			},
		},
		Required: []string{"key", "operator"},
	}

	PortProtocol = apiextensionsv1beta1.JSONSchemaProps{
		Description: "PortProtocol specifies an L4 port with an optional transport protocol",
		Required: []string{
			"port",
		},
		Properties: map[string]apiextensionsv1beta1.JSONSchemaProps{
			"port": {
				Description: "Port is an L4 port number. For now the string will be strictly " +
					"parsed as a single uint16. In the future, this field may support ranges " +
					"in the form \"1024-2048",
				Type: "string",
				// uint16 string regex
				Pattern: `^(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|` +
					`[1-5][0-9]{4}|[0-9]{1,4})$`,
			},
			"protocol": {
				Description: `Protocol is the L4 protocol. If omitted or empty, any protocol ` +
					`matches. Accepted values: "TCP", "UDP", ""/"ANY"\n\nMatching on ` +
					`ICMP is not supported.`,
				Type: "string",
				Enum: []apiextensionsv1beta1.JSON{
					{
						Raw: []byte(`"TCP"`),
					},
					{
						Raw: []byte(`"UDP"`),
					},
					{
						Raw: []byte(`"ANY"`),
					},
				},
			},
		},
	}

	PortRule = apiextensionsv1beta1.JSONSchemaProps{
		Description: "PortRule is a list of ports/protocol combinations with optional Layer 7 " +
			"rules which must be met.",
		Properties: map[string]apiextensionsv1beta1.JSONSchemaProps{
			"ports": {
				Description: "Ports is a list of L4 port/protocol\n\nIf omitted or empty but " +
					"RedirectPort is set, then all ports of the endpoint subject to either the " +
					"ingress or egress rule are being redirected.",
				Type: "array",
				Items: &apiextensionsv1beta1.JSONSchemaPropsOrArray{
					Schema: &PortProtocol,
				},
			},
			"redirectPort": {
				Description: "RedirectPort is the L4 port which, if set, all traffic matching " +
					"the Ports is being redirected to. Whatever listener behind that port " +
					"becomes responsible to enforce the port rules and is also responsible to " +
					"reinject all traffic back and ensure it reaches its original destination.",
				Type:   "integer",
				Format: "uint16",
			},
			"rules": L7Rules,
		},
	}

	PortRuleHTTP = apiextensionsv1beta1.JSONSchemaProps{
		Description: "PortRuleHTTP is a list of HTTP protocol constraints. All fields are " +
			"optional, if all fields are empty or missing, the rule does not have any effect." +
			"\n\nAll fields of this type are extended POSIX regex as defined by " +
			"IEEE Std 1003.1, (i.e this follows the egrep/unix syntax, not the perl syntax) " +
			"matched against the path of an incoming request. Currently it can contain " +
			"characters disallowed from the conventional \"path\" part of a URL as defined by " +
			"RFC 3986.",
		Properties: map[string]apiextensionsv1beta1.JSONSchemaProps{
			"headers": {
				Description: "Headers is a list of HTTP headers which must be present in the " +
					"request. If omitted or empty, requests are allowed regardless of headers " +
					"present.",
				Type: "array",
				Items: &apiextensionsv1beta1.JSONSchemaPropsOrArray{
					Schema: &apiextensionsv1beta1.JSONSchemaProps{
						Type: "string",
					},
				},
			},
			"host": {
				Description: "Host is an extended POSIX regex matched against the host header " +
					"of a request, e.g. \"foo.com\"\n\nIf omitted or empty, the value of the " +
					"host header is ignored.",
				Type:   "string",
				Format: "idn-hostname",
			},
			"method": {
				Description: "Method is an extended POSIX regex matched against the method of " +
					"a request, e.g. \"GET\", \"POST\", \"PUT\", \"PATCH\", \"DELETE\", ...\n\n" +
					"If omitted or empty, all methods are allowed.",
				Type: "string",
			},
			"path": {
				Description: "Path is an extended POSIX regex matched against the path of a " +
					"request. Currently it can contain characters disallowed from the " +
					"conventional \"path\" part of a URL as defined by RFC 3986.\n\n" +
					"If omitted or empty, all paths are all allowed.",
				Type: "string",
			},
		},
	}

	PortRuleKafka = apiextensionsv1beta1.JSONSchemaProps{
		Description: "PortRuleKafka is a list of Kafka protocol constraints. All fields are " +
			"optional, if all fields are empty or missing, the rule will match all Kafka " +
			"messages.",
		Properties: map[string]apiextensionsv1beta1.JSONSchemaProps{
			"role": {
				Description: "Role is a case-insensitive string and describes a group of API keys" +
					"necessary to perform certain higher level Kafka operations such as" +
					"\"produce\" or \"consume\". An APIGroup automatically expands into all APIKeys" +
					"required to perform the specified higher level operation." +
					"The following values are supported:" +
					"- \"produce\": Allow producing to the topics specified in the rule" +
					"- \"consume\": Allow consuming from the topics specified in the rule" +
					"This field is incompatible with the APIKey field, either APIKey or Role" +
					"may be specified. If omitted or empty, the field has no effect and the " +
					"logic of the APIKey field applies.",
				Type: "string",
				Enum: []apiextensionsv1beta1.JSON{
					{
						Raw: []byte(`"produce"`),
					},
					{
						Raw: []byte(`"consume"`),
					},
				},
			},
			"apiKey": {
				Description: "APIKey is a case-insensitive string matched against the key of " +
					"a request, e.g. \"produce\", \"fetch\", \"createtopic\", \"deletetopic\", " +
					"et al Reference: https://kafka.apache.org/protocol#protocol_api_keys\n\n" +
					"If omitted or empty, all keys are allowed.",
				Type: "string",
			},
			"apiVersion": {
				Description: "APIVersion is the version matched against the api version of the " +
					"Kafka message. If set, it has to be a string representing a positive " +
					"integer.\n\nIf omitted or empty, all versions are allowed.",
				Type: "string",
			},
			"clientID": {
				Description: "ClientID is the client identifier as provided in the request.\n\n" +
					"From Kafka protocol documentation: This is a user supplied identifier for " +
					"the client application. The user can use any identifier they like and it " +
					"will be used when logging errors, monitoring aggregates, etc. For " +
					"example, one might want to monitor not just the requests per second " +
					"overall, but the number coming from each client application (each of " +
					"which could reside on multiple servers). This id acts as a logical " +
					"grouping across all requests from a particular client.\n\nIf omitted or " +
					"empty, all client identifiers are allowed.",
				Type: "string",
			},
			"topic": {
				Description: "Topic is the topic name contained in the message. If a Kafka " +
					"request contains multiple topics, then all topics must be allowed or the " +
					"message will be rejected.\n\nThis constraint is ignored if the matched " +
					"request message type doesn't contain any topic. Maximum size of Topic can " +
					"be 249 characters as per recent Kafka spec and allowed characters are " +
					"a-z, A-Z, 0-9, -, . and _ Older Kafka versions had longer topic lengths " +
					"of 255, but in Kafka 0.10 version the length was changed from 255 to 249. " +
					"For compatibility reasons we are using 255\n\nIf omitted or empty, all " +
					"topics are allowed.",
				Type:      "string",
				MaxLength: getInt64(255),
			},
		},
	}

	PortRuleL7 = apiextensionsv1beta1.JSONSchemaProps{
		Description: "PortRuleL7 is a map of {key,value} pairs which is passed to the " +
			"parser referenced in l7proto. It is up to the parser to define what to " +
			"do with the map data. If omitted or empty, all requests are allowed. " +
			"Both keys and values must be strings.",
		//
		// AdditionalProperties is supported by k8s 1.11 and later only
		// Without it non-string value types are accepted which may cause policy translation
		// in cilium-agent to fail.
		//
		// Keep this here so that we can re-introduce this when th minimum suppoerted k8s version
		// is 1.11.
		//
		//AdditionalProperties: &apiextensionsv1beta1.JSONSchemaPropsOrBool{
		//	Schema: &apiextensionsv1beta1.JSONSchemaProps{
		//		Type: "string",
		//	},
		//},
	}

	Rule = apiextensionsv1beta1.JSONSchemaProps{
		Description: "Rule is a policy rule which must be applied to all endpoints which match " +
			"the labels contained in the endpointSelector\n\nEach rule is split into an " +
			"ingress section which contains all rules applicable at ingress, and an egress " +
			"section applicable at egress. For rule types such as `L4Rule` and `CIDR` which " +
			"can be applied at both ingress and egress, both ingress and egress side have to " +
			"either specifically allow the connection or one side has to be omitted.\n\n" +
			"Either ingress, egress, or both can be provided. If both ingress and egress are " +
			"omitted, the rule has no effect.",
		Required: []string{
			"endpointSelector",
		},
		Properties: map[string]apiextensionsv1beta1.JSONSchemaProps{
			"Description": {
				Description: "Description is a free form string, it can be used by the creator " +
					"of the rule to store human readable explanation of the purpose of this " +
					"rule. Rules cannot be identified by comment.",
				Type: "string",
			},
			"egress": {
				Description: "Egress is a list of EgressRule which are enforced at egress. If " +
					"omitted or empty, this rule does not apply at egress.",
				Type: "array",
				Items: &apiextensionsv1beta1.JSONSchemaPropsOrArray{
					Schema: &EgressRule,
				},
			},
			"endpointSelector": EndpointSelector,
			"ingress": {
				Description: "Ingress is a list of IngressRule which are enforced at ingress. " +
					"If omitted or empty, this rule does not apply at ingress.",
				Type: "array",
				Items: &apiextensionsv1beta1.JSONSchemaPropsOrArray{
					Schema: &IngressRule,
				},
			},
			"labels": {
				Description: "Labels is a list of optional strings which can be used to " +
					"re-identify the rule or to store metadata. It is possible to lookup or " +
					"delete strings based on labels. Labels are not required to be unique, " +
					"multiple rules can have overlapping or identical labels.",
				Type: "array",
				Items: &apiextensionsv1beta1.JSONSchemaPropsOrArray{
					Schema: &Label,
				},
			},
		},
	}

	Service = apiextensionsv1beta1.JSONSchemaProps{
		Description: "Service wraps around selectors for services",
		Properties: map[string]apiextensionsv1beta1.JSONSchemaProps{
			"k8sService":         K8sServiceNamespace,
			"k8sServiceSelector": ServiceSelector,
		},
	}

	ServiceSelector = apiextensionsv1beta1.JSONSchemaProps{
		Description: "ServiceSelector is a label selector for k8s services",
		Required: []string{
			"selector",
		},
		Properties: map[string]apiextensionsv1beta1.JSONSchemaProps{
			"selector": EndpointSelector,
			"namespace": {
				Type: "string",
			},
		},
	}

	spec = *Rule.DeepCopy()

	specs = apiextensionsv1beta1.JSONSchemaProps{
		Description: "Specs is a list of desired Cilium specific rule specification.",
		Type:        "array",
		Items: &apiextensionsv1beta1.JSONSchemaPropsOrArray{
			Schema: &spec,
		},
	}
)

func init() {
	EndpointSelector.Description = "EndpointSelector is a wrapper for k8s LabelSelector."

	portRuleProps := PortRule.Properties["rules"]
	portRuleProps.Description = "Rules is a list of additional port level rules which must be " +
		"met in order for the PortRule to allow the traffic. If omitted or empty, " +
		"no layer 7 rules are enforced."
	PortRule.Properties["rules"] = portRuleProps

	ruleProps := Rule.Properties["endpointSelector"]
	ruleProps.Description = "EndpointSelector selects all endpoints which should be subject " +
		"to this rule. Cannot be empty."
	Rule.Properties["endpointSelector"] = ruleProps

	serviceProps := Service.Properties["k8sServiceSelector"]
	serviceProps.Description = "K8sServiceSelector selects services by k8s labels. " +
		"Not supported yet"
	Service.Properties["k8sServiceSelector"] = serviceProps

	spec.Description = "Spec is the desired Cilium specific rule specification."
	spec.Type = "object"

}
