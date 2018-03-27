// Copyright 2016-2018 Authors of Cilium
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

package v3

import (
	apiextensionsv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
)

func getInt64(i int64) *int64 {
	return &i
}

var (
	JSONSchema = map[string]apiextensionsv1beta1.JSONSchemaProps{
		"spec":  spec,
		"specs": specs,
	}

	cidrSchema = apiextensionsv1beta1.JSONSchemaProps{
		Description: `CIDR specifies a block of IP addresses.
Example: 192.0.2.1/32`,
		Type: "string",
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
				Pattern: `^s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]` +
					`{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|` +
					`2[0-4]d|1dd|[1-9]?d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4})` +
					`{1,2})|:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3})` +
					`|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]` +
					`{1,4})?:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}` +
					`))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]` +
					`{1,4}){0,2}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d))` +
					`{3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:` +
					`[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|` +
					`1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|` +
					`((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d` +
					`|1dd|[1-9]?d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4})` +
					`{0,5}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|` +
					`:)))(%.+)?s*/([0-9]|[1-9][0-9]|1[0-1][0-9]|12[0-8])$`,
			},
		},
	}

	cidrRuleSchema = apiextensionsv1beta1.JSONSchemaProps{
		Description: `CIDRRule is a rule that specifies a CIDR prefix to/from which outside
communication is allowed, along with an optional list of subnets within that
CIDR prefix to/from which outside communication is not allowed.`,
		Required: []string{
			"anyOf",
		},
		Properties: map[string]apiextensionsv1beta1.JSONSchemaProps{
			"anyOf": {
				Description: `anyOf CIDR is a CIDR prefix / IP Block.`,
				Type:        "array",
				Items: &apiextensionsv1beta1.JSONSchemaPropsOrArray{
					Schema: &cidrSchema,
				},
			},
			"except": {
				Description: `except is a list of IP blocks which the endpoint subject to the rule
is not allowed to initiate connections to. These CIDR prefixes should be
contained within Cidr. These exceptions are only applied to the CIDR in
this CIDRRule, and do not apply to any other CIDR prefixes in any other
CIDRRules.`,
				Type: "array",
				Items: &apiextensionsv1beta1.JSONSchemaPropsOrArray{
					Schema: &cidrSchema,
				},
			},
			"toPorts": {
				Description: `ToPorts is a list of destination ports identified by port number and
protocol on which the endpoint subject to the rule is allowed to
receive connections. If empty, all ports will be allowed.

Example:
Any endpoint with the label "app=httpd" can only accept incoming
connections on port 80/tcp from IPs in CIDR prefix 10.0.0.0/8.`,
				Type:       "object",
				Properties: portRuleSchema.Properties,
			},
		},
	}

	egressRuleSchema = apiextensionsv1beta1.JSONSchemaProps{
		Description: `EgressRule contains all rule types which can be applied at egress, i.e.
network traffic that originates inside the endpoint and exits the endpoint
selected by the endpointSelector.

- All members of this structure are optional. If omitted or empty, the
  member will have no effect on the rule.`,
		Properties: map[string]apiextensionsv1beta1.JSONSchemaProps{
			"toIdentities": {
				Description: `ToIdentities is a list of endpoints identified by an identitySelector to
which the endpoints subject to the rule are allowed to communicate.

Example:
Any endpoint with the label "role=frontend" can communicate with any
endpoint carrying the label "role=backend".`,
				Type: "object",
				Items: &apiextensionsv1beta1.JSONSchemaPropsOrArray{
					Schema: &identityRuleSchema,
				},
			},
			"toRequires": {
				Description: `ToRequires is a list of additional constraints which must be met
in order for the selected endpoints to be able to connect to other
endpoints. These additional constraints do not by themselves grant access
privileges and must always be accompanied with at least one matching
ToIdentities.

Example:
Any Endpoint with the label "team=A" requires any endpoint to which it
communicates to also carry the label "team=A".`,
				Type:       "object",
				Properties: identityRequirementSchema.Properties,
			},
			"toCIDR": {
				Description: `ToCIDRs is a list of IP blocks which the endpoint subject to the rule
is allowed to initiate connections. Only connections destined for
outside of the cluster and not targeting the host will be subject
to CIDR rules. This will match on the destination IP address of
outgoing connections.

Example:
Any endpoint with the label "app=database-proxy" is allowed to
initiate connections to 10.2.3.0/24`,
				Type:       "object",
				Properties: cidrRuleSchema.Properties,
			},
			"toEntities": {
				Description: `ToEntities is a list of special entities to which the endpoint subject
to the rule is allowed to initiate connections. Supported entities are
world and host`,
				Type:       "object",
				Properties: entityRuleSchema.Properties,
			},
			"toServices": {
				Description: `ToServices is a list of services to which the endpoint subject
to the rule is allowed to initiate connections.

Example:
Any endpoint with the label "app=backend-app" is allowed to
initiate connections to all cidrs backing the "external-service" service`,
				Type:       "object",
				Properties: serviceRuleSchema.Properties,
			},
		},
	}

	entityRuleSchema = apiextensionsv1beta1.JSONSchemaProps{
		Description: `EntityRule is a rule that specifies a list of entities to/from which
communication is allowed.`,
		Properties: map[string]apiextensionsv1beta1.JSONSchemaProps{
			"anyOf": {
				Description: `anyOf is a list of special entities from which the endpoint subject to
the rule is allowed to receive connections.`,
				Type: "array",
				Items: &apiextensionsv1beta1.JSONSchemaPropsOrArray{
					Schema: &entitySchema,
				},
			},
			"toPorts": {
				Description: `ToPorts is a list of destination ports identified by port number and
protocol which the endpoint subject to the rule is allowed to
receive connections on. If empty, all ports will be allowed.

Example:
Any endpoint with the label "app=httpd" can only accept incoming
connections on port 80/tcp from "world".`,
				Type:       "object",
				Properties: portRuleSchema.Properties,
			},
		},
	}

	entitySchema = apiextensionsv1beta1.JSONSchemaProps{
		Description: `Entity specifies the class of receiver/sender endpoints that do not have
individual identities. Entities are used to describe "outside of cluster",
"host", etc.`,
		Type: "string",
		Enum: []apiextensionsv1beta1.JSON{
			{
				Raw: []byte(`"all"`),
			},
			{
				Raw: []byte(`"host"`),
			},
			{
				Raw: []byte(`"world"`),
			},
		},
	}

	identityRequirementSchema = apiextensionsv1beta1.JSONSchemaProps{
		Description: `IdentityRequirement is a list of additional constraints which must be met
in order for the selected endpoints to be reachable. These additional
constraints do no by itself grant access privileges and must always be
accompanied with at least one matching FromEndpoints.`,
		Properties: map[string]apiextensionsv1beta1.JSONSchemaProps{
			"anyOf": {
				Description: `anyOf is the selector to or from which the traffic will be
allowed.`,
				Type: "array",
				Items: &apiextensionsv1beta1.JSONSchemaPropsOrArray{
					Schema: &identitySelectorSchema,
				},
			},
		},
	}

	identityRuleSchema = apiextensionsv1beta1.JSONSchemaProps{
		Description: `IdentityRule is a rule that specifies an identitySelector in a form of
matchLabels and matchExpressions that are allowed to communicate. If toPorts
is specified the traffic will be filtered accordingly the given PortRules.`,
		Properties: map[string]apiextensionsv1beta1.JSONSchemaProps{
			"identitySelector": {
				Description: `IdentitySelector is the selector to or from which the traffic will be
allowed.`,
				Type:       "object",
				Properties: identitySelectorSchema.Properties,
			},
			"toPorts": {
				Description: `ToPorts is a list of destination ports identified by port number and
protocol on which the endpoint subject to the rule is allowed to
receive connections. If empty, all ports will be allowed.

Example:
Any endpoint with the label "app=httpd" can only accept incoming
connections on port 80/tcp.`,
				Type:       "object",
				Properties: portRuleSchema.Properties,
			},
		},
	}

	identitySelectorSchema = apiextensionsv1beta1.JSONSchemaProps{
		Description: ``,
		Properties: map[string]apiextensionsv1beta1.JSONSchemaProps{
			"matchLabels": {
				Description: ``,
				Type:        "object",
			},
			"matchExpressions": {
				Description: ``,
				Type:        "array",
				Items: &apiextensionsv1beta1.JSONSchemaPropsOrArray{
					Schema: &labelSelectorRequirementSchema,
				},
			},
		},
	}

	ingressRuleSchema = apiextensionsv1beta1.JSONSchemaProps{
		Description: `IngressRule contains all rule types which can be applied at ingress,
i.e. network traffic that originates outside of the endpoint and
is entering the endpoint selected by the identitySelector.

- All members of this structure are optional. If omitted or empty, the
  member will have no effect on the rule.

- If multiple members are set, all of them need to match in order for
  the rule to take effect. The exception to this rule is FromRequires field;
  the effects of any Requires field in any rule will apply to all other
  rules as well.`,
		Properties: map[string]apiextensionsv1beta1.JSONSchemaProps{
			"fromIdentities": {
				Description: `FromIdentities is a list of identities, previously known as endpoints,
identified by an IdentitySelector which are allowed to communicate with
the endpoint subject to the rule.

Example:
Any endpoint with the label "role=backend" can be consumed by any
endpoint carrying the label "role=frontend".`,
				Type:       "object",
				Properties: identityRuleSchema.Properties,
			},
			"fromRequires": {
				Description: `FromRequires is a list of additional constraints which must be met
in order for the selected endpoints to be reachable. These additional
constraints do not by themselves grant access privileges and must always
be accompanied with at least one matching FromIdentities.

Example:
Any Endpoint with the label "team=A" requires consuming endpoint
to also carry the label "team=A".`,
				Type:       "object",
				Properties: identityRequirementSchema.Properties,
			},
			"fromCIDR": {
				Description: `FromCIDRs is a list of IP blocks from which the endpoint subject to the
rule is allowed to receive connections in addition to FromEndpoints,
along with a list of subnets contained within their corresponding IP
block from which traffic should not be allowed.
This will match on the source IP address of incoming connections.

Example:
Any endpoint with the label "app=my-legacy-pet" is allowed to receive
connections from 10.0.0.0/8 except from IPs in subnet 10.96.0.0/12.`,
				Type:       "object",
				Properties: cidrRuleSchema.Properties,
			},
			"fromEntities": {
				Description: `FromEntities is a list of special entities from which the endpoint subject
to the rule is allowed to receive connections. Supported entities are
world and host.`,
				Type:       "object",
				Properties: entityRuleSchema.Properties,
			},
		},
	}

	k8sServiceNamespaceSchema = apiextensionsv1beta1.JSONSchemaProps{
		Description: `K8sServiceNamespace is an abstraction for the k8s service + namespace types.`,
		Required: []string{
			"serviceSelector",
		},
		Properties: map[string]apiextensionsv1beta1.JSONSchemaProps{
			"serviceSelector": {
				Description: ``,
				Type:        "object",
				Properties:  serviceSelectorSchema.Properties,
			},
			"namespace": {
				Description: ``,
				Type:        "string",
			},
		},
	}

	k8sServiceSelectorNamespaceSchema = apiextensionsv1beta1.JSONSchemaProps{
		Description: `K8sServiceSelectorNamespace wraps service selector with namespace`,
		Properties: map[string]apiextensionsv1beta1.JSONSchemaProps{
			"serviceName": {
				Description: ``,
				Type:        "string",
			},
			"serviceNamespace": {
				Description: ``,
				Type:        "string",
			},
		},
	}

	l7RulesSchema = apiextensionsv1beta1.JSONSchemaProps{
		Description: `L7Rules is a union of port-level rule types. Mixing of different port-level
rule types is not allowed; exactly one of the following must be set.
If none are specified, then no additional port-level rules are applied.`,
		// FIXME confirm existence of anyOf in kube-apiserver
		Properties: map[string]apiextensionsv1beta1.JSONSchemaProps{
			"http": {
				Description: `HTTP specific rules.`,
				Type:        "array",
				Items: &apiextensionsv1beta1.JSONSchemaPropsOrArray{
					Schema: &portRuleHTTPSchema,
				},
			},
			"kafka": {
				Description: `Kafka-specific rules.`,
				Type:        "array",
				Items: &apiextensionsv1beta1.JSONSchemaPropsOrArray{
					Schema: &portRuleKafkaSchema,
				},
			},
		},
	}

	labelSchema = apiextensionsv1beta1.JSONSchemaProps{
		Description: ``,
		Required: []string{
			"key",
		},
		Properties: map[string]apiextensionsv1beta1.JSONSchemaProps{
			"key": {
				Description: ``,
				Type:        "string",
			},
			"source": {
				Description: ``,
				Type:        "string",
			},
			"value": {
				Description: ``,
				Type:        "string",
			},
		},
	}

	labelSelectorRequirementSchema = apiextensionsv1beta1.JSONSchemaProps{
		Description: ``,
		Properties: map[string]apiextensionsv1beta1.JSONSchemaProps{
			"key": {
				Description: ``,
				Type:        "string",
			},
			"operator": {
				Description: ``,
				Type:        "string",
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
				Description: ``,
				Type:        "array",
				Items: &apiextensionsv1beta1.JSONSchemaPropsOrArray{
					Schema: &apiextensionsv1beta1.JSONSchemaProps{
						Type: "string",
					},
				},
			},
		},
		Required: []string{"key", "operator"},
	}

	portProtocolSchema = apiextensionsv1beta1.JSONSchemaProps{
		Description: `PortProtocol specifies a Layer 4 port with an optional transport protocol.`,
		Required: []string{
			"port",
		},
		Properties: map[string]apiextensionsv1beta1.JSONSchemaProps{
			"port": {
				Description: `Port is an L4 port number. For now the string will be strictly
parsed as a single uint16. In the future, this field may support
ranges in the form "1024-2048`,
				Type: "string",
				// uint16 string regex
				Pattern: `^(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|` +
					`[1-5][0-9]{4}|[0-9]{1,4})$`,
			},
			"protocol": {
				Description: `Protocol is the Layer 4 protocol. If omitted or empty, any protocol
matches. Accepted values: "TCP", "UDP", ""/"ANY"

Matching on ICMP is not supported.`,
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
					{
						Raw: []byte(`"tcp"`),
					},
					{
						Raw: []byte(`"udp"`),
					},
					{
						Raw: []byte(`"any"`),
					},
				},
			},
		},
	}

	portRuleHTTPSchema = apiextensionsv1beta1.JSONSchemaProps{
		Description: `PortRuleHTTP is a list of HTTP protocol constraints. All fields are
optional, if all fields are empty or missing, the rule does not have any
effect.

All fields of this type are extended POSIX regex as defined by IEEE Std
1003.1, (i.e this follows the egrep/unix syntax, not the perl syntax)
matched against the path of an incoming request. Currently it can contain
characters disallowed from the conventional "path" part of a URL as defined
by RFC 3986.`,
		Properties: map[string]apiextensionsv1beta1.JSONSchemaProps{
			"headers": {
				Description: `Headers is a list of HTTP headers which must be present in the
request. If omitted or empty, requests are allowed regardless of
headers present.`,
				Type: "array",
				Items: &apiextensionsv1beta1.JSONSchemaPropsOrArray{
					Schema: &apiextensionsv1beta1.JSONSchemaProps{
						Type: "string",
					},
				},
			},
			"host": {
				Description: `Host is an extended POSIX regex matched against the host header of a
request, e.g. "foo.com"

If omitted or empty, the value of the host header is ignored.`,
				Type:   "string",
				Format: "idn-hostname",
			},
			"method": {
				Description: `Method is an extended POSIX regex matched against the method of a
request, e.g. "GET", "POST", "PUT", "PATCH", "DELETE", ...

If omitted or empty, all methods are allowed.`,
				Type: "string",
			},
			"path": {
				Description: `Path is an extended POSIX regex matched against the path of a
request. Currently it can contain characters disallowed from the
conventional "path" part of a URL as defined by RFC 3986.

If omitted or empty, all paths are all allowed.`,
				Type: "string",
			},
		},
	}

	portRuleKafkaSchema = apiextensionsv1beta1.JSONSchemaProps{
		Description: `PortRuleKafka is a list of Kafka protocol constraints. All fields are
optional, if all fields are empty or missing, the rule will match all
Kafka messages.`,
		Properties: map[string]apiextensionsv1beta1.JSONSchemaProps{
			"role": {
				Description: `Role is a case-insensitive string and describes a group of API keys
necessary to perform certain higher level Kafka operations such as "produce"
or "consume". An APIGroup automatically expands into all APIKeys required
to perform the specified higher level operation.

The following values are supported:
 - "produce": Allow producing to the topics specified in the rule
 - "consume": Allow consuming from the topics specified in the rule

This field is incompatible with the APIKey field, either APIKey or Role
may be specified.

If omitted or empty, the field has no effect and the logic of the APIKey
field applies.`,
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
				Description: `APIKey is a case-insensitive string matched against the key of a
request, e.g. "produce", "fetch", "createtopic", "deletetopic", et al
Reference: https://kafka.apache.org/protocol#protocol_api_keys

If omitted or empty, all keys are allowed.`,
				Type: "string",
			},
			"apiVersion": {
				Description: `APIVersion is the version matched against the api version of the
Kafka message. If set, it has to be a string representing a positive
integer.

If omitted or empty, all versions are allowed.`,
				Type: "string",
			},
			"clientID": {
				Description: `ClientID is the client identifier as provided in the request.

From Kafka protocol documentation:
This is a user supplied identifier for the client application. The
user can use any identifier they like and it will be used when
logging errors, monitoring aggregates, etc. For example, one might
want to monitor not just the requests per second overall, but the
number coming from each client application (each of which could
reside on multiple servers). This id acts as a logical grouping
across all requests from a particular client.

If omitted or empty, all client identifiers are allowed.`,
				Type: "string",
			},
			"topic": {
				Description: `Topic is the topic name contained in the message. If a Kafka request
contains multiple topics, then all topics must be allowed or the
message will be rejected.

This constraint is ignored if the matched request message type
doesn't contain any topic. Maximum size of Topic can be 249
characters as per recent Kafka spec and allowed characters are
a-z, A-Z, 0-9, -, . and _
Older Kafka versions had longer topic lengths of 255, but in Kafka 0.10
version the length was changed from 255 to 249. For compatibility
reasons we are using 255

If omitted or empty, all topics are allowed.`,
				Type:      "string",
				MaxLength: getInt64(255),
			},
		},
	}

	portRuleSchema = apiextensionsv1beta1.JSONSchemaProps{
		Description: `PortRule is a list of ports/protocol combinations with optional Layer 7
rules which must be met.`,
		Properties: map[string]apiextensionsv1beta1.JSONSchemaProps{
			"anyOf": {
				Description: `anyOf is a list of Layer 4 port/protocol pairs.

If omitted or empty, but with RedirectPort set, then all ports of the
endpoint subject to either the ingress or egress rule are being
redirected to the proxy.`,
				Type: "array",
				Items: &apiextensionsv1beta1.JSONSchemaPropsOrArray{
					Schema: &portProtocolSchema,
				},
			},
			"rules": {
				Description: `Rules is a list of additional port level rules which must be met in
order for the PortRule to allow traffic. If omitted or empty,
no Layer 7 rules are enforced.`,
				Type:       "object",
				Properties: l7RulesSchema.Properties,
			},
		},
	}

	ruleSchema = apiextensionsv1beta1.JSONSchemaProps{
		Description: `Rule is a policy rule which must be applied to all endpoints which match the
labels contained in the identitySelector.

Each rule is split into an ingress section which contains all rules
applicable at ingress, and an egress section applicable at egress.

Either ingress, egress, or both can be provided. If both ingress and egress
are omitted, the rule has no effect.`,
		Required: []string{
			"identitySelector",
		},
		Properties: map[string]apiextensionsv1beta1.JSONSchemaProps{
			"identitySelector": {
				Description: `IdentitySelector selects all endpoints which should be subject to
this rule. Cannot be empty.`,
				Type:       "object",
				Properties: identitySelectorSchema.Properties,
			},
			"ingress": {
				Description: `Ingress is a list of IngressRule which are enforced at ingress.
If omitted or empty, this rule does not apply at ingress.`,
				Type: "array",
				Items: &apiextensionsv1beta1.JSONSchemaPropsOrArray{
					Schema: &ingressRuleSchema,
				},
			},
			"egress": {
				Description: `Egress is a list of EgressRule which are enforced at egress.
If omitted or empty, this rule does not apply at egress.`,
				Type: "array",
				Items: &apiextensionsv1beta1.JSONSchemaPropsOrArray{
					Schema: &egressRuleSchema,
				},
			},
			"labels": {
				Description: `Labels is a list of optional strings which can be used to
re-identify the rule or to store metadata. It is possible to lookup
or delete strings based on labels. Labels are not required to be
unique, multiple rules can have overlapping or identical labels.`,
				Type: "array",
				Items: &apiextensionsv1beta1.JSONSchemaPropsOrArray{
					Schema: &labelSchema,
				},
			},
			"description": {
				Description: `Description is a free form string, it can be used by the creator of
the rule to store human readable explanation of the purpose of this
rule. Rules cannot be identified by comment.`,
				Type: "string",
			},
		},
	}

	serviceRuleSchema = apiextensionsv1beta1.JSONSchemaProps{
		Description: `ServiceRule is a rule that allows to select a service by its namespace
and name, or by a label selector.`,
		Properties: map[string]apiextensionsv1beta1.JSONSchemaProps{
			"k8sServiceSelector": {
				Description: ``,
				Type:        "object",
				Properties:  k8sServiceSelectorNamespaceSchema.Properties,
			},
			"k8sService": {
				Description: `K8sService selects a service by a name and namespace pair.`,
				Type:        "object",
				Properties:  k8sServiceNamespaceSchema.Properties,
			},
			"toPorts": {
				Description: `ToPorts is a list of destination ports identified by port number and
protocol which the endpoint subject to the rule is allowed to
receive connections on. If empty, all ports will be allowed.

Example:
Any endpoint with the label "app=httpd" can only accept incoming
connections on port 80/tcp from the service "frontend" in namespace
"qa".`,
				Type:       "object",
				Properties: portRuleSchema.Properties,
			},
		},
	}

	serviceSelectorSchema = apiextensionsv1beta1.JSONSchemaProps{
		Description: `ServiceSelector is a label selector for Kubernetes services.`,
		Type:        "object",
		Properties:  identitySelectorSchema.Properties,
	}

	spec = apiextensionsv1beta1.JSONSchemaProps{
		Description: `spec is a representation of a single cilium network policy rule.`,
		Type:        "object",
		Properties:  ruleSchema.Properties,
	}

	specs = apiextensionsv1beta1.JSONSchemaProps{
		Description: `specs is a representation of multiple cilium network policy rules.`,
		Type:        "array",
		Items: &apiextensionsv1beta1.JSONSchemaPropsOrArray{
			Schema: &ruleSchema,
		},
	}
)
