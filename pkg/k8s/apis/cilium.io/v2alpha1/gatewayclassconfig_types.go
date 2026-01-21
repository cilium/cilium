// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium},singular="ciliumgatewayclassconfig",path="ciliumgatewayclassconfigs",scope="Namespaced",shortName={cgcc}
// +kubebuilder:printcolumn:name="Accepted",type=string,JSONPath=`.status.conditions[?(@.type=="Accepted")].status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
// +kubebuilder:printcolumn:name="Description",type=string,JSONPath=`.spec.description`,priority=1
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// CiliumGatewayClassConfig is a Kubernetes third-party resource which
// is used to configure Gateways owned by GatewayClass.
type CiliumGatewayClassConfig struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	// +kubebuilder:validation:Required
	metav1.ObjectMeta `json:"metadata"`

	// Spec is a human-readable of a GatewayClass configuration.
	//
	// +kubebuilder:validation:Optional
	Spec CiliumGatewayClassConfigSpec `json:"spec,omitempty"`

	// Status is the status of the policy.
	//
	// +deepequal-gen=false
	// +kubebuilder:validation:Optional
	Status CiliumGatewayClassConfigStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:openapi-gen=false
// +deepequal-gen=false

// CiliumGatewayClassConfigList is a list of
// CiliumGatewayClassConfig objects.
type CiliumGatewayClassConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	// Items is a list of CiliumGatewayClassConfigs.
	Items []CiliumGatewayClassConfig `json:"items"`
}

// +deepequal-gen=true

type LoadBalancerSourceRangesPolicyType string

const (
	// LoadBalancerSourceRangesPolicyAllow allows traffic for the given source ranges.
	LoadBalancerSourceRangesPolicyAllow LoadBalancerSourceRangesPolicyType = "Allow"

	// LoadBalancerSourceRangesPolicyDeny denies traffic for the given source ranges.
	LoadBalancerSourceRangesPolicyDeny LoadBalancerSourceRangesPolicyType = "Deny"
)

// ServerHeaderTransformationType controls how Envoy handles the HTTP Server header.
//
// +kubebuilder:validation:Enum=OVERWRITE;APPEND_IF_ABSENT;PASS_THROUGH
type ServerHeaderTransformationType string

const (
	// ServerHeaderTransformationOverwrite overwrites any Server header with "envoy".
	ServerHeaderTransformationOverwrite ServerHeaderTransformationType = "OVERWRITE"

	// ServerHeaderTransformationAppendIfAbsent appends Server "envoy" if no Server header is present.
	// If a Server header is present, passes it through.
	ServerHeaderTransformationAppendIfAbsent ServerHeaderTransformationType = "APPEND_IF_ABSENT"

	// ServerHeaderTransformationPassThrough passes through the value of the server header,
	// and does not append a header if none is present.
	ServerHeaderTransformationPassThrough ServerHeaderTransformationType = "PASS_THROUGH"
)

type ServiceConfig struct {
	// Sets the Service.Spec.Type in generated Service objects to the given value.
	// Only LoadBalancer and NodePort are supported.
	//
	// +kubebuilder:validation:Enum=LoadBalancer;NodePort
	// +kubebuilder:default="LoadBalancer"
	// +kubebuilder:validation:Optional
	Type corev1.ServiceType `json:"type,omitempty"`

	// Sets the Service.Spec.ExternalTrafficPolicy in generated Service objects to the given value.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:default="Cluster"
	ExternalTrafficPolicy corev1.ServiceExternalTrafficPolicy `json:"externalTrafficPolicy,omitempty"`

	// Sets the Service.Spec.LoadBalancerClass in generated Service objects to the given value.
	//
	// +kubebuilder:validation:Optional
	LoadBalancerClass *string `json:"loadBalancerClass,omitempty"`

	// Sets the Service.Spec.IPFamilies in generated Service objects to the given value.
	//
	// +listType=atomic
	// +kubebuilder:validation:Optional
	IPFamilies []corev1.IPFamily `json:"ipFamilies,omitempty"`

	// Sets the Service.Spec.IPFamilyPolicy in generated Service objects to the given value.
	//
	// +kubebuilder:validation:Optional
	IPFamilyPolicy *corev1.IPFamilyPolicy `json:"ipFamilyPolicy,omitempty"`

	// Sets the Service.Spec.AllocateLoadBalancerNodePorts in generated Service objects to the given value.
	//
	// +kubebuilder:validation:Optional
	AllocateLoadBalancerNodePorts *bool `json:"allocateLoadBalancerNodePorts,omitempty"`

	// Sets the Service.Spec.LoadBalancerSourceRanges in generated Service objects to the given value.
	//
	// +kubebuilder:validation:Optional
	// +listType=atomic
	LoadBalancerSourceRanges []string `json:"loadBalancerSourceRanges,omitempty"`

	// LoadBalancerSourceRangesPolicy defines the policy for the LoadBalancerSourceRanges if the incoming traffic
	// is allowed or denied.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Enum=Allow;Deny
	// +kubebuilder:default="Allow"
	LoadBalancerSourceRangesPolicy LoadBalancerSourceRangesPolicyType `json:"loadBalancerSourceRangesPolicy,omitempty"`

	// Sets the Service.Spec.TrafficDistribution in generated Service objects to the given value.
	//
	// +kubebuilder:validation:Optional
	TrafficDistribution *string `json:"trafficDistribution,omitempty"`
}

type GRPCWebTranslationConfig struct {
	// Enabled controls Envoy's gRPC-web to gRPC request translation.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=true
	Enabled *bool `json:"enabled,omitempty"`
}

type HTTPOptions struct {
	// GRPCWebTranslation controls Envoy's gRPC-web to gRPC request translation.
	//
	// +kubebuilder:validation:Optional
	GRPCWebTranslation *GRPCWebTranslationConfig `json:"grpcWebTranslation,omitempty"`
}

// Telemetry specifies observability configuration for Gateways using this
// GatewayClass configuration.
type Telemetry struct {
	// AccessLogs configures Envoy access logging for generated Gateway
	// listeners.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=8
	AccessLogs []AccessLogs `json:"accessLogs,omitempty"`
}

// AccessLogs defines an Envoy access log configuration, including its output
// format and the generated proxy components that should emit it.
// Access logs are currently written to Envoy stdout.
type AccessLogs struct {
	// Format specifies the access log output format.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=JSON;Text
	Format AccessLogsFormat `json:"format"`
	// JSON maps access log field names to Envoy command operators.
	// It is used when Format is "JSON".
	// For available format specifiers, see the Envoy documentation:
	// - https://www.envoyproxy.io/docs/envoy/latest/configuration/observability/access_log/usage
	// Note: Always refer to the documentation matching the specific Envoy version you are running.
	// The following Cilium-specific formatters are also supported:
	// - %CILIUM_GATEWAY_NAME% -- replaced with the Gateway resource name.
	// - %CILIUM_GATEWAY_NAMESPACE% -- replaced with the Gateway resource namespace.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MinProperties=1
	// +kubebuilder:validation:MaxProperties=64
	// +kubebuilder:default={start_time:"%START_TIME%",method:"%REQUEST_HEADER(:METHOD)%",path:"%REQUEST_HEADER(X-ENVOY-ORIGINAL-PATH?:PATH)%",protocol:"%PROTOCOL%",response_code:"%RESPONSE_CODE%",response_flags:"%RESPONSE_FLAGS%",bytes_received:"%BYTES_RECEIVED%",bytes_sent:"%BYTES_SENT%",duration:"%DURATION%",upstream_service_time:"%RESPONSE_HEADER(X-ENVOY-UPSTREAM-SERVICE-TIME)%",x_forwarded_for:"%REQUEST_HEADER(X-FORWARDED-FOR)%",user_agent:"%REQUEST_HEADER(USER-AGENT)%",request_id:"%REQUEST_HEADER(X-REQUEST-ID)%",authority:"%REQUEST_HEADER(:AUTHORITY)%",upstream_host:"%UPSTREAM_HOST%"}
	JSON map[string]string `json:"json,omitempty"`
	// Text specifies the Envoy access log format string.
	// It is used when Format is "Text".
	// For available format specifiers, see the Envoy documentation:
	// - https://www.envoyproxy.io/docs/envoy/latest/configuration/observability/access_log/usage
	// Note: Always refer to the documentation matching the specific Envoy version you are running.
	// The following Cilium-specific formatters are also supported:
	// - %CILIUM_GATEWAY_NAME% -- replaced with the Gateway resource name.
	// - %CILIUM_GATEWAY_NAMESPACE% -- replaced with the Gateway resource namespace.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=4096
	// +kubebuilder:default="[%START_TIME%] \"%REQUEST_HEADER(:METHOD)% %REQUEST_HEADER(X-ENVOY-ORIGINAL-PATH?:PATH)% %PROTOCOL%\" %RESPONSE_CODE% %RESPONSE_FLAGS% %BYTES_RECEIVED% %BYTES_SENT% %DURATION% %RESPONSE_HEADER(X-ENVOY-UPSTREAM-SERVICE-TIME)% \"%REQUEST_HEADER(X-FORWARDED-FOR)%\" \"%REQUEST_HEADER(USER-AGENT)%\" \"%REQUEST_HEADER(X-REQUEST-ID)%\" \"%REQUEST_HEADER(:AUTHORITY)%\" \"%UPSTREAM_HOST%\""
	Text string `json:"text,omitempty"`
	// Targets specifies the generated Envoy proxy components where access logs
	// are emitted. If omitted, access logs are emitted for HTTP traffic only.
	// HTTP targets Envoy HTTP connection managers. TCP targets Envoy TCP proxies,
	// including TLS passthrough.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:default={HTTP}
	// +listType=set
	Targets []AccessLogsTarget `json:"targets,omitempty"`
}

// AccessLogsFormat specifies the access log output format.
type AccessLogsFormat string

const (
	AccessLogsFormatJSON AccessLogsFormat = "JSON"
	AccessLogsFormatText AccessLogsFormat = "Text"
)

// AccessLogsTarget specifies where access logs are emitted.
//
// +kubebuilder:validation:Enum=HTTP;TCP
type AccessLogsTarget string

const (
	// AccessLogsTargetHTTP emits access logs from Envoy HTTP connection managers.
	AccessLogsTargetHTTP AccessLogsTarget = "HTTP"
	// AccessLogsTargetTCP emits access logs from Envoy TCP proxies, including TLS passthrough.
	AccessLogsTargetTCP AccessLogsTarget = "TCP"
)

// EnvoyConfig specifies proxy configuration options for Cilium-managed Gateways.
// These settings control Envoy-specific behavior that is not part of the Gateway API standard.
// +deepequal-gen=true
type EnvoyConfig struct {
	// ServerHeaderTransformation controls the HTTP "Server" response header.
	// Defaults to OVERWRITE.
	//
	// +kubebuilder:default="OVERWRITE"
	// +kubebuilder:validation:Optional
	ServerHeaderTransformation *ServerHeaderTransformationType `json:"serverHeaderTransformation,omitempty"`
}

// CiliumGatewayClassConfigSpec specifies all the configuration options for a
// Cilium managed GatewayClass.
type CiliumGatewayClassConfigSpec struct {
	// Description helps describe a GatewayClass configuration with more details.
	//
	// +kubebuilder:validation:MaxLength=64
	// +kubebuilder:validation:Optional
	Description *string `json:"description,omitempty"`

	// Service specifies the configuration for the generated Service.
	// Note that not all fields from upstream Service.Spec are supported
	//
	// +kubebuilder:validation:Optional
	Service *ServiceConfig `json:"service,omitempty"`
	// HTTPOptions specifies HTTP connection manager options.
	//
	// +kubebuilder:validation:Optional
	HTTPOptions *HTTPOptions `json:"httpOptions,omitempty"`
	// Telemetry specifies observability options for Gateways using this
	// GatewayClass configuration.
	//
	// +kubebuilder:validation:Optional
	Telemetry *Telemetry `json:"telemetry,omitempty"`
	// Envoy specifies proxy configuration options.
	// These settings control Envoy-specific behavior that is not part of the Gateway API standard.
	//
	// +kubebuilder:validation:Optional
	Envoy *EnvoyConfig `json:"envoy,omitempty"`
}

// +deepequal-gen=false

// CiliumGatewayClassConfigStatus contains the status of a CiliumGatewayClassConfig.
type CiliumGatewayClassConfigStatus struct {
	// Current service state
	// +kubebuilder:validation:Optional
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`
}

// GRPCWebTranslationEnabled returns true if gRPC-web to gRPC request translation should be enabled.
// Translation is always enabled unless explicitly disabled.
func (c *CiliumGatewayClassConfig) GRPCWebTranslationEnabled() bool {
	return c == nil ||
		c.Spec.HTTPOptions == nil ||
		c.Spec.HTTPOptions.GRPCWebTranslation == nil ||
		c.Spec.HTTPOptions.GRPCWebTranslation.Enabled == nil ||
		*c.Spec.HTTPOptions.GRPCWebTranslation.Enabled
}

// IsTelemetryConfigured returns true if telemetry is configured.
func (c *CiliumGatewayClassConfig) IsTelemetryConfigured() bool {
	return c != nil &&
		c.Spec.Telemetry != nil
}

// IsAccessLogsConfigured returns true if access logging is configured.
func (t *Telemetry) IsAccessLogsConfigured() bool {
	return t != nil && len(t.AccessLogs) > 0
}
