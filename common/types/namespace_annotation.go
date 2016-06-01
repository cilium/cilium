package types

type IngressIsolationPolicy string

const (
	// Deny all ingress traffic to pods in this namespace. Ingress means
	// any incoming traffic to pods, whether that be from other pods within this namespace
	// or any source outside of this namespace.
	DefaultDeny IngressIsolationPolicy = "DefaultDeny"
)

// Standard NamespaceSpec object, modified to include a new
// NamespaceNetworkPolicy field.
type NamespaceSpec struct {
	// This is a pointer so that it can be left undefined.
	NetworkPolicy *NamespaceNetworkPolicy `json:"networkPolicy,omitempty"`
}

type NamespaceNetworkPolicy struct {
	// Ingress configuration for this namespace.  This config is
	// applied to all pods within this namespace. For now, only
	// ingress is supported.  This field is optional - if not
	// defined, then the cluster default for ingress is applied.
	Ingress *NamespaceIngressPolicy `json:"ingress,omitempty"`
}

// Configuration for ingress to pods within this namespace.
// For now, this only supports specifying an isolation policy.
type NamespaceIngressPolicy struct {
	// The isolation policy to apply to pods in this namespace.
	// Currently this field only supports "DefaultDeny", but could
	// be extended to support other policies in the future.  When set to DefaultDeny,
	// pods in this namespace are denied ingress traffic by default.  When not defined,
	// the cluster default ingress isolation policy is applied (currently allow all).
	Isolation *IngressIsolationPolicy `json:"isolation,omitempty"`
}
