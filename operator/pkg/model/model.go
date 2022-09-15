package model

// Model holds an abstracted data model representing the translation
// of various types of Kubernetes config to Cilium config.
type Model struct {
	HTTP []HTTPListener
	// mu   lock.Mutex
}

// HTTPListener holds configuration for any listener that terminates and proxies HTTP
// including HTTP and HTTPS.
// Each holds the configuration info for one distinct HTTP listener, by
//   - Hostname
//   - TLS
//   - Address
//   - Port
type HTTPListener struct {
	// Name of the HTTPListener
	Name string
	// Sources is a slice of fully qualified resources this HTTPListener is sourced
	// from.
	Sources []FullyQualifiedResource
	// IPAddress that the listener should listen on.
	// The string must be parseable as an IP address.
	Address string
	// Port on which the service can be expected to be accessed by clients.
	Port uint32
	// Hostname that the listener should match.
	// Wildcards are supported in prefix or suffix forms, or the special wildcard `*`.
	// An empty list means that the Listener should match all hostnames.
	Hostname string
	// TLS Certifcate information. If omitted, then the listener is a cleartext HTTP listener.
	TLS *TLSSecret
	// Routes associated with HTTP traffic to the service.
	// An empty list means that traffic will not be routed.
	Routes []HTTPRoute
}

// FullyQualifiedResource stores the full details of a Kubernetes resource, including
// the Group, Version, and Kind.
// Namespace must be set to the empty string for cluster-scoped resources.
type FullyQualifiedResource struct {
	Name      string
	Namespace string
	Group     string
	Version   string
	Kind      string
}

// TLSSecret holds a reference to a secret containing a TLS keypair.
type TLSSecret struct {
	Name      string
	Namespace string
}

// HTTPRoute holds all the details needed to route HTTP traffic to a backend.
type HTTPRoute struct {
	Name string
	// PathMatch specifies that the HTTPRoute should match a path.
	PathMatch StringMatch
	Backends  []Backend
}

// StringMatch describes various types of string matching.
// Only one field may be set.
type StringMatch struct {
	Prefix string
	Exact  string
	Regex  string
}

// Backend holds a Kubernetes Service that points to a backend for traffic.
type Backend struct {
	// Name of the Service.
	Name string
	// Namespace of the Service.
	Namespace string
	// Port contains the details of the port on the Service to connect to
	// If unset, the same port as the top-level Listener will be used.
	Port *BackendPort
}

// BackendPort holds the details of what port on the Service to connect to.
// Only one of Port or Name can be set.
type BackendPort struct {
	// Port holds the numeric port to connect to.
	Port uint32
	// Name holds a string which will be used to connect to the port with a
	// matching spec.ports[].name in the target Service.
	Name string
}
