package structs

// LoadBalancerState defines the data format for the "lb/sync" command used
// for synchronizing the "source=LocalAPI" load-balancing state, e.g. for standalone
// load-balancing uses without Kubernetes.
type LoadBalancerState struct {
	// Version of the data format. If omitted version "1" is implied.
	Version int `json:"version,omitempty" yaml:"version,omitempty"`

	Services []Service `json:"services" yaml:"services"`
}

type Service struct {
	Namespace           string     `json:"namespace" yaml:"namespace"`
	Name                string     `json:"name" yaml:"name"`
	HealthCheckNodePort uint16     `json:"healthCheckNodePort,omitempty" yaml:"healthCheckNodePort,omitempty"`
	Frontends           []Frontend `json:"frontends" yaml:"frontends"`
	Backends            []Backend  `json:"backends" yaml:"backends"`
}

type Frontend struct {
	Address Address `json:"address" yaml:"address"`
	Type    string  `json:"type" yaml:"type"`
}

type Backend struct {
	Address  Address `json:"address" yaml:"address"`
	NodeName string  `json:"nodeName,omitempty" yaml:"nodeName,omitempty"`
	State    string  `json:"state,omitempty" yaml:"state,omitempty"`
	Weight   uint16  `json:"weight,omitempty" yaml:"weight,omitempty"`
}

type Address struct {
	IP       string `json:"ip" yaml:"ip"`
	Port     uint16 `json:"port" yaml:"port"`
	Protocol string `json:"protocol" yaml:"protocol"`
	Scope    string `json:"scope,omitempty" yaml:"scope,omitempty"`
}
