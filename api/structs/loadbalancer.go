package structs

// LoadBalancerState defines the file format for the "lb/sync" command used
// for synchronizing the "source=LocalAPI" load-balancing state, e.g. for standalone
// load-balancing uses without Kubernetes.
type LoadBalancerState struct {
	// Version of the file format. If omitted "v1" is implied.
	Version int `json:"version,omitempty" yaml:"version,omitempty"`

	Services []Service `json:"services" yaml:"services"`
}

type Service struct {
	Namespace           string `json:"namespace" yaml:"namespace"`
	Name                string `json:"name" yaml:"name"`
	ExtTrafficPolicy    string `json:"extTrafficPolicy,omitempty" yaml:"extTrafficPolicy,omitempty"`
	IntTrafficPolicy    string `json:"intTrafficPolicy,omitempty" yaml:"intTrafficPolicy,omitempty"`
	NatPolicy           string `json:"natPolicy,omitempty" yaml:"natPolicy,omitempty"`
	HealthCheckNodePort uint16 `json:"healthCheckNodePort,omitempty"`

	Frontends []Frontend `json:"frontends" yaml:"frontends"`
	Backends  []Backend  `json:"backends" yaml:"backends"`
}

type Frontend struct {
	Address  Address `json:"address" yaml:"address"`
	PortName string  `json:"portName,omitempty" yaml:"portName,omitempty"`
	Type     string  `json:"type" yaml:"type"`
}

type Backend struct {
	Address Address `json:"address" yaml:"address"`
	State   string  `json:"state,omitempty"`
	Weight  uint16  `json:"weight,omitempty"`
}

type Address struct {
	IP       string `json:"address" yaml:"address"`
	Port     uint16 `json:"port" yaml:"port"`
	Protocol string `json:"protocol" yaml:"protocol"`
	Scope    string `json:"scope,omitempty"`
}
