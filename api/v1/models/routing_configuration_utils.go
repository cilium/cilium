package models

// String returns the RoutingConfiguration as string
func (rc *RoutingConfiguration) String() string {
	if rc == nil {
		return ""
	}

	result := "encapsulation=" + rc.Encapsulation
	if dcStr := rc.DirectRouting.String(); dcStr != "" {
		result = result + " " + dcStr
	}

	return result
}

// Equal returns true if both objects are equals
func (rc *RoutingConfiguration) Equal(ro *RoutingConfiguration) bool {
	return rc.Encapsulation == ro.Encapsulation && rc.DirectRouting.Equal(ro.DirectRouting)
}

// EncapsulationEnabled returns true if any kind of encapsulation is enabled
func (rc *RoutingConfiguration) EncapsulationEnabled() bool {
	return rc != nil && rc.Encapsulation != RoutingConfigurationEncapsulationDisabled && rc.Encapsulation != ""
}

// NewRoutingConfiguration returns a new empty RoutingConfiguration
func NewRoutingConfiguration() *RoutingConfiguration {
	return &RoutingConfiguration{
		DirectRouting: &DirectRoutingConfiguration{},
	}
}
