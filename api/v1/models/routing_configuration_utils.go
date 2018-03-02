package models

import (
	"fmt"
)

func (rc *RoutingConfiguration) String() string {
	return fmt.Sprintf("encapsulation=%s announce-direct-routing=%t install-direct-routes=%t",
		rc.Encapsulation, rc.DirectRouting.Announce, rc.DirectRouting.InstallRoutes)
}

// Equal returns true if both objects are equals
func (rc *RoutingConfiguration) Equal(ro *RoutingConfiguration) bool {
	return rc.Encapsulation == ro.Encapsulation && rc.DirectRouting.Equal(ro.DirectRouting)
}

// EncapsulationEnabled returns true if any kind of encapsulation is enabled
func (rc *RoutingConfiguration) EncapsulationEnabled() bool {
	return rc != nil && rc.Encapsulation != RoutingConfigurationEncapsulationDisabled && rc.Encapsulation != ""
}

// DirectRoutingAnnounced returns true if the node is announcing direct routing
func (rc *RoutingConfiguration) DirectRoutingAnnounced() bool {
	return rc != nil && rc.DirectRouting != nil && rc.DirectRouting.Announce
}

// NewRoutingConfiguration returns a new empty RoutingConfiguration
func NewRoutingConfiguration() *RoutingConfiguration {
	return &RoutingConfiguration{
		DirectRouting: &DirectRoutingConfiguration{},
	}
}
