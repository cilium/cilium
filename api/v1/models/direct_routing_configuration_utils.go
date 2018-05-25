package models

import (
	"fmt"
)

// Equal returns true if both objects are equals
func (dc *DirectRoutingConfiguration) Equal(do *DirectRoutingConfiguration) bool {
	return dc.InstallRoutes == do.InstallRoutes
}

// String returns the DirectRoutingConfiguration as string
func (dc *DirectRoutingConfiguration) String() string {
	if dc == nil {
		return ""
	}

	return fmt.Sprintf("install-direct-routes=%t", dc.InstallRoutes)
}
