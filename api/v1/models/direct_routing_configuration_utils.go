package models

// Equal returns true if both objects are equals
func (dc *DirectRoutingConfiguration) Equal(do *DirectRoutingConfiguration) bool {
	return dc.Announce == do.Announce && dc.InstallRoutes == do.InstallRoutes
}
