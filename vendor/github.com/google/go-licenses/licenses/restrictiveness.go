package licenses

type LicenseRestrictiveness string

const (
	RestrictionsShareLicense LicenseRestrictiveness = "ShareLicense"
	RestrictionsShareCode    LicenseRestrictiveness = "ShareCode"
	RestrictionsUnknown      LicenseRestrictiveness = "Unknown"
	RestrictionsNotAllowed   LicenseRestrictiveness = "NotAllowed"
)

func LicenseTypeRestrictiveness(licenseTypes ...Type) LicenseRestrictiveness {
	if len(licenseTypes) == 0 {
		// No licenses foundm, so we don't know what the restrictions are
		return RestrictionsUnknown
	}

	// Find any non-allowed licenses
	for _, licenseType := range licenseTypes {
		switch licenseType {
		case Notice, Permissive, Unencumbered,
			Restricted, Reciprocal,
			Unknown:
			// these are allowed/ handled by following logic
		default:
			return RestrictionsNotAllowed
		}
	}

	// Find unknown licenses
	for _, licenseType := range licenseTypes {
		switch licenseType {
		case Unknown:
			return RestrictionsUnknown
		}
	}

	// Find any licenses that require sharing code
	for _, licenseType := range licenseTypes {
		switch licenseType {
		case Restricted, Reciprocal:
			return RestrictionsShareCode
		}
	}

	// Find any licenses that require sharing license
	for _, licenseType := range licenseTypes {
		switch licenseType {
		case Notice, Permissive, Unencumbered:
			return RestrictionsShareLicense
		}
	}

	panic("unreachable")
}
