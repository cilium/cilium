package config

import "github.com/envoyproxy/go-control-plane/pkg/log"

// Opts for individual xDS implementations that can be
// utilized through the functional opts pattern.
type Opts struct {
	// If true respond to ADS requests with a guaranteed resource ordering
	Ordered bool

	Logger log.Logger

	// If true, deactivate legacy wildcard mode for all resource types
	legacyWildcardDeactivated bool

	// Deactivate legacy wildcard mode for specific resource types
	legacyWildcardDeactivatedTypes map[string]struct{}
}

func NewOpts() Opts {
	return Opts{
		Ordered: false,
		Logger:  log.NewDefaultLogger(),
	}
}

// IsLegacyWildcardActive returns whether legacy wildcard mode is active for the given resource type.
// Returns true if legacy wildcard mode is active, false if it has been deactivated.
func (o Opts) IsLegacyWildcardActive(typeURL string) bool {
	if o.legacyWildcardDeactivated {
		return false
	}
	if len(o.legacyWildcardDeactivatedTypes) > 0 {
		if _, found := o.legacyWildcardDeactivatedTypes[typeURL]; found {
			return false
		}
	}
	return true
}

// Each xDS implementation should implement their own functional opts.
// It is recommended that config values be added in this package specifically,
// but the individual opts functions should be in their respective
// implementation package so the import looks like the following:
//
// `sotw.WithOrderedADS()`
// `delta.WithOrderedADS()`
//
// this allows for easy inference as to which opt applies to what implementation.
type XDSOption func(*Opts)

func DeactivateLegacyWildcard() XDSOption {
	return func(o *Opts) {
		o.legacyWildcardDeactivated = true
	}
}

func DeactivateLegacyWildcardForTypes(types []string) XDSOption {
	return func(o *Opts) {
		typeMap := make(map[string]struct{}, len(types))
		for _, t := range types {
			typeMap[t] = struct{}{}
		}
		o.legacyWildcardDeactivatedTypes = typeMap
	}
}
