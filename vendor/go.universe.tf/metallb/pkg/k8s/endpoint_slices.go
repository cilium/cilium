package k8s

import (
	v1 "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1beta1"
)

type EpsOrSlices struct {
	Type      EpsOrSliceType
	EpVal     *v1.Endpoints
	SlicesVal []*discovery.EndpointSlice
}

type EpsOrSliceType int

const (
	Unknown EpsOrSliceType = iota
	Eps
	Slices
)

// IsConditionReady tells if the conditions represent a ready state, interpreting
// nil ready as ready
func IsConditionReady(conditions discovery.EndpointConditions) bool {
	if conditions.Ready == nil {
		return true
	}
	return *conditions.Ready
}
