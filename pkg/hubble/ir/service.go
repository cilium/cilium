// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ir

import "github.com/cilium/cilium/api/v1/flow"

// Service tracks a k8s service.
type Service struct {
	Name      string `json:"name,omitempty"`
	Namespace string `json:"namespace,omitempty"`
}

func (s Service) isEmpty() bool {
	return s.Name == "" && s.Namespace == ""
}

func (s Service) toProto() *flow.Service {
	if s.isEmpty() {
		return nil
	}

	return &flow.Service{
		Name:      s.Name,
		Namespace: s.Namespace,
	}
}

// ProtoToService converts protobuf representation to an internal representation.
func ProtoToService(s *flow.Service) Service {
	if s == nil {
		return Service{}
	}

	return Service{
		Name:      s.Name,
		Namespace: s.Namespace,
	}
}
