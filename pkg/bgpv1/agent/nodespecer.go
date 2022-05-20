// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package agent

import (
	"fmt"

	v1 "k8s.io/client-go/listers/core/v1"

	v2 "github.com/cilium/cilium/pkg/k8s/client/listers/cilium.io/v2"
)

// nodeSpecer abstracts the underlying mechanism to list information about the
// Node resource Cilium is running on.
//
// The BGP Control Plane needs to obtain Node information however, it may need
// to query the Kubernetes Node or the Cilium Node object depending on IPAM
// configuration.
type nodeSpecer interface {
	PodCIDRs() ([]string, error)
	Labels() (map[string]string, error)
	Annotations() (map[string]string, error)
}

type kubernetesNodeSpecer struct {
	Name       string
	NodeLister v1.NodeLister
}

func (s *kubernetesNodeSpecer) Annotations() (map[string]string, error) {
	n, err := s.NodeLister.Get(s.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to get node %v: %v", s.Name, err)
	}
	return n.Annotations, nil
}

func (s *kubernetesNodeSpecer) Labels() (map[string]string, error) {
	n, err := s.NodeLister.Get(s.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to get node %v: %v", s.Name, err)
	}
	return n.Labels, nil
}

func (s *kubernetesNodeSpecer) PodCIDRs() ([]string, error) {
	n, err := s.NodeLister.Get(s.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to get node %v: %v", s.Name, err)
	}
	if n.Spec.PodCIDRs != nil {
		return n.Spec.PodCIDRs, nil
	}
	if n.Spec.PodCIDR != "" {
		return []string{n.Spec.PodCIDR}, nil
	}
	return []string{}, nil
}

type ciliumNodeSpecer struct {
	Name       string
	NodeLister v2.CiliumNodeLister
}

func (s *ciliumNodeSpecer) Annotations() (map[string]string, error) {
	n, err := s.NodeLister.Get(s.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to get node %v: %v", s.Name, err)
	}
	return n.Annotations, nil
}

func (s *ciliumNodeSpecer) Labels() (map[string]string, error) {
	n, err := s.NodeLister.Get(s.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to get node %v: %v", s.Name, err)
	}
	return n.Labels, nil
}

func (s *ciliumNodeSpecer) PodCIDRs() ([]string, error) {
	n, err := s.NodeLister.Get(s.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to get node %v: %v", s.Name, err)
	}
	if n.Spec.IPAM.PodCIDRs != nil {
		return n.Spec.IPAM.PodCIDRs, nil
	}
	return []string{}, nil
}
