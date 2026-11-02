// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package resolver

import (
	"github.com/cilium/cilium/pkg/cgroups/manager"
	"github.com/cilium/cilium/pkg/hubble/resolver/types"
)

type PodMetadataGetter struct {
	manager manager.CGroupManager
}

func NewPodMetadataGetter(manager manager.CGroupManager) types.PodMetadataGetter {
	return &PodMetadataGetter{manager: manager}
}

func (g *PodMetadataGetter) GetPodMetadataForContainer(cgroupId uint64) *manager.PodMetadata {
	if g.manager == nil {
		return nil
	}
	return g.manager.GetPodMetadataForContainer(cgroupId)
}
