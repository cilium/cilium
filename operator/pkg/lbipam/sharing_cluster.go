// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lbipam

import "slices"

type sharingKey string

type sharingIndex map[sharingKey]sharingGroup

func newSharingIndex() sharingIndex {
	return make(map[sharingKey]sharingGroup)
}

func (si sharingIndex) Get(key sharingKey) sharingGroup {
	return si[key]
}

func (si sharingIndex) Add(key sharingKey, cluster *sharingCluster) {
	si[key] = append(si[key], cluster)
}

func (si sharingIndex) Remove(key sharingKey, cluster *sharingCluster) {
	group, ok := si[key]
	if !ok {
		return
	}

	idx := slices.Index(group, cluster)
	if idx == -1 {
		return
	}

	group = slices.Delete(group, idx, idx+1)
	if len(group) == 0 {
		delete(si, key)
	} else {
		si[key] = group
	}
}

type sharingGroup []*sharingCluster

type sharingCluster struct {
	SVIP     ServiceViewIP
	Services []*ServiceView
}

func (c *sharingCluster) Add(sv *ServiceView) {
	c.Services = append(c.Services, sv)
}

func (c *sharingCluster) Remove(sv *ServiceView) (empty bool) {
	idx := slices.Index(c.Services, sv)
	if idx == -1 {
		return
	}

	c.Services = slices.Delete(c.Services, idx, idx+1)
	return len(c.Services) == 0
}

func (cluster *sharingCluster) IsCompatible(sv *ServiceView) (bool, string) {
	for _, service := range cluster.Services {
		// Do not check compatibility of the service with itself, this allows us to check if a service is still
		// compatible with the current sharing cluster after modification.
		if service == sv {
			continue
		}

		if compatible, reason := service.isCompatible(sv); !compatible {
			return false, reason
		}
	}

	return true, ""
}
