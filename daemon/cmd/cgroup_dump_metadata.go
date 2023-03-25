// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/go-openapi/runtime/middleware"

	"github.com/cilium/cilium/api/v1/models"
	restapi "github.com/cilium/cilium/api/v1/server/restapi/daemon"
)

type getCgroupDumpMetadata struct {
	daemon *Daemon
}

// NewGetCgroupDumpMetadataHandler returns the cgroup dump metadata handler for the agent
func NewGetCgroupDumpMetadataHandler(d *Daemon) restapi.GetCgroupDumpMetadataHandler {
	return &getCgroupDumpMetadata{daemon: d}
}

func (h *getCgroupDumpMetadata) Handle(params restapi.GetCgroupDumpMetadataParams) middleware.Responder {
	resp := models.CgroupDumpMetadata{}
	d := h.daemon
	metadata := d.cgroupManager.DumpPodMetadata()

	for _, pm := range metadata {
		var respCms []*models.CgroupContainerMetadata
		for _, cm := range pm.Containers {
			respCm := &models.CgroupContainerMetadata{
				CgroupID:   cm.CgroupId,
				CgroupPath: cm.CgroupPath,
			}
			respCms = append(respCms, respCm)
		}
		respPm := &models.CgroupPodMetadata{
			Name:       pm.Name,
			Namespace:  pm.Namespace,
			Containers: respCms,
			Ips:        pm.IPs,
		}
		resp.PodMetadatas = append(resp.PodMetadatas, respPm)
	}

	return restapi.NewGetCgroupDumpMetadataOK().WithPayload(&resp)
}
