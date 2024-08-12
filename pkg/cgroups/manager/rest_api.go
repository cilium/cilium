// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package manager

import (
	"github.com/go-openapi/runtime/middleware"

	"github.com/cilium/cilium/api/v1/models"
	daemonrestapi "github.com/cilium/cilium/api/v1/server/restapi/daemon"
)

type getCgroupDumpMetadataRestApiHandler struct {
	cgroupManager CGroupManager
}

func newGetCgroupDumpMetadataRestApiHandler(cgroupManager CGroupManager) daemonrestapi.GetCgroupDumpMetadataHandler {
	return &getCgroupDumpMetadataRestApiHandler{
		cgroupManager: cgroupManager,
	}
}

func (h *getCgroupDumpMetadataRestApiHandler) Handle(params daemonrestapi.GetCgroupDumpMetadataParams) middleware.Responder {
	resp := models.CgroupDumpMetadata{}
	metadata := h.cgroupManager.DumpPodMetadata()

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

	return daemonrestapi.NewGetCgroupDumpMetadataOK().WithPayload(&resp)
}
