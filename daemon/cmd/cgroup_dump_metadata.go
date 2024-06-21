// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/go-openapi/runtime/middleware"

	"github.com/cilium/cilium/api/v1/models"
	restapi "github.com/cilium/cilium/api/v1/server/restapi/daemon"
)

func getCgroupDumpMetadataHandler(d *Daemon, params restapi.GetCgroupDumpMetadataParams) middleware.Responder {
	resp := models.CgroupDumpMetadata{}
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

		ips := make([]string, 0, len(pm.IPs))
		for i := range pm.IPs {
			ips = append(ips, pm.IPs[i].String())
		}

		respPm := &models.CgroupPodMetadata{
			Name:       pm.Name,
			Namespace:  pm.Namespace,
			Containers: respCms,
			Ips:        ips,
		}
		resp.PodMetadatas = append(resp.PodMetadatas, respPm)
	}

	return restapi.NewGetCgroupDumpMetadataOK().WithPayload(&resp)
}
