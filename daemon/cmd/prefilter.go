// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"net"

	"github.com/go-openapi/runtime/middleware"

	"github.com/cilium/cilium/api/v1/models"
	. "github.com/cilium/cilium/api/v1/server/restapi/prefilter"
	"github.com/cilium/cilium/pkg/api"
)

func getPrefilterHandler(d *Daemon, params GetPrefilterParams) middleware.Responder {
	var list []string
	var revision int64
	if d.preFilter == nil {
		msg := fmt.Errorf("Prefilter is not enabled in daemon")
		return api.Error(GetPrefilterFailureCode, msg)
	}
	list, revision = d.preFilter.Dump(list)
	spec := &models.PrefilterSpec{
		Revision: revision,
		Deny:     list,
	}
	status := &models.Prefilter{
		Spec: spec,
		Status: &models.PrefilterStatus{
			Realized: spec,
		},
	}
	return NewGetPrefilterOK().WithPayload(status)
}

func patchPrefilterHandler(d *Daemon, params PatchPrefilterParams) middleware.Responder {
	if d.preFilter == nil {
		msg := fmt.Errorf("Prefilter is not enabled in daemon")
		return api.Error(PatchPrefilterFailureCode, msg)
	}

	spec := params.PrefilterSpec
	list := make([]net.IPNet, 0, len(spec.Deny))
	for _, cidrStr := range spec.Deny {
		_, cidr, err := net.ParseCIDR(cidrStr)
		if err != nil {
			msg := fmt.Errorf("Invalid CIDR string %s", cidrStr)
			return api.Error(PatchPrefilterInvalidCIDRCode, msg)
		}
		list = append(list, *cidr)
	}
	err := d.preFilter.Insert(spec.Revision, list)
	if err != nil {
		return api.Error(PatchPrefilterFailureCode, err)
	}
	return NewPatchPrefilterOK()
}

func deletePrefilterHandler(d *Daemon, params DeletePrefilterParams) middleware.Responder {
	if d.preFilter == nil {
		msg := fmt.Errorf("Prefilter is not enabled in daemon")
		return api.Error(DeletePrefilterFailureCode, msg)
	}

	spec := params.PrefilterSpec
	list := make([]net.IPNet, 0, len(spec.Deny))
	for _, cidrStr := range spec.Deny {
		_, cidr, err := net.ParseCIDR(cidrStr)
		if err != nil {
			msg := fmt.Errorf("Invalid CIDR string %s", cidrStr)
			return api.Error(DeletePrefilterInvalidCIDRCode, msg)
		}
		list = append(list, *cidr)
	}
	err := d.preFilter.Delete(spec.Revision, list)
	if err != nil {
		return api.Error(DeletePrefilterFailureCode, err)
	}
	return NewDeletePrefilterOK()
}
