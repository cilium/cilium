// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package prefilter

import (
	"fmt"
	"net"

	"github.com/go-openapi/runtime/middleware"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/api/v1/server/restapi/prefilter"
	"github.com/cilium/cilium/pkg/api"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
)

type getPrefilterHandler struct {
	preFilter datapath.PreFilter
}

func (h *getPrefilterHandler) Handle(_ prefilter.GetPrefilterParams) middleware.Responder {
	var list []string
	var revision int64
	if !h.preFilter.Enabled() {
		msg := fmt.Errorf("prefilter is not enabled in daemon")
		return api.Error(prefilter.GetPrefilterFailureCode, msg)
	}
	list, revision = h.preFilter.Dump(list)
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
	return prefilter.NewGetPrefilterOK().WithPayload(status)
}

type patchPrefilterHandler struct {
	preFilter datapath.PreFilter
}

func (h *patchPrefilterHandler) Handle(params prefilter.PatchPrefilterParams) middleware.Responder {
	if !h.preFilter.Enabled() {
		msg := fmt.Errorf("prefilter is not enabled in daemon")
		return api.Error(prefilter.PatchPrefilterFailureCode, msg)
	}

	spec := params.PrefilterSpec
	list := make([]net.IPNet, 0, len(spec.Deny))
	for _, cidrStr := range spec.Deny {
		_, cidr, err := net.ParseCIDR(cidrStr)
		if err != nil {
			msg := fmt.Errorf("invalid CIDR string %s", cidrStr)
			return api.Error(prefilter.PatchPrefilterInvalidCIDRCode, msg)
		}
		list = append(list, *cidr)
	}
	err := h.preFilter.Insert(spec.Revision, list)
	if err != nil {
		return api.Error(prefilter.PatchPrefilterFailureCode, err)
	}
	return prefilter.NewPatchPrefilterOK()
}

type deletePrefilterHandler struct {
	preFilter datapath.PreFilter
}

func (h *deletePrefilterHandler) Handle(params prefilter.DeletePrefilterParams) middleware.Responder {
	if !h.preFilter.Enabled() {
		msg := fmt.Errorf("prefilter is not enabled in daemon")
		return api.Error(prefilter.DeletePrefilterFailureCode, msg)
	}

	spec := params.PrefilterSpec
	list := make([]net.IPNet, 0, len(spec.Deny))
	for _, cidrStr := range spec.Deny {
		_, cidr, err := net.ParseCIDR(cidrStr)
		if err != nil {
			msg := fmt.Errorf("invalid CIDR string %s", cidrStr)
			return api.Error(prefilter.DeletePrefilterInvalidCIDRCode, msg)
		}
		list = append(list, *cidr)
	}
	err := h.preFilter.Delete(spec.Revision, list)
	if err != nil {
		return api.Error(prefilter.DeletePrefilterFailureCode, err)
	}
	return prefilter.NewDeletePrefilterOK()
}
