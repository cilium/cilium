// Copyright 2017 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"fmt"
	"net"

	"github.com/cilium/cilium/api/v1/models"
	. "github.com/cilium/cilium/api/v1/server/restapi/prefilter"
	"github.com/cilium/cilium/pkg/apierror"
	"github.com/go-openapi/runtime/middleware"
)

type getPrefilter struct {
	d *Daemon
}

// NewGetPrefilterHandler returns new get handler for api
func NewGetPrefilterHandler(d *Daemon) GetPrefilterHandler {
	return &getPrefilter{d: d}
}

func (h *getPrefilter) Handle(params GetPrefilterParams) middleware.Responder {
	var list []string
	var revision int64
	if h.d.preFilter == nil {
		msg := fmt.Errorf("Prefilter is not enabled in daemon")
		return apierror.Error(GetPrefilterFailureCode, msg)
	}
	list, revision = h.d.preFilter.Dump(list)
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

type patchPrefilter struct {
	d *Daemon
}

// NewPatchPrefilterHandler returns new patch handler for api
func NewPatchPrefilterHandler(d *Daemon) PatchPrefilterHandler {
	return &patchPrefilter{d: d}
}

func (h *patchPrefilter) Handle(params PatchPrefilterParams) middleware.Responder {
	var list []net.IPNet
	spec := params.PrefilterSpec
	if h.d.preFilter == nil {
		msg := fmt.Errorf("Prefilter is not enabled in daemon")
		return apierror.Error(PatchPrefilterFailureCode, msg)
	}
	for _, cidrStr := range spec.Deny {
		_, cidr, err := net.ParseCIDR(cidrStr)
		if err != nil {
			msg := fmt.Errorf("Invalid CIDR string %s", cidrStr)
			return apierror.Error(PatchPrefilterInvalidCIDRCode, msg)
		}
		list = append(list, *cidr)
	}
	err := h.d.preFilter.Insert(spec.Revision, list)
	if err != nil {
		return apierror.Error(PatchPrefilterFailureCode, err)
	}
	return NewPatchPrefilterOK()
}
