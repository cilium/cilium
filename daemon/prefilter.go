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
	cl := &models.CIDRList{
		Revision: revision,
		List:     list,
	}
	return NewGetPrefilterOK().WithPayload(cl)
}

type putPrefilter struct {
	d *Daemon
}

// NewPutPrefilterHandler returns new put handler for api
func NewPutPrefilterHandler(d *Daemon) PutPrefilterHandler {
	return &putPrefilter{d: d}
}

func (h *putPrefilter) Handle(params PutPrefilterParams) middleware.Responder {
	var list []net.IPNet
	cl := params.CidrList
	if h.d.preFilter == nil {
		msg := fmt.Errorf("Prefilter is not enabled in daemon")
		return apierror.Error(PutPrefilterFailureCode, msg)
	}
	for _, cidrStr := range cl.List {
		_, cidr, err := net.ParseCIDR(cidrStr)
		if err != nil {
			msg := fmt.Errorf("Invalid CIDR string %s", cidrStr)
			return apierror.Error(PutPrefilterInvalidCIDRCode, msg)
		}
		list = append(list, *cidr)
	}
	err := h.d.preFilter.Insert(cl.Revision, list)
	if err != nil {
		return apierror.Error(PutPrefilterFailureCode, err)
	}
	return NewPutPrefilterOK()
}

type deletePrefilter struct {
	d *Daemon
}

// NewDeletePrefilterHandler returns new delete handler for api
func NewDeletePrefilterHandler(d *Daemon) DeletePrefilterHandler {
	return &deletePrefilter{d: d}
}

func (h *deletePrefilter) Handle(params DeletePrefilterParams) middleware.Responder {
	var list []net.IPNet
	cl := params.CidrList
	if h.d.preFilter == nil {
		msg := fmt.Errorf("Prefilter is not enabled in daemon")
		return apierror.Error(DeletePrefilterFailureCode, msg)
	}
	for _, cidrStr := range cl.List {
		_, cidr, err := net.ParseCIDR(cidrStr)
		if err != nil {
			msg := fmt.Errorf("Invalid CIDR string %s", cidrStr)
			return apierror.Error(DeletePrefilterInvalidCIDRCode, msg)
		}
		list = append(list, *cidr)
	}
	err := h.d.preFilter.Delete(cl.Revision, list)
	if err != nil {
		return apierror.Error(DeletePrefilterFailureCode, err)
	}
	return NewDeletePrefilterOK()
}
