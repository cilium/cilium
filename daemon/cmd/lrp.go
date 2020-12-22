// Copyright 2016-2020 Authors of Cilium
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

package cmd

import (
	"github.com/cilium/cilium/api/v1/models"
	. "github.com/cilium/cilium/api/v1/server/restapi/service"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/redirectpolicy"

	"github.com/go-openapi/runtime/middleware"
)

type getLRP struct {
	rpm *redirectpolicy.Manager
}

func NewGetLrpHandler(rpm *redirectpolicy.Manager) GetLrpHandler {
	return &getLRP{rpm: rpm}
}

func (h *getLRP) Handle(params GetLrpParams) middleware.Responder {
	log.WithField(logfields.Params, logfields.Repr(params)).Debug("GET /lrp request")
	return NewGetLrpOK().WithPayload(getLRPs(h.rpm))
}

func getLRPs(rpm *redirectpolicy.Manager) []*models.LRPSpec {
	lrps := rpm.GetLRPs()
	list := make([]*models.LRPSpec, 0, len(lrps))
	for _, v := range lrps {
		list = append(list, v.GetModel())
	}
	return list
}
