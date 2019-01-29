// Copyright 2019 Authors of Cilium
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

package endpoint

import (
	"sort"

	"github.com/cilium/cilium/api/v1/models"
)

type orderEPModel func(e1, e2 *models.Endpoint) bool

// OrderEndpointModelAsc orders the slice of Endpoint in ascending ID order.
func OrderEndpointModelAsc(eps []*models.Endpoint) {
	ascPriority := func(e1, e2 *models.Endpoint) bool {
		return e1.ID < e2.ID
	}
	orderEPModel(ascPriority).sort(eps)
}

func (by orderEPModel) sort(eps []*models.Endpoint) {
	dS := &epModelSorter{
		eps: eps,
		by:  by,
	}
	sort.Sort(dS)
}

type epModelSorter struct {
	eps []*models.Endpoint
	by  func(e1, e2 *models.Endpoint) bool
}

func (epS *epModelSorter) Len() int {
	return len(epS.eps)
}

func (epS *epModelSorter) Swap(i, j int) {
	epS.eps[i], epS.eps[j] = epS.eps[j], epS.eps[i]
}

func (epS *epModelSorter) Less(i, j int) bool {
	return epS.by(epS.eps[i], epS.eps[j])
}
