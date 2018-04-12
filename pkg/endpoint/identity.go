// Copyright 2016-2018 Authors of Cilium
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
	"fmt"
	"github.com/cilium/cilium/pkg/controller"
	"time"
)

func (e *Endpoint) identityResolutionIsObsolete(myChangeRev int) bool {
	// If in disconnected state, skip as well as this operation is no
	// longer required.
	if e.state == StateDisconnected {
		return true
	}

	// Check if the endpoint has since received a new identity revision, if
	// so, abort as a new resolution routine will have been started.
	if myChangeRev != e.identityRevision {
		return true
	}

	return false
}

func (e *Endpoint) runLabelsResolver(owner Owner, myChangeRev int) {
	ctrlName := fmt.Sprintf("resolve-identity-%d", e.ID)
	e.controllers.UpdateController(ctrlName,
		controller.ControllerParams{
			DoFunc: func() error {
				return e.identityLabelsChanged(owner, myChangeRev)
			},
			RunInterval: time.Duration(5) * time.Minute,
		},
	)
}
