// Copyright 2016-2017 Authors of Cilium
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

package container

import (
	"sync"

	dTypes "github.com/docker/engine-api/types"
)

type Container struct {
	// Mutex internal mutex for the whole container structure
	Mutex sync.RWMutex
	dTypes.ContainerJSON
}

// NewContainer a Container with its labels initialized.
func NewContainer(dc *dTypes.ContainerJSON) *Container {
	// FIXME should we calculate LabelsHash here?
	return &Container{
		ContainerJSON: *dc,
	}
}
