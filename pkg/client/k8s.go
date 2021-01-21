// Copyright 2021 Authors of Cilium
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

package client

import (
	"io"

	"github.com/cilium/cilium/api/v1/client/k8s"
	"github.com/cilium/cilium/pkg/api"
)

// CRDPut registers a CRD into the K8s apiserver.
func (c *Client) CRDPut(crd io.ReadCloser) error {
	params := k8s.NewPutCrdParams().WithCrd(crd).WithTimeout(api.ClientTimeout)
	if _, err := c.K8s.PutCrd(params); err != nil {
		return Hint(err)
	}
	return nil
}
