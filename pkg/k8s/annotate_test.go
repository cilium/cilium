// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	. "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/annotation"
)

func (s *K8sSuite) TestPrepareRemoveNodeAnnotationsPayload(c *C) {
	tests := []struct {
		name       string
		annotation nodeAnnotation
		wantJson   string
	}{
		{
			name: "Test remove one annotation",
			annotation: nodeAnnotation{
				annotation.V4CIDRName: "cidr",
			},
			wantJson: "[{\"op\":\"remove\",\"path\":\"/metadata/annotations/network.cilium.io~1ipv4-pod-cidr\",\"value\":null}]",
		},
		{
			name:       "Test remove zero annotations",
			annotation: nodeAnnotation{},
			wantJson:   "[]",
		},
	}

	for _, tt := range tests {
		got, err := prepareRemoveNodeAnnotationsPayload(tt.annotation)
		c.Assert(err, IsNil)
		c.Assert(string(got), Equals, tt.wantJson, Commentf("Test Name: %s", tt.name))
	}
}
