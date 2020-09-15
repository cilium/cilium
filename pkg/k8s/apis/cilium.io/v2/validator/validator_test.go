// Copyright 2020 Authors of Cilium
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

// +build !privileged_tests

package validator

import (
	"encoding/json"
	"testing"

	"github.com/cilium/cilium/pkg/checker"

	. "gopkg.in/check.v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/yaml"
)

func Test(t *testing.T) {
	TestingT(t)
}

// Hook up gocheck into the "go test" runner.
type CNPValidationSuite struct {
}

var _ = Suite(&CNPValidationSuite{})

func (s *CNPValidationSuite) Test_GH10643(c *C) {
	cnp := []byte(`apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: exampleapp
  namespace: examplens
spec:
  egress:
  - toFQDNs:
    - matchPattern: prefix*.tier.location.example.com
    toPorts:
    - ports:
      - port "8050"
      - protocol TCP
      - port "8051"
      - protocol TCP
      - port "8052"
      - protocol TCP
      - port "8053"
      - protocol TCP
      - port "8054"
      - protocol TCP
      - port "8055"
      - protocol TCP
      - port "8056"
      - protocol TCP
      - port "8057"
      - protocol TCP
      - port "8058"
      - protocol TCP
      - port "8059"
      - protocol TCP
  endpointSelector:
    matchExpressions:
    - key: app
      operator: In
      values:
      - example-app-0-spark-worker
      - example-app-0-spark-driver
      - example-app-0-spark-worker-qe3
      - example-app-0-spark-driver-qe3
      - example-app-1-spark-worker
      - example-app-1-spark-driver
      - example-app-1-spark-worker-qe3
      - example-app-1-spark-driver-qe3
`)
	jsnByte, err := yaml.YAMLToJSON(cnp)
	c.Assert(err, IsNil)

	us := unstructured.Unstructured{}
	err = json.Unmarshal(jsnByte, &us)
	c.Assert(err, IsNil)

	validator, err := NewNPValidator()
	c.Assert(err, IsNil)
	err = validator.ValidateCNP(&us)
	// Err can't be nil since validation should detect the policy is not correct.
	c.Assert(err, Not(IsNil))
}

func (s *CNPValidationSuite) Test_BadMatchLabels(c *C) {
	cnp := []byte(`apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: cnp-test-1
  namespace: ns-2
spec:
  egress:
  - toServices:
    - k8sService:
        namespace: default
        serviceName: kubernetes
  endpointSelector:
    matchLabels:
      key: app
      operator: In
      values:
      - prometheus
      - kube-state-metrics
`)
	jsnByte, err := yaml.YAMLToJSON(cnp)
	c.Assert(err, IsNil)

	us := unstructured.Unstructured{}
	err = json.Unmarshal(jsnByte, &us)
	c.Assert(err, IsNil)

	validator, err := NewNPValidator()
	c.Assert(err, IsNil)
	err = validator.ValidateCNP(&us)
	// Err can't be nil since validation should detect the policy is not correct.
	c.Assert(err, Not(IsNil))
}

func (s *CNPValidationSuite) Test_GoodCNP(c *C) {
	cnp := []byte(`apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: cnp-test-1
  namespace: ns-2
spec:
  egress:
  - toServices:
    - k8sService:
        namespace: default
        serviceName: kubernetes
  endpointSelector:
    matchLabels:
      key: app
      operator: In
`)
	jsnByte, err := yaml.YAMLToJSON(cnp)
	c.Assert(err, IsNil)

	us := unstructured.Unstructured{}
	err = json.Unmarshal(jsnByte, &us)
	c.Assert(err, IsNil)

	validator, err := NewNPValidator()
	c.Assert(err, IsNil)
	err = validator.ValidateCNP(&us)
	c.Assert(err, IsNil)
}

func (s *CNPValidationSuite) Test_GoodCCNP(c *C) {
	ccnp := []byte(`apiVersion: cilium.io/v2
kind: CiliumClusterwideNetworkPolicy
metadata:
  name: cnp-test-1
spec:
  egress:
  - toServices:
    - k8sService:
        namespace: default
        serviceName: kubernetes
  endpointSelector:
    matchLabels:
      key: app
      operator: In
`)
	jsnByte, err := yaml.YAMLToJSON(ccnp)
	c.Assert(err, IsNil)

	us := unstructured.Unstructured{}
	err = json.Unmarshal(jsnByte, &us)
	c.Assert(err, IsNil)

	validator, err := NewNPValidator()
	c.Assert(err, IsNil)
	err = validator.ValidateCCNP(&us)
	c.Assert(err, IsNil)
}

func (s *CNPValidationSuite) Test_BadCCNP(c *C) {
	// Bad CCNP with endpointSelector and nodeSelector
	ccnp := []byte(`apiVersion: cilium.io/v2
kind: CiliumClusterwideNetworkPolicy
metadata:
  name: cnp-test-1
spec:
  egress:
  - toServices:
    - k8sService:
        namespace: default
        serviceName: kubernetes
  endpointSelector:
    matchLabels:
      key: app
      operator: In
  nodeSelector:
    matchLabels:
      key: app
      operator: In
`)
	jsnByte, err := yaml.YAMLToJSON(ccnp)
	c.Assert(err, IsNil)

	us := unstructured.Unstructured{}
	err = json.Unmarshal(jsnByte, &us)
	c.Assert(err, IsNil)

	validator, err := NewNPValidator()
	c.Assert(err, IsNil)
	err = validator.ValidateCCNP(&us)
	// Err can't be nil since validation should detect the policy is not correct.
	c.Assert(err, Not(IsNil))
}

func (s *CNPValidationSuite) Test_UnknownFieldDetection(c *C) {
	tests := []struct {
		name        string
		policy      []byte
		clusterwide bool
		err         error
	}{
		{
			name: "neither a cnp or ccnp",
			policy: []byte(`
kind: ServiceAccount
apiVersion: v1
metadata:
  name: app1-account
`),
			clusterwide: false,
			err: ErrUnknownKind{
				kind: "ServiceAccount",
			},
		},

		{
			name: "cnp top-level description exists",
			policy: []byte(`
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
description: "default deny policy"
metadata:
  name: cnp-test-1
spec:
  endpointSelector: {}
`),
			clusterwide: false,
			err:         ErrTopLevelDescriptionFound,
		},
		{
			name: "cnp top-level description does not exist",
			policy: []byte(`
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: cnp-test-1
spec:
  endpointSelector: {}
`),
			clusterwide: false,
			err:         nil,
		},
		{
			name: "ccnp top-level description exists",
			policy: []byte(`
apiVersion: cilium.io/v2
kind: CiliumClusterwideNetworkPolicy
description: "default deny policy"
metadata:
  name: ccnp-test-1
spec:
  nodeSelector: {}
`),
			clusterwide: true,
			err:         ErrTopLevelDescriptionFound,
		},
		{
			name: "ccnp top-level description does not exist",
			policy: []byte(`
apiVersion: cilium.io/v2
kind: CiliumClusterwideNetworkPolicy
metadata:
  name: ccnp-test-1
spec:
  nodeSelector: {}
`),
			clusterwide: true,
			err:         nil,
		},

		{
			name: "cnp extra unknown fields",
			policy: []byte(`
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
foo: bar
metadata:
  name: ccnp-test-1
spec:
  endpointSelector: {}
  bar: baz
`),
			clusterwide: false,
			err: ErrUnknownFields{
				extras: []string{"foo", "spec.bar"},
			},
		},
		{
			name: "ccnp extra unknown fields",
			policy: []byte(`
apiVersion: cilium.io/v2
kind: CiliumClusterwideNetworkPolicy
foo: bar
metadata:
  name: ccnp-test-1
spec:
  nodeSelector: {}
  bar: baz
`),
			clusterwide: true,
			err: ErrUnknownFields{
				extras: []string{"foo", "spec.bar"},
			},
		},
		{
			name: "cnp specs",
			policy: []byte(`
apiVersion: "cilium.io/v2"
kind: CiliumNetworkPolicy
metadata:
  name: "cnp-specs"
specs:
  - description: "Policy to test multiple rules in a single file"
    endpointSelector:
      matchLabels:
        app: ratings
        version: v1
    ingress:
    - fromEndpoints:
      - matchLabels:
          app: reviews
          track: stable
          version: v1
      toPorts:
      - ports:
        - port: "9080"
          protocol: TCP
        rules:
          http:
          - method: "GET"
            path: "/health"
  - endpointSelector:
      matchLabels:
        app: details
        track: stable
        version: v1
    ingress:
    - fromEndpoints:
      - matchLabels:
          app: productpage
          track: stable
          version: v1
      toPorts:
      - ports:
        - port: "9080"
          protocol: TCP
        rules:
          http:
          - method: "GET"
            path: "/.*"
`),
			clusterwide: false,
			err:         nil,
		},
	}
	for _, tt := range tests {
		c.Log(tt.name)

		jsnByte, err := yaml.YAMLToJSON(tt.policy)
		c.Assert(err, IsNil)

		us := unstructured.Unstructured{}
		err = json.Unmarshal(jsnByte, &us)
		c.Assert(err, IsNil)

		validator, err := NewNPValidator()
		c.Assert(err, IsNil)

		if tt.clusterwide {
			c.Assert(validator.ValidateCCNP(&us), checker.DeepEquals, tt.err)
		} else {
			c.Assert(validator.ValidateCNP(&us), checker.DeepEquals, tt.err)
		}
	}
}
