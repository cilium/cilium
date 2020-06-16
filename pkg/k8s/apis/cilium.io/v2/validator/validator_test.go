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
      - protocl TCP
      - port "8051"
      - protocl TCP
      - port "8052"
      - protocl TCP
      - port "8053"
      - protocl TCP
      - port "8054"
      - protocl TCP
      - port "8055"
      - protocl TCP
      - port "8056"
      - protocl TCP
      - port "8057"
      - protocl TCP
      - port "8058"
      - protocl TCP
      - port "8059"
      - protocl TCP
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
