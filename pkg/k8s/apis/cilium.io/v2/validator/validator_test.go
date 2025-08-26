// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package validator

import (
	"encoding/json"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/yaml"
)

func Test_GH10643(t *testing.T) {
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
	require.NoError(t, err)

	us := unstructured.Unstructured{}
	err = json.Unmarshal(jsnByte, &us)
	require.NoError(t, err)

	validator, err := NewNPValidator(hivetest.Logger(t))
	require.NoError(t, err)
	err = validator.ValidateCNP(&us)
	// Err can't be nil since validation should detect the policy is not correct.
	require.Error(t, err)
}

func Test_BadMatchLabels(t *testing.T) {
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
	require.NoError(t, err)

	us := unstructured.Unstructured{}
	err = json.Unmarshal(jsnByte, &us)
	require.NoError(t, err)

	validator, err := NewNPValidator(hivetest.Logger(t))
	require.NoError(t, err)
	err = validator.ValidateCNP(&us)
	// Err can't be nil since validation should detect the policy is not correct.
	require.Error(t, err)
}

func Test_GoodCNP(t *testing.T) {
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
	require.NoError(t, err)

	us := unstructured.Unstructured{}
	err = json.Unmarshal(jsnByte, &us)
	require.NoError(t, err)

	validator, err := NewNPValidator(hivetest.Logger(t))
	require.NoError(t, err)
	err = validator.ValidateCNP(&us)
	require.NoError(t, err)
}

func Test_GoodCCNP(t *testing.T) {
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
	require.NoError(t, err)

	us := unstructured.Unstructured{}
	err = json.Unmarshal(jsnByte, &us)
	require.NoError(t, err)

	validator, err := NewNPValidator(hivetest.Logger(t))
	require.NoError(t, err)
	err = validator.ValidateCCNP(&us)
	require.NoError(t, err)
}

func Test_BadCCNP(t *testing.T) {
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
	require.NoError(t, err)

	us := unstructured.Unstructured{}
	err = json.Unmarshal(jsnByte, &us)
	require.NoError(t, err)

	validator, err := NewNPValidator(hivetest.Logger(t))
	require.NoError(t, err)
	err = validator.ValidateCCNP(&us)
	// Err can't be nil since validation should detect the policy is not correct.
	require.Error(t, err)
}

func Test_UnknownFieldDetection(t *testing.T) {
	tests := []struct {
		name        string
		policy      []byte
		clusterwide bool
		err         error
	}{
		{
			name: "ccnp GH-14526",
			policy: []byte(`
apiVersion: cilium.io/v2
kind: CiliumClusterwideNetworkPolicy
metadata:
  annotations:
    kubectl.kubernetes.io/last-applied-configuration: |
      {"apiVersion":"cilium.io/v2","kind":"CiliumClusterwideNetworkPolicy","metadata":{"annotations":{},"name":"ccnp-default-deny-egress"},"spec":{"egress":[{}],"endpointSelector":{}}}
  creationTimestamp: "2021-01-07T00:26:34Z"
  generation: 1
  managedFields:
  - apiVersion: cilium.io/v2
    fieldsType: FieldsV1
    fieldsV1:
      f:metadata:
        f:annotations:
          .: {}
          f:kubectl.kubernetes.io/last-applied-configuration: {}
      f:spec:
        .: {}
        f:egress: {}
        f:endpointSelector: {}
    manager: kubectl-client-side-apply
    operation: Update
    time: "2021-01-07T00:26:34Z"
  name: ccnp-default-deny-egress
  resourceVersion: "7849"
  selfLink: /apis/cilium.io/v2/ciliumclusterwidenetworkpolicies/ccnp-default-deny-egress
  uid: f776ca84-86dc-4589-ab91-64fccdec468a
spec:
  egress:
  - {}
  endpointSelector: {}
`),
			clusterwide: true,
			err:         nil,
		},
		{
			name: "cnp GH-14526",
			policy: []byte(`
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  annotations:
    kubectl.kubernetes.io/last-applied-configuration: |
      {"apiVersion":"cilium.io/v2","kind":"CiliumNetworkPolicy","metadata":{"annotations":{},"name":"ccnp-default-deny-egress"},"spec":{"egress":[{}],"endpointSelector":{}}}
  creationTimestamp: "2021-01-07T00:26:34Z"
  generation: 1
  managedFields:
  - apiVersion: cilium.io/v2
    fieldsType: FieldsV1
    fieldsV1:
      f:metadata:
        f:annotations:
          .: {}
          f:kubectl.kubernetes.io/last-applied-configuration: {}
      f:spec:
        .: {}
        f:egress: {}
        f:endpointSelector: {}
    manager: kubectl-client-side-apply
    operation: Update
    time: "2021-01-07T00:26:34Z"
  name: ccnp-default-deny-egress
  resourceVersion: "7849"
  selfLink: /apis/cilium.io/v2/ciliumnetworkpolicies/ccnp-default-deny-egress
  uid: f776ca84-86dc-4589-ab91-64fccdec468a
spec:
  egress:
  - {}
  endpointSelector: {}
`),
			clusterwide: false,
			err:         nil,
		},
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
  ingress: 
    - {}
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
  ingress: 
    - {}
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
  ingress: 
    - {}
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
  ingress: 
    - {}
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
  ingress: 
    - {}
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
  ingress: 
    - {}
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
		t.Log(tt.name)

		jsnByte, err := yaml.YAMLToJSON(tt.policy)
		require.NoError(t, err)

		us := unstructured.Unstructured{}
		err = json.Unmarshal(jsnByte, &us)
		require.NoError(t, err)

		validator, err := NewNPValidator(hivetest.Logger(t))
		require.NoError(t, err)

		if tt.clusterwide {
			require.Equal(t, tt.err, validator.ValidateCCNP(&us))
		} else {
			require.Equal(t, tt.err, validator.ValidateCNP(&us))
		}
	}
}

func Test_GH28007(t *testing.T) {
	cnp := []byte(`apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: exampleapp
  namespace: examplens
spec:
  egress:
  - toEntities:
    - world
  endpointSelector:
    matchExpressions:
    - key: reserved:init
      operator: DoesNotExist
`)
	jsnByte, err := yaml.YAMLToJSON(cnp)
	require.NoError(t, err)

	us := unstructured.Unstructured{}
	err = json.Unmarshal(jsnByte, &us)
	require.NoError(t, err)

	validator, err := NewNPValidator(hivetest.Logger(t))
	require.NoError(t, err)
	err = validator.ValidateCNP(&us)
	// Err can't be nil since validation should detect the policy is not correct.
	require.Equal(t, errInitPolicyCNP, err)
}
