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

package policygen

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/cilium/pkg/policy/api/v2"
	"github.com/cilium/cilium/test/helpers"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/onsi/ginkgo"
	"github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
)

// ConnTestSpec Connectivity Test Specification. This structs contains the
// mapping of all protocols tested and the expected result based on the context
// of each test case
type ConnTestSpec struct {
	HTTP        ResultType
	HTTPPrivate ResultType
	Ping        ResultType
	UDP         ResultType
}

// GetField method to retrieve the value of any type of the struct.
// It is used by `TestSpec` to created expected results
func (conn *ConnTestSpec) GetField(field string) ResultType {
	switch field {
	case HTTP:
		return conn.HTTP
	case HTTPPrivate:
		return conn.HTTPPrivate
	case Ping:
		return conn.Ping
	case UDP:
		return conn.UDP
	}
	return ResultType{}
}

// PolicyTestKind is utilized to decribe a new TestCase
// It needs a described name, the kind of the test (Egrees or Ingress) and the
// expected result of `ConnTestSpec`
// Template field is used to render the cilium network policy.
type PolicyTestKind struct {
	name     string
	kind     string //Egress/ingress
	tests    ConnTestSpec
	template map[string]string
}

// SetTemplate renders the template field from the PolicyTest struct using go
// templates. The result will be stored in the result parameter. The spec
// parameters is needed to retrieve the source and destination pods and pass
// the information to the go template.
func (pol *PolicyTestKind) SetTemplate(result *map[string]interface{}, spec *TestSpec) error {
	getTemplate := func(tmpl string) (*bytes.Buffer, error) {
		t, err := template.New("").Parse(tmpl)
		if err != nil {
			return nil, err
		}
		content := new(bytes.Buffer)
		err = t.Execute(content, spec)
		if err != nil {
			return nil, err
		}
		return content, nil
	}

	for k, v := range pol.template {
		// If any key was already set we do not need to overwrite it.
		// This is in use on L7 when a port is always needed
		if _, ok := (*result)[k]; ok {
			continue
		}
		tmpl, err := getTemplate(v)
		if err != nil {
			return err
		}
		var data interface{}
		err = json.Unmarshal(tmpl.Bytes(), &data)
		if err != nil {
			return err
		}
		(*result)[k] = data
	}
	return nil
}

// ResultType defines the expected result for a connectivity test.
type ResultType struct {
	kind    string // Timeout, reply
	success bool   // If the cmd exec is valid or not.
}

// String returns the ResultType in humman readable format
func (res ResultType) String() string {
	return fmt.Sprintf("kind: %s sucess: %t", res.kind, res.success)
}

// PolicyTestSuite groups together L3, L4, and L7 policy-related tests.
type PolicyTestSuite struct {
	l3Checks []PolicyTestKind
	l4Checks []PolicyTestKind
	l7Checks []PolicyTestKind
}

// Target defines the destination for traffic when running tests
type Target struct {
	Kind       string // serviceL3, serviceL4, NodePort, Direct
	PortNumber int
}

// SetPortNumber returns an unused port on the host to use in a Kubernetes
// NodePort service
func (t *Target) SetPortNumber() int {
	NodePortStart++
	t.PortNumber = NodePortStart
	return t.PortNumber
}

// GetTarget returns a `TargetDetails`  with the IP and Port to run the tests
// in spec. It needs the `TestSpec` parameter to be able to retrieve the
// service name. It'll return an error if the service is not defined or cannot
// be retrieved. This function only returns the first port mapped in the
// service;  It'll not work with multiple ports.
func (t *Target) GetTarget(spec *TestSpec) (*TargetDetails, error) {

	switch t.Kind {
	case nodePort, service:
		host, port, err := spec.Kub.GetServiceHostPort(helpers.DefaultNamespace, t.GetServiceName(spec))
		if err != nil {
			return nil, err
		}
		return &TargetDetails{
			Port: port,
			IP:   []byte(host),
		}, nil
	case direct:
		filter := `{.status.podIP}{"="}{.spec.containers[0].ports[0].containerPort}`
		res, err := spec.Kub.Get(helpers.DefaultNamespace, fmt.Sprintf("pod %s", spec.DestPod)).Filter(filter)
		if err != nil {
			return nil, fmt.Errorf("cannot get pod '%s' info: %s", spec.DestPod, err)
		}
		vals := strings.Split(res.String(), "=")
		port, err := strconv.Atoi(vals[1])
		if err != nil {
			return nil, fmt.Errorf("cannot get pod '%s' port: %s", spec.DestPod, err)
		}
		return &TargetDetails{
			Port: port,
			IP:   []byte(vals[0]),
		}, nil
	}
	return nil, fmt.Errorf("%s not Implemented yet", t.Kind)
}

// GetServiceName returns the prefix of spec prefixed with the kind of the the
// target
func (t *Target) GetServiceName(spec *TestSpec) string {
	return fmt.Sprintf("%s-%s", strings.ToLower(t.Kind), spec.Prefix)
}

// GetManifestName returns the manifest filename for the target using the spec
// parameter
func (t *Target) GetManifestName(spec *TestSpec) string {
	return fmt.Sprintf("%s_%s_manifest.json", spec.Prefix, strings.ToLower(t.Kind))
}

// GetManifestPath returns the manifest path for the target using the spec
// parameter
func (t *Target) GetManifestPath(spec *TestSpec) string {
	return fmt.Sprintf("%s/%s", helpers.BasePath, t.GetManifestName(spec))
}

// CreateApplyManifest creates the manifest for the type of the target and
// applies it in kubernetes. It will fail if the service manifest cannot be
// created correctly or applied to Kubernetes
func (t *Target) CreateApplyManifest(spec *TestSpec) error {
	manifestPath := t.GetManifestPath(spec)
	getTemplate := func(tmpl string) (*bytes.Buffer, error) {
		metadata := map[string]interface{}{
			"spec":       spec,
			"target":     t,
			"targetName": t.GetServiceName(spec),
		}
		t, err := template.New("").Parse(tmpl)
		if err != nil {
			return nil, err
		}
		content := new(bytes.Buffer)
		err = t.Execute(content, metadata)
		if err != nil {
			return nil, err
		}
		return content, nil
	}

	switch t.Kind {
	case service:
		// As default services are listen on port 80.
		t.PortNumber = 80
		service := `{
		"apiVersion": "v1",
		"kind": "Service",
		"metadata": {
			"name": "{{ .targetName }}"
		},
		"spec": {
			"ports": [
				{ "port": {{ .target.PortNumber }} }
			],
			"selector": {
				"id": "{{ .spec.DestPod }}"
			}
		}}`
		data, err := getTemplate(service)
		if err != nil {
			return fmt.Errorf("cannot render template: %s", err)
		}
		err = helpers.RenderTemplateToFile(t.GetManifestName(spec), data.String(), os.ModePerm)
		if err != nil {
			return err
		}
	case nodePort:
		t.SetPortNumber()
		nodePort := `
		{
		  "apiVersion": "v1",
		  "kind": "Service",
		  "metadata": {
			"name": "{{ .targetName }}"
		  },
		  "spec": {
			"type": "NodePort",
			"ports": [
			  {
				"targetPort": 80,
				"port": {{ .target.PortNumber }},
				"protocol": "TCP"
			  }
			],
			"selector": {
			  "id": "{{ .spec.DestPod }}"
			}
		  }
		}`

		data, err := getTemplate(nodePort)
		if err != nil {
			return fmt.Errorf("cannot render template: %s", err)
		}

		err = helpers.RenderTemplateToFile(t.GetManifestName(spec), data.String(), os.ModePerm)
		if err != nil {
			return err
		}
	case direct:
		t.PortNumber = 80
		return nil
	}
	res := spec.Kub.Apply(manifestPath)
	if !res.WasSuccessful() {
		return fmt.Errorf("%s", res.CombineOutput())
	}
	return nil
}

// TargetDetails represents the address of a TCP end point.
type TargetDetails net.TCPAddr

// String combines host and port into a network address of the
// form "host:port" or, if host contains a colon or a percent sign,
// "[host]:port".
func (target TargetDetails) String() string {
	return net.JoinHostPort(string(target.IP), fmt.Sprintf("%d", target.Port))
}

// TestSpec defined a new test specification. It contains three different rules
// (l3, l4, l7) and a destination and source pod in which test will run. Each
// testSpec has a prefix, which is a label used to group all resources created
// by the TestSpec. Each test is  executed using a type of Destination which is
// defined under Target struct.  This struct needs a `*helpers.Kubectl` to run
// the needed commands
type TestSpec struct {
	l3          PolicyTestKind
	l4          PolicyTestKind
	l7          PolicyTestKind
	SrcPod      string
	DestPod     string
	Prefix      string
	Destination Target
	Kub         *helpers.Kubectl
}

// String return the testSpec definition on human-readable format
func (t TestSpec) String() string {
	return fmt.Sprintf("L3:%s L4:%s L7:%s Destination:%s",
		t.l3.name, t.l4.name, t.l7.name, t.Destination.Kind)
}

// RunTest runs all the `TestSpec` methods and makes the needed assertions for
// Ginkgo tests. This method will create pods, wait for pods to be ready, apply
// a new CiliumNetworkPolicy and create a new Destination (Service, NodePort)
// if needed. Then it will execute `connectivityTest` and compare the results
// with the expected results within the test specification
func (t *TestSpec) RunTest(kub *helpers.Kubectl) {
	defer func() { go t.Destroy(destroyDelay) }()
	t.Kub = kub
	err := t.CreateManifests()
	gomega.Expect(err).To(gomega.BeNil(), "cannot create pods manifest for %s", t.Prefix)

	manifest, err := t.ApplyManifest()
	gomega.Expect(err).To(gomega.BeNil(), "cannot apply pods manifest for %s", t.Prefix)
	log.WithField("prefix", t.Prefix).Infof("Manifest '%s' is created correctly", manifest)

	err = t.Destination.CreateApplyManifest(t)
	gomega.Expect(err).To(gomega.BeNil(), "cannot apply destination for %s", t.Prefix)

	err = t.NetworkPolicyApply()
	gomega.Expect(err).To(gomega.BeNil(), "cannot apply network policy for %s", t.Prefix)

	err = t.ExecTest()
	gomega.Expect(err).To(gomega.BeNil(), "cannot execute test for %s", t.Prefix)
}

// Destroy deletes the pods, CiliumNetworkPolicies and Destinations created by
// `TestSpec` after specified delay. The delay parameter is used to have the
// pod running for a while and keep Cilium and Kubernetes with a consider load.
func (t *TestSpec) Destroy(delay time.Duration) error {
	manifestToDestroy := []string{
		t.GetManifestsPath(),
		fmt.Sprintf("%s/%s", helpers.BasePath, t.NetworkPolicyName()),
		fmt.Sprintf("%s", t.Destination.GetManifestPath(t)),
	}

	done := time.After(delay)

	for {
		select {
		case <-done:
			for _, manifest := range manifestToDestroy {
				t.Kub.Delete(manifest)
			}
		}
	}
}

// GetManifestName returns a string with the `TestSpec` manifest name
func (t *TestSpec) GetManifestName() string {
	return fmt.Sprintf("%s_manifest.yaml", t.Prefix)
}

// GetManifestsPath returns the `TestSpec` manifest path
func (t *TestSpec) GetManifestsPath() string {
	return fmt.Sprintf("%s/%s", helpers.BasePath, t.GetManifestName())
}

// CreateManifests creates a new pod manifest. It sets a random prefix for the
// `TestCase` and creates two new pods (srcPod and DestPod). Returns an error
// if the manifest cannot be created
func (t *TestSpec) CreateManifests() error {
	t.Prefix = helpers.MakeUID()
	t.SrcPod = fmt.Sprintf("%s-%s", t.Prefix, helpers.MakeUID())
	t.DestPod = fmt.Sprintf("%s-%s", t.Prefix, helpers.MakeUID())

	manifest := `
---
apiVersion: v1
kind: Pod
metadata:
  name: "%[2]s"
  labels:
    id: "%[2]s"
    zgroup: "%[1]s"
spec:
  containers:
  - name: app-frontend
    image: byrnedo/alpine-curl
    command: [ "sleep" ]
    args:
      - "1000h"
---
apiVersion: v1
kind: Pod
metadata:
  name: "%[3]s"
  labels:
    id: "%[3]s"
    zgroup: "%[1]s"
spec:
  containers:
  - name: web
    image: cilium/demo-httpd
    ports:
      - containerPort: 80`

	err := helpers.RenderTemplateToFile(
		t.GetManifestName(),
		fmt.Sprintf(manifest, t.Prefix, t.SrcPod, t.DestPod),
		os.ModePerm)
	if err != nil {
		return err
	}
	return nil
}

// ApplyManifest applies a new deployment manifest into the Kubernetes cluster.
// Returns an error if the manifest cannot be applied correctly
func (t *TestSpec) ApplyManifest() (string, error) {
	err := t.CreateManifests()
	if err != nil {
		return "", err
	}
	res := t.Kub.Apply(t.GetManifestsPath())
	if !res.WasSuccessful() {
		return "", fmt.Errorf("%s", res.CombineOutput())
	}
	status, err := t.Kub.WaitforPods(
		helpers.DefaultNamespace,
		fmt.Sprintf("-l zgroup=%s", t.Prefix),
		600)
	if err != nil || !status {
		return "", err
	}
	return t.GetManifestName(), nil
}

// GetPodMetadata returns a map with the pod name and the IP for the pods used
// by the `TestSpec`. Returns an error in case that the pod info cannot
// be retrieved correctly.
func (t *TestSpec) GetPodMetadata() (map[string]string, error) {
	result := make(map[string]string)
	filter := `{range .items[*]}{@.metadata.name}{"="}{@.status.podIP}{"\n"}{end}`

	res := t.Kub.Get(helpers.DefaultNamespace, fmt.Sprintf("pods -l zgroup=%s", t.Prefix))
	data, err := res.Filter(filter)
	if err != nil {
		return nil, err
	}

	for _, line := range strings.Split(data.String(), "\n") {
		vals := strings.Split(line, "=")
		if len(vals) == 2 {
			result[vals[0]] = vals[1]
		}
	}
	return result, nil
}

// CreateCiliumNetworkPolicy returns a CiliumNetworkPolicy based on the
// `TestSpec` l3, l4 and l7 rules. Returns an error if any of the `PolicyTest`
// set Template fails or if spec cannot be dump as string
func (t *TestSpec) CreateCiliumNetworkPolicy() (string, error) {

	type rule map[string]interface{}

	specs := []v2.Rule{}
	var err error

	ingressMap := map[string]interface{}{}
	l4ingress := map[string]interface{}{}
	egressMap := map[string]interface{}{}
	l4egress := map[string]interface{}{}

	metadata := []byte(`
	{
	  "apiVersion": "cilium.io/v2",
	  "kind": "CiliumNetworkPolicy",
	  "metadata": {
		"name": "%[1]s",
		"test": "%[3]s"
	  },
	  "specs": %[2]s}`)

	//Create template
	switch kind := t.l3.kind; kind {
	case ingress:
		err = t.l3.SetTemplate(&ingressMap, t)
	case egress:
		err = t.l3.SetTemplate(&egressMap, t)
	}

	if err != nil {
		return "", err
	}

	switch kind := t.l4.kind; kind {
	case ingress:
		err = t.l4.SetTemplate(&l4ingress, t)
	case egress:
		err = t.l4.SetTemplate(&l4egress, t)
	}

	if err != nil {
		return "", err
	}

	switch kind := t.l7.kind; kind {
	case ingress:
		err = t.l7.SetTemplate(&l4ingress, t)
	case egress:
		err = t.l7.SetTemplate(&l4egress, t)
	}

	if err != nil {
		return "", err
	}

	if len(l4ingress) > 0 {
		ingressMap[toPorts] = []rule{l4ingress}
	}

	if len(l4egress) > 0 {
		egressMap[toPorts] = []rule{l4egress}
	}

	if len(ingressMap) > 0 {
		var ingressVal v2.IngressRule
		jsonOut, err := json.Marshal(ingressMap)
		if err != nil {
			return "", err
		}
		err = json.Unmarshal(jsonOut, &ingressVal)
		if err != nil {
			return "", err
		}
		specs = append(specs, v2.Rule{
			EndpointSelector: v2.EndpointSelector{
				LabelSelector: &metav1.LabelSelector{MatchLabels: map[string]string{
					"id": t.DestPod,
				}},
			},
			Ingress: []v2.IngressRule{ingressVal},
			Egress:  []v2.EgressRule{},
		})
	}

	if len(egressMap) > 0 {
		var egressVal v2.EgressRule
		jsonOut, err := json.Marshal(egressMap)
		if err != nil {
			return "", err
		}
		err = json.Unmarshal(jsonOut, &egressVal)
		if err != nil {
			return "", err
		}

		specs = append(specs, v2.Rule{
			EndpointSelector: v2.EndpointSelector{
				LabelSelector: &metav1.LabelSelector{MatchLabels: map[string]string{
					"id": t.SrcPod,
				}},
			},
			Ingress: []v2.IngressRule{},
			Egress:  []v2.EgressRule{egressVal},
		})
	}

	if len(specs) == 0 {
		return "", nil
	}

	jsonOutput, err := json.Marshal(specs)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf(string(metadata), t.Prefix, jsonOutput, t), nil
}

// NetworkPolicyName returns the name of the NetworkPolicy
func (t *TestSpec) NetworkPolicyName() string {
	return fmt.Sprintf("%s_policy.json", t.Prefix)
}

// NetworkPolicyApply applies the CiliumNetworkPolicy in Kubernetes and wait
// until the statuses of all pods have been updated. Returns an error if the
// status of the pods did not update or if the policy was unable to be applied
func (t *TestSpec) NetworkPolicyApply() error {
	policy, err := t.CreateCiliumNetworkPolicy()
	if err != nil {
		return fmt.Errorf("Network policy cannot be created prefix=%s: %s", t.Prefix, err)
	}

	if policy == "" {
		//This only happens on L3:No Policy L4:No Policy L7:No Policy
		log.Info("No policy so do not import it")
		return nil
	}

	err = ioutil.WriteFile(t.NetworkPolicyName(), []byte(policy), os.ModePerm)
	if err != nil {
		return fmt.Errorf("Network policy cannot be written prefix=%s: %s", t.Prefix, err)
	}

	_, err = t.Kub.CiliumPolicyAction(
		helpers.KubeSystemNamespace,
		fmt.Sprintf("%s/%s", helpers.BasePath, t.NetworkPolicyName()),
		helpers.KubectlApply,
		helpers.HelperTimeout)

	if err != nil {
		return fmt.Errorf("Network policy cannot be imported prefix=%s: %s", t.Prefix, err)
	}
	return nil
}

type connTestResultType struct {
	kind   string
	result ResultType
}

// getConnectivityTest returns an array with the expected results of the given
// connectivity test kind
func (t *TestSpec) getConnectivityTest(kind string) []connTestResultType {
	return []connTestResultType{
		{t.l3.kind, t.l3.tests.GetField(kind)},
		{t.l4.kind, t.l4.tests.GetField(kind)},
		{t.l7.kind, t.l7.tests.GetField(kind)}}
}

// GetTestExpects returns a map with the connTestType and the expected result
// based on the `testExpect`
func (t *TestSpec) GetTestExpects() map[string]ResultType {
	expectedTestResult := func(testType string) ResultType {
		connTest := t.getConnectivityTest(testType)

		//First check the egress rules that are the first rules that match
		for _, kind := range ConnTestsFailedResults {
			for _, test := range connTest {
				if test.kind == egress {
					if test.result == kind {
						return kind
					}
				}
			}
		}
		// If no ResultType for egress, we need to check if any specific
		// ResultType on ingress
		for _, kind := range ConnTestsFailedResults {
			for _, test := range connTest {
				if test.kind == ingress {
					if test.result == kind {
						return kind
					}
				}
			}
		}
		return ResultOK
	}

	result := map[string]ResultType{}
	for _, connTestType := range ConnTests {
		result[connTestType] = expectedTestResult(connTestType)
	}

	return result
}

// ExecTest runs the connectivityTest for the expected `PolicyTest`. It will
// assert using gomega.
func (t *TestSpec) ExecTest() error {
	testFailMessage := func(kind string) string {
		return fmt.Sprintf("Type %s from %s to %s did not work", kind, t.SrcPod, t.DestPod)
	}
	for connType, expectResult := range t.GetTestExpects() {
		if connType == Ping && (t.Destination.Kind == service || t.Destination.Kind == nodePort) {
			continue
		}
		ginkgo.By(fmt.Sprintf("Checking %s", connType))
		fn := ConnTestsActions[connType]
		target, err := t.Destination.GetTarget(t)
		if err != nil {
			return fmt.Errorf("cannot get target in '%s': %s", t.Prefix, err)
		}
		result := fn(t.SrcPod, *target, t.Kub)
		gomega.Expect(result).To(gomega.Equal(expectResult), testFailMessage(connType))
	}
	return nil
}

// TestSpecsGroup is a group of different TestSpec
type TestSpecsGroup []*TestSpec

// CreateAndApplyManifests creates all of the pods manifests and applies those
// manifest to the given kubernetes instance.
func (tg TestSpecsGroup) CreateAndApplyManifests(kub *helpers.Kubectl) {
	completeManifest := "/tmp/data.yaml"
	manifests := []string{}
	for _, test := range tg {
		test.CreateManifests()
		manifests = append(manifests, test.GetManifestsPath())
	}
	res := kub.Exec(fmt.Sprintf("cat %s > %s", strings.Join(manifests, " "), completeManifest))
	res.ExpectSuccess()

	res = kub.Exec(fmt.Sprintf("%s apply -f %s", helpers.KubectlCmd, completeManifest))
	res.ExpectSuccess()
}

// CreateAndApplyCNP creates all Cilium Network Policies and it applies those
// manifests to the given Kubernetes instance.
func (tg TestSpecsGroup) CreateAndApplyCNP(kub *helpers.Kubectl) {
	for _, test := range tg {
		// TODO: Should be any better way to do this
		test.Kub = kub
		err := test.NetworkPolicyApply()
		gomega.ExpectWithOffset(1, err).To(gomega.BeNil())
	}
}

// ConnectivityTest runs the Connectivity test per each TestSpec defined into
// the TestSpecsGroup
func (tg TestSpecsGroup) ConnectivityTest() {
	for _, test := range tg {
		err := test.Destination.CreateApplyManifest(test)
		gomega.ExpectWithOffset(1, err).To(gomega.BeNil(), "cannot apply destination for %s", test.Prefix)

		err = test.ExecTest()
		gomega.ExpectWithOffset(1, err).To(gomega.BeNil(), "cannot execute test for %s", test.Prefix)
	}
}
