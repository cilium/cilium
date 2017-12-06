package policygen

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"net"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/cilium/test/helpers"
	"github.com/onsi/ginkgo"
	"github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
)

// ConnTestSpec Connectivy Test Specification. This is a struct to use in
// PolicyTest to determine the result of the TestCase.
type ConnTestSpec struct {
	HTTP        ResultType
	HTTPPrivate ResultType
	Ping        ResultType
	UDP         ResultType
}

// GetField method to retrieve the value of any type of the struct.
// It is used by `TestSpec` to created expected results
func (conn *ConnTestSpec) GetField(field string) ResultType {
	r := reflect.ValueOf(conn)
	f := reflect.Indirect(r).FieldByName(field)
	return (f.Interface()).(ResultType)
}

// PolicyTest is utilized to decribe a new TestCase
// It needs a described name, the kind of the test (Egrees or Ingress) and the
// expected result of `ConnTestSpec`
// Template field is used to render the cilium network policy.
type PolicyTest struct {
	name     string
	kind     string //Egress/ingress
	tests    ConnTestSpec
	template map[string]string
}

// SetTemplate renders the template field from the PolicyTest struct using go
// templates. The result will be stored in the result parameter, the spec
// parameters is needed to retrieve the source and destination pods and pass
// the information to the go template.
func (pol *PolicyTest) SetTemplate(result *map[string]interface{}, spec *TestSpec) error {
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

// ResultType each connectivity test needs to have an expected result. This
// result is defined in ResultType. Some ResultTypes s are defined under
// policygen.const
type ResultType struct {
	kind    string // Timeout, reply
	success bool   // If the cmd exec is valid or not.
}

// String returns the the ResultType in humman readable format
func (res ResultType) String() string {
	return fmt.Sprintf("kind: %s sucess: %t", res.kind, res.success)
}

// PolicyTestSuite  helper struct to store all different policies types
type PolicyTestSuite struct {
	l3Checks []PolicyTest
	l4Checks []PolicyTest
	l7Checks []PolicyTest
}

// Target struct to define the destination that wee need to use for the
// testcase
type Target struct {
	Kind       string // serviceL3, serviceL4, NodePort, Direct
	PortNumber int
}

// SetPortNumber returns a non used host(Kubernetes node) port to set in the
// NodePort Service configuration.
func (t *Target) SetPortNumber() int {
	NodePortStart++
	t.PortNumber = NodePortStart
	return t.PortNumber
}

// GetTarget returns a `TargetDetails` struct with the IP and Port to  be able
// to execute the actions for the test spec. It needs the `TestSpec` parameter
// to be able to retrieve the service name. It'll return an error if the
// service is not defined or cannot be retrieved. This function only returns
// the first port mapped in the service, it'll not work with multiple ports.
func (t *Target) GetTarget(spec *TestSpec) (*TargetDetails, error) {

	switch t.Kind {
	case nodePort, service:
		host, port, err := spec.Kub.GetServiceHostPort(helpers.DefaultNamespace, t.GetServiceName(spec))
		if err != nil {
			return nil, err
		}
		return &TargetDetails{
			Port: port,
			IP:   host,
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
			IP:   vals[0],
		}, nil
	}
	return nil, fmt.Errorf("Not Implemented yet")
}

// GetServiceName returns an string with the service name using the spec
// parameter
func (t *Target) GetServiceName(spec *TestSpec) string {
	return fmt.Sprintf("%s-%s", strings.ToLower(t.Kind), spec.Prefix)
}

//GetManifestName returns the manifest filename for the target using the spec
//parameter
func (t *Target) GetManifestName(spec *TestSpec) string {
	return fmt.Sprintf("%s_%s_manifest.json", spec.Prefix, strings.ToLower(t.Kind))
}

// GetManifestPath returns the manifest path for the target using the spec
// parameter
func (t *Target) GetManifestPath(spec *TestSpec) string {
	return fmt.Sprintf("%s/%s", helpers.BasePath, t.GetManifestName(spec))
}

// CreateApplyManifest it creates the manifest for the type of the target and
// applied it in kubernetes. It will fail if the service manifest cannot be
// created correctly or applied to kubernetes
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
		service := `{
		"apiVersion": "v1",
		"kind": "Service",
		"metadata": {
			"name": "{{ .targetName }}"
		},
		"spec": {
			"ports": [
				{ "port": 80 }
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
		return nil
	}
	res := spec.Kub.Apply(manifestPath)
	if !res.WasSuccessful() {
		return fmt.Errorf("%s", res.CombineOutput())
	}
	return nil
}

// TargetDetails helper struct to store the IP and Port
type TargetDetails struct {
	Port int
	IP   string
}

// String combines host and port into a network address of the
// form "host:port" or, if host contains a colon or a percent sign,
// "[host]:port".
func (target TargetDetails) String() string {
	return net.JoinHostPort(target.IP, fmt.Sprintf("%d", target.Port))
}

// TestSpec struct is where a new test specification is defined. It contains
// three different rules (l3,l4,l7) and a destination and source pod in which
// test will run. Each testSpec has a prefix, that is a label that is used to
// group all resources created by the TestSpec. Each test is going to be
// executed using a type of Destination that is defined under Target struct.
// This struct needs a `*helpers.Kubectl` to run the needed commands
type TestSpec struct {
	l3          PolicyTest
	l4          PolicyTest
	l7          PolicyTest
	SrcPod      string
	DestPod     string
	Prefix      string
	Destination Target
	Kub         *helpers.Kubectl
}

// String: return the testSpec definition on human readable format
func (t TestSpec) String() string {
	return fmt.Sprintf("L3:%s L4:%s L7:%s Destination:%s",
		t.l3.name, t.l4.name, t.l7.name, t.Destination.Kind)
}

// RunTest is the method that runs all the `TestSpec` methods and makes the
// needed assertions for Ginkgo tests. This method will create pods manifest,
// wait for pods to be ready, apply a new cilium network policy and create a
// new Destination (Service, NodePort) if it's needed. When all of this happen
// it'll execute the `connectivityTest` and validated that it is the expected
// result.
func (t *TestSpec) RunTest(kub *helpers.Kubectl) {
	defer func() { go t.Destroy(destroyDelay) }()
	t.Kub = kub
	err := t.CreateManifests()
	gomega.Expect(err).To(gomega.BeNil(), "cannot create pods manifest for %s", t.Prefix)

	manifest, err := t.ApplyManifest()
	gomega.Expect(err).To(gomega.BeNil(), "cannot apply pods manifest for %s", t.Prefix)
	log.WithField("prefix", t.Prefix).Infof("Manifest '%s' is created correctly", manifest)

	err = t.NetworkPolicyApply()
	gomega.Expect(err).To(gomega.BeNil(), "cannot apply network policy for %s", t.Prefix)

	err = t.Destination.CreateApplyManifest(t)
	gomega.Expect(err).To(gomega.BeNil(), "cannot apply destination for %s", t.Prefix)

	err = t.ExecTest()
	gomega.Expect(err).To(gomega.BeNil(), "cannot execute test for %s", t.Prefix)
}

// Destroy will delete all the pods, cnp and Destinations that was created by
// `TestSpec`. It needs a delay parameter that means that it'll delete it after
// the specified time. (This is to keep the Nightly test under consider load)
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

// GetManifestName returns an string with the `TestSpec` manifest name
func (t *TestSpec) GetManifestName() string {
	return fmt.Sprintf("%s_manifest.yaml", t.Prefix)
}

// GetManifestsPath returns the `TestSpec` manifest path
func (t *TestSpec) GetManifestsPath() string {
	return fmt.Sprintf("%s/%s", helpers.BasePath, t.GetManifestName())
}

// CreateManifests creates a new pod manifest. It will set a random prefix for
// the `TestCase` and it creates two new pods (srcPod and DestPod). It will
// return an error in case that the manifest cannot be created.
func (t *TestSpec) CreateManifests() error {
	t.Prefix = helpers.MakeUID()
	t.SrcPod = fmt.Sprintf("%s-%s", t.Prefix, helpers.MakeUID())
	t.DestPod = fmt.Sprintf("%s-%s", t.Prefix, helpers.MakeUID())

	manifest := `
apiVersion: v1
kind: Pod
metadata:
  name: %[2]s
  labels:
    id: %[2]s
    zgroup: %[1]s
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
  name: %[3]s
  labels:
    id: %[3]s
    zgroup: %[1]s
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

// ApplyManifest applies a new deployment manifest into the kubernetes cluster.
// It'll return an error if the manifest cannot be applied correctly
func (t *TestSpec) ApplyManifest() (string, error) {
	err := t.CreateManifests()
	if err != nil {
		return "", err
	}
	res := t.Kub.Apply(t.GetManifestsPath())
	if !res.WasSuccessful() {
		return "", fmt.Errorf("%s", res.CombineOutput())
	}
	status, err := t.Kub.WaitforPods(helpers.DefaultNamespace, fmt.Sprintf("-l zgroup=%s", t.Prefix), 300)
	if err != nil || !status {
		return "", err
	}
	return t.GetManifestName(), nil
}

// GetPodMetadata returns a map with the pod name and the IP for the pods used
// by the `TestSpec`. It will return an error in case that the pod info cannot
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

// NetworkPolicyCreate returns a network policy based on the `TestSpec` l3,l4
// and l7 rules. It will return an error if any of the `PolicyTest` set
// Template fails or if spec cannot be dump as string
func (t *TestSpec) NetworkPolicyCreate() (string, error) {

	type rule map[string]interface{}

	type endpointSelector struct {
		Matchlabels map[string]string `json:"matchlabels"`
	}

	type Spec struct {
		EndpointSelector endpointSelector
		Ingress          []rule
		Egress           []rule
	}
	specs := []Spec{}
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
		specs = append(specs, Spec{
			EndpointSelector: endpointSelector{
				Matchlabels: map[string]string{
					"id": t.DestPod},
			},
			Ingress: []rule{ingressMap},
		})
	}

	if len(egressMap) > 0 {
		specs = append(specs, Spec{
			EndpointSelector: endpointSelector{
				Matchlabels: map[string]string{
					"id": t.SrcPod},
			},
			Egress: []rule{egressMap},
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

// NetworkPolicyApply applies the cilium network policy in kubernetes and wait
// until all  pods updates their status. It'll return an error if pods did not
// update the state or policy cannot be applied
func (t *TestSpec) NetworkPolicyApply() error {
	policy, err := t.NetworkPolicyCreate()
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

	_, err = t.Kub.CiliumImportPolicy(
		helpers.KubeSystemNamespace,
		fmt.Sprintf("%s/%s", helpers.BasePath, t.NetworkPolicyName()),
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

// GetConnectivyTest returns and array with the expected results of the given
// connectivy test kind
func (t *TestSpec) GetConnectivyTest(kind string) []connTestResultType {
	return []connTestResultType{
		connTestResultType{t.l3.kind, t.l3.tests.GetField(kind)},
		connTestResultType{t.l4.kind, t.l4.tests.GetField(kind)},
		connTestResultType{t.l7.kind, t.l7.tests.GetField(kind)}}
}

// GetTestExpects returns a map with the connTestType and the exepected result
// based on the `testExpect`
func (t *TestSpec) GetTestExpects() map[string]ResultType {
	DetermineStatus := func(testType string) ResultType {
		connTest := t.GetConnectivyTest(testType)

		//First check the egress rules that are the first rules that matchs
		for _, kind := range ConnTestsFailedResults {
			for _, test := range connTest {
				if test.kind == egress {
					if test.result == kind {
						return kind
					}
				}
			}
		}
		// If no resulttype for egress, we need to check if any specific
		// resultType on ingress
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
		result[connTestType] = DetermineStatus(connTestType)
	}

	return result
}

// ExecTest runs the connectivyTest for the expected `PolicyTest`. It will
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
		result := fn(t.SrcPod, target, t.Kub)
		gomega.Expect(result).To(gomega.Equal(&expectResult), testFailMessage(connType))
	}
	return nil
}
