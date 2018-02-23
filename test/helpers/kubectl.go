// Copyright 2018 Authors of Cilium
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

package helpers

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/annotation"

	"github.com/asaskevich/govalidator"
	"github.com/onsi/ginkgo"
	"github.com/sirupsen/logrus"
	"k8s.io/api/core/v1"
)

const (
	KubectlCmd    = "kubectl"
	manifestsPath = "k8sT/manifests/"
	kubeDNSLabel  = "k8s-app=kube-dns"
)

// GetCurrentK8SEnv returns the value of K8S_VERSION from the OS environment.
func GetCurrentK8SEnv() string { return os.Getenv("K8S_VERSION") }

// Kubectl is a wrapper around an SSHMeta. It is used to run Kubernetes-specific
// commands on the node which is accessible via the SSH metadata stored in its
// SSHMeta.
type Kubectl struct {
	*SSHMeta
}

// CreateKubectl initializes a Kubectl helper with the provided vmName and log
// It marks the test as Fail if cannot get the ssh meta information or cannot
// execute a `ls` on the virtual machine.
func CreateKubectl(vmName string, log *logrus.Entry) *Kubectl {
	node := GetVagrantSSHMeta(vmName)
	if node == nil {
		ginkgo.Fail(fmt.Sprintf("Cannot connect to vmName  '%s'", vmName), 1)
		return nil
	}
	// This `ls` command is a sanity check, sometimes the meta ssh info is not
	// nil but new commands cannot be executed using SSH, tests failed and it
	// was hard to debug.
	res := node.Exec("ls /tmp/")
	if !res.WasSuccessful() {
		ginkgo.Fail(fmt.Sprintf(
			"Cannot execute ls command on vmName '%s'", vmName), 1)
		return nil
	}
	node.logger = log
	return &Kubectl{
		SSHMeta: node,
	}
}

// ExecKafkaPodCmd executes shell command with arguments arg in the specified pod residing in the specified
// namespace. It returns the stdout of the command that was executed.
// The kafka producer and consumer scripts do not return error if command
// leads to TopicAuthorizationException or any other error. Hence the
// function needs to also take into account the stderr messages returned.
func (kub *Kubectl) ExecKafkaPodCmd(namespace string, pod string, arg string) error {
	command := fmt.Sprintf("%s exec -n %s %s sh -- %s", KubectlCmd, namespace, pod, arg)
	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)
	err := kub.Execute(command, stdout, stderr)
	if err != nil {
		return fmt.Errorf("ExecKafkaPodCmd: command '%s' failed '%s' || '%s'", command, stdout.String(), stderr.String())
	}

	if strings.Contains(stderr.String(), "ERROR") {
		return fmt.Errorf("ExecKafkaPodCmd: command '%s' failed '%s' || '%s'", command, stdout.String(), stderr.String())
	}
	return nil
}

// ExecPodCmd executes command cmd in the specified pod residing in the specified
// namespace. It returns the stdout of the command that was executed, and an
// error if cmd did not execute successfully.
func (kub *Kubectl) ExecPodCmd(namespace string, pod string, cmd string) (string, error) {
	command := fmt.Sprintf("%s exec -n %s %s -- %s", KubectlCmd, namespace, pod, cmd)
	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)
	err := kub.Execute(command, stdout, stderr)
	if err != nil {
		// TODO: Return CmdRes here
		return "", fmt.Errorf("ExecPodCmd: command '%s' failed '%s' || '%s'", command, stdout.String(), stderr.String())
	}
	return stdout.String(), nil
}

// Get retrieves the provided Kubernetes objects from the specified namespace.
func (kub *Kubectl) Get(namespace string, command string) *CmdRes {
	return kub.Exec(fmt.Sprintf(
		"%s -n %s get %s -o json", KubectlCmd, namespace, command))
}

// GetPods gets all of the pods in the given namespace that match the provided
// filter.
func (kub *Kubectl) GetPods(namespace string, filter string) *CmdRes {
	return kub.Exec(fmt.Sprintf("%s -n %s get pods %s -o json", KubectlCmd, namespace, filter))
}

// GetPodsNodes returns a map with pod name as a key and node name as value. It
// only gets pods in the given namespace that match the provided filter. It
// returns an error if pods cannot be retrieved correctly
func (kub *Kubectl) GetPodsNodes(namespace string, filter string) (map[string]string, error) {
	jsonFilter := `{range .items[*]}{@.metadata.name}{"="}{@.spec.nodeName}{"\n"}{end}`
	res := kub.Exec(fmt.Sprintf("%s -n %s get pods %s -o jsonpath='%s'",
		KubectlCmd, namespace, filter, jsonFilter))
	if !res.WasSuccessful() {
		return nil, fmt.Errorf("cannot retrieve pods: %s", res.CombineOutput())
	}
	return res.KVOutput(), nil
}

// GetPodsIPs returns a map with pod name as a key and pod IP name as value. It
// only gets pods in the given namespace that match the provided filter. It
// returns an error if pods cannot be retrieved correctly
func (kub *Kubectl) GetPodsIPs(namespace string, filter string) (map[string]string, error) {
	jsonFilter := `{range .items[*]}{@.metadata.name}{"="}{@.status.podIP}{"\n"}{end}`
	res := kub.Exec(fmt.Sprintf("%s -n %s get pods -l %s -o jsonpath='%s'",
		KubectlCmd, namespace, filter, jsonFilter))
	if !res.WasSuccessful() {
		return nil, fmt.Errorf("cannot retrieve pods: %s", res.CombineOutput())
	}
	return res.KVOutput(), nil
}

// GetEndpoints gets all of the endpoints in the given namespace that match the
// provided filter.
func (kub *Kubectl) GetEndpoints(namespace string, filter string) *CmdRes {
	return kub.Exec(fmt.Sprintf("%s -n %s get endpoints %s -o json", KubectlCmd, namespace, filter))
}

// GetPodNames returns the names of all of the pods that are labeled with label
// in the specified namespace, along with an error if the pod names cannot be
// retrieved.
func (kub *Kubectl) GetPodNames(namespace string, label string) ([]string, error) {
	stdout := new(bytes.Buffer)
	filter := "-o jsonpath='{.items[*].metadata.name}'"

	err := kub.Execute(
		fmt.Sprintf("%s -n %s get pods -l %s %s", KubectlCmd, namespace, label, filter),
		stdout, nil)

	if err != nil {
		return nil, fmt.Errorf(
			"could not find pods in namespace '%v' with label '%v': %s", namespace, label, err)
	}

	out := strings.Trim(stdout.String(), "\n")
	if len(out) == 0 {
		//Small hack. String split always return an array with an empty string
		return []string{}, nil
	}
	return strings.Split(out, " "), nil
}

// GetServiceHostPort returns the host and the first port for the given service name.
// It will return an error if service cannot be retrieved.
func (kub *Kubectl) GetServiceHostPort(namespace string, service string) (string, int, error) {
	var data v1.Service
	err := kub.Get(namespace, fmt.Sprintf("service %s", service)).Unmarshal(&data)
	if err != nil {
		return "", 0, err
	}
	if len(data.Spec.Ports) == 0 {
		return "", 0, fmt.Errorf("Service %q does not have ports defined", service)
	}
	return data.Spec.ClusterIP, int(data.Spec.Ports[0].Port), nil
}

// Logs returns a CmdRes with containing the resulting metadata from the
// execution of `kubectl logs <pod> -n <namespace>`.
func (kub *Kubectl) Logs(namespace string, pod string) *CmdRes {
	return kub.Exec(
		fmt.Sprintf("%s -n %s logs %s", KubectlCmd, namespace, pod))
}

// ManifestGet returns the full path of the given manifest corresponding to the
// Kubernetes version being tested, if such a manifest exists, if not it
// returns the global manifest file.
func (kub *Kubectl) ManifestGet(manifestFilename string) string {
	fullPath := fmt.Sprintf("%s/%s/%s", manifestsPath, GetCurrentK8SEnv(), manifestFilename)
	_, err := os.Stat(fullPath)
	if err == nil {
		return fmt.Sprintf("%s/%s", BasePath, fullPath)
	}
	return fmt.Sprintf("%s/k8sT/manifests/%s", BasePath, manifestFilename)
}

// NodeCleanMetadata annotates each node in the Kubernetes cluster with the
// annotation.V4CIDRName and annotation.V6CIDRName annotations. It returns an
// error if the nodes cannot be retrieved via the Kubernetes API.
func (kub *Kubectl) NodeCleanMetadata() error {
	metadata := []string{
		annotation.V4CIDRName,
		annotation.V6CIDRName,
	}

	data := kub.Exec(fmt.Sprintf("%s get nodes -o jsonpath='{.items[*].metadata.name}'", KubectlCmd))
	if !data.WasSuccessful() {
		return fmt.Errorf("could not get nodes via %s: %s", KubectlCmd, data.CombineOutput())
	}
	for _, node := range strings.Split(data.Output().String(), " ") {
		for _, label := range metadata {
			kub.Exec(fmt.Sprintf("%s annotate nodes %s %s", KubectlCmd, node, label))
		}
	}
	return nil
}

// NamespaceCreate creates a new Kubernetes namespace with the given name
func (kub *Kubectl) NamespaceCreate(name string) *CmdRes {
	return kub.Exec(fmt.Sprintf("%s create namespace %s", KubectlCmd, name))
}

// NamespaceDelete deletes a given Kubernetes namespace
func (kub *Kubectl) NamespaceDelete(name string) *CmdRes {
	return kub.Exec(fmt.Sprintf("%s delete namespace %s", KubectlCmd, name))
}

// WaitforPods waits up until timeout seconds have elapsed for all pods in the
// specified namespace that match the provided JSONPath filter to have their
// containterStatuses equal to "ready". Returns true if all pods achieve
// the aforementioned desired state within timeout seconds. Returns false and
// an error if the command failed or the timeout was exceeded.
func (kub *Kubectl) WaitforPods(namespace string, filter string, timeout time.Duration) (bool, error) {
	body := func() bool {
		var jsonPath = "{.items[*].status.containerStatuses[*].ready}"
		data, err := kub.GetPods(namespace, filter).Filter(jsonPath)
		if err != nil {
			kub.logger.Errorf("could not get pods: %s", err)
			return false
		}

		valid := true
		result := strings.Split(data.String(), " ")
		for _, v := range result {
			if val, _ := govalidator.ToBoolean(v); val == false {
				valid = false
				break
			}
		}
		if valid == true {
			return true
		}
		kub.logger.WithFields(logrus.Fields{
			"namespace": namespace,
			"filter":    filter,
			"data":      data,
		}).Info("WaitforPods: pods are not ready")
		return false
	}
	err := WithTimeout(body, "could not get Pods", &TimeoutConfig{Timeout: timeout})
	if err != nil {
		return false, err
	}
	return true, nil
}

// WaitForServiceEndpoints waits up until timeout seconds have elapsed for all
// endpoints in the specified namespace that match the provided JSONPath filter
// to have their port equal to the provided port. Returns true if all pods achieve
// the aforementioned desired state within timeout seconds. Returns false and
// an error if the command failed or the timeout was exceeded.
func (kub *Kubectl) WaitForServiceEndpoints(namespace string, filter string, service string, port string, timeout time.Duration) (bool, error) {
	body := func() bool {
		var jsonPath = fmt.Sprintf("{.items[?(@.metadata.name =='%s')].subsets[0].ports[0].port}", service)
		data, err := kub.GetEndpoints(namespace, filter).Filter(jsonPath)

		if err != nil {
			kub.logger.WithError(err)
			return false
		}

		if data.String() == port {
			return true
		}

		kub.logger.WithFields(logrus.Fields{
			"namespace": namespace,
			"filter":    filter,
			"data":      data,
		}).Info("WaitForServiceEndpoints: service endpoint not ready")
		return false
	}

	err := WithTimeout(body, "could not get service endpoints", &TimeoutConfig{Timeout: timeout})
	if err != nil {
		return false, err
	}
	return true, nil
}

// Action performs the specified ResourceLifeCycleAction on the Kubernetes
// manifest located at path filepath in the given namespace
func (kub *Kubectl) Action(action ResourceLifeCycleAction, filePath string) *CmdRes {
	kub.logger.Debugf("performing '%v' on '%v'", action, filePath)
	return kub.Exec(fmt.Sprintf("%s %s -f %s", KubectlCmd, action, filePath))
}

// Apply applies the Kubernetes manifest located at path filepath.
func (kub *Kubectl) Apply(filePath string) *CmdRes {
	kub.logger.Debugf("applying %s", filePath)
	return kub.Exec(
		fmt.Sprintf("%s apply -f  %s", KubectlCmd, filePath))
}

// Create creates the Kubernetes kanifest located at path filepath.
func (kub *Kubectl) Create(filePath string) *CmdRes {
	kub.logger.Debugf("creating %s", filePath)
	return kub.Exec(
		fmt.Sprintf("%s create -f  %s", KubectlCmd, filePath))
}

// CreateResource is a wrapper around `kubernetes create <resource>
// <resourceName>.
func (kub *Kubectl) CreateResource(resource, resourceName string) *CmdRes {
	kub.logger.Debug(fmt.Sprintf("creating resource %s with name %s", resource, resourceName))
	return kub.Exec(fmt.Sprintf("kubectl create %s %s", resource, resourceName))
}

// DeleteResource is a wrapper around `kubernetes delete <resource>
// resourceName>.
func (kub *Kubectl) DeleteResource(resource, resourceName string) *CmdRes {
	kub.logger.Debug(fmt.Sprintf("deleting resource %s with name %s", resource, resourceName))
	return kub.Exec(fmt.Sprintf("kubectl delete %s %s", resource, resourceName))
}

// Delete deletes the Kubernetes manifest at path filepath.
func (kub *Kubectl) Delete(filePath string) *CmdRes {
	kub.logger.Debugf("deleting %s", filePath)
	return kub.Exec(
		fmt.Sprintf("%s delete -f  %s", KubectlCmd, filePath))
}

// WaitKubeDNS waits until the kubeDNS pods are ready. In case of exceeding the
// default timeout it returns an error.
func (kub *Kubectl) WaitKubeDNS() error {
	body := func() bool {
		status, err := kub.WaitforPods(KubeSystemNamespace, fmt.Sprintf("-l %s", kubeDNSLabel), 300)
		if status {
			return true
		}
		kub.logger.WithError(err).Debug("KubeDNS is not ready yet")
		return false
	}
	err := WithTimeout(body, "KubeDNS pods are not ready", &TimeoutConfig{Timeout: HelperTimeout})
	return err
}

// WaitCleanAllTerminatingPods waits until all nodes that are in `Terminating`
// state are deleted correctly in the platform. In case of excedding the
// default timeout it returns an error
func (kub *Kubectl) WaitCleanAllTerminatingPods() error {
	body := func() bool {
		res := kub.Exec(fmt.Sprintf(
			"%s get pods --all-namespaces -o jsonpath='{.items[*].status.phase}'",
			KubectlCmd))
		if !res.WasSuccessful() {
			return false
		}
		podsTerminating := strings.Count(res.Output().String(), StateTerminating)
		kub.logger.WithField("Terminating pods", podsTerminating).Info("List of pods terminating")
		if podsTerminating > 0 {
			return false
		}
		return true
	}

	err := WithTimeout(
		body,
		"Pods are still not deleted after a timeout",
		&TimeoutConfig{Timeout: HelperTimeout * time.Second})
	return err
}

// GetCiliumPods returns a list of all Cilium pods in the specified namespace,
// and an error if the Cilium pods were not able to be retrieved.
func (kub *Kubectl) GetCiliumPods(namespace string) ([]string, error) {
	return kub.GetPodNames(namespace, "k8s-app=cilium")
}

// CiliumEndpointsList returns the result of `cilium endpoint list` from the
// specified pod.
func (kub *Kubectl) CiliumEndpointsList(pod string) *CmdRes {
	return kub.CiliumExec(pod, "cilium endpoint list -o json")
}

// CiliumEndpointGet returns the output of `cilium endpoint get` for the
// provided endpoint ID.
func (kub *Kubectl) CiliumEndpointGet(pod string, id string) *CmdRes {
	return kub.CiliumExec(pod, fmt.Sprintf(
		"cilium endpoint get %s -o json", id))
}

// CiliumEndpointsIDs returns a mapping  of a pod name to it is corresponding
// endpoint's security identity
func (kub *Kubectl) CiliumEndpointsIDs(pod string) map[string]string {
	filter := `{range [*]}{@.pod-name}{"="}{@.id}{"\n"}{end}`
	return kub.CiliumExec(pod, fmt.Sprintf(
		"cilium endpoint list -o jsonpath='%s'", filter)).KVOutput()
}

// CiliumEndpointsStatus returns a mapping  of a pod name to it is corresponding
// endpoint's status
func (kub *Kubectl) CiliumEndpointsStatus(pod string) map[string]string {
	filter := `{range [*]}{@.pod-name}{"="}{@.state}{"\n"}{end}`
	return kub.CiliumExec(pod, fmt.Sprintf(
		"cilium endpoint list -o jsonpath='%s'", filter)).KVOutput()
}

// CiliumEndpointsIdentityIDs returns a mapping with of a pod name to it is
// corresponding endpoint's security identity
func (kub *Kubectl) CiliumEndpointsIdentityIDs(pod string) map[string]string {
	filter := `{range [*]}{@.container-name}{"="}{@.identity.id}{"\n"}{end}`
	return kub.CiliumExec(pod, fmt.Sprintf(
		"cilium endpoint list -o jsonpath='%s'", filter)).KVOutput()
}

// CiliumEndpointsListByLabel returns all endpoints that are labeled with label
// in the form of an EndpointMap, which maps an endpoint's container name to its
// corresponding Cilium API endpoint model. It returns an error if the extraction
// of the command to retrieve the endpoints via the Cilium API fails.
func (kub *Kubectl) CiliumEndpointsListByLabel(pod, label string) (EndpointMap, error) {
	result := make(EndpointMap)
	var data []models.Endpoint
	eps := kub.CiliumEndpointsList(pod)

	err := eps.Unmarshal(&data)
	if err != nil {
		return nil, err
	}

	for _, ep := range data {
		for _, orchLabel := range ep.Labels.OrchestrationIdentity {
			if label == orchLabel {
				result[ep.ContainerName] = ep
				break
			}
		}

	}
	return result, nil
}

// CiliumEndpointWait waits until all endpoints managed by the specified Cilium
// pod are ready. Returns false if the command to retrieve the state of the
// endpoints times out.
func (kub *Kubectl) CiliumEndpointWait(pod string) bool {

	body := func() bool {
		status, err := kub.CiliumEndpointsList(pod).Filter("{[*].state}")
		if err != nil {
			return false
		}

		var valid, invalid int
		for _, endpoint := range strings.Split(status.String(), " ") {
			if endpoint != "ready" {
				invalid++
			} else {
				valid++
			}
		}
		if invalid == 0 {
			return true
		}

		kub.logger.WithFields(logrus.Fields{
			"pod":     pod,
			"valid":   valid,
			"invalid": invalid,
		}).Info("Waiting for cilium endpoints")
		return false
	}

	err := WithTimeout(body, "cannot retrieve endpoints", &TimeoutConfig{Timeout: HelperTimeout})
	if err != nil {
		return false
	}
	return true
}

// CiliumEndpointPolicyVersion returns a mapping of each endpoint's ID to its
// policy revision number for all endpoints in the specified Cilium pod.
func (kub *Kubectl) CiliumEndpointPolicyVersion(pod string) map[string]int64 {
	result := map[string]int64{}
	filter := `{range [*]}{@.id}{"="}{@.policy-revision}{"\n"}{end}`

	data := kub.CiliumExec(
		pod,
		fmt.Sprintf("cilium endpoint list -o jsonpath='%s'", filter))
	for k, v := range data.KVOutput() {
		val, _ := govalidator.ToInt(v)
		result[k] = val
	}
	return result
}

// CiliumExec runs cmd in the specified Cilium pod.
func (kub *Kubectl) CiliumExec(pod string, cmd string) *CmdRes {
	cmd = fmt.Sprintf("%s exec -n kube-system %s -- %s", KubectlCmd, pod, cmd)
	return kub.Exec(cmd)
}

// CiliumNodesWait waits until all nodes in the Kubernetes cluster are annotated
// with Cilium annotations. Its runtime is bounded by a maximum of `HelperTimeout`.
// When a node is annotated with said annotations, it indicates
// that the tunnels in the nodes are set up and that cross-node traffic can be
// tested. Returns an error if the timeout is exceeded for waiting for the nodes
// to be annotated.
func (kub *Kubectl) CiliumNodesWait() (bool, error) {
	body := func() bool {
		filter := `{range .items[*]}{@.metadata.name}{"="}{@.metadata.annotations.io\.cilium\.network\.ipv4-pod-cidr}{"\n"}{end}`
		data := kub.Exec(fmt.Sprintf(
			"%s get nodes -o jsonpath='%s'", KubectlCmd, filter))
		if !data.WasSuccessful() {
			return false
		}
		result := data.KVOutput()
		for k, v := range result {
			if v == "" {
				kub.logger.Infof("Kubernetes node '%v' does not have Cilium metadata", k)
				return false
			}
			kub.logger.Infof("Kubernetes node '%v' IPv4 address: '%v'", k, v)
		}
		return true
	}
	err := WithTimeout(body, "Kubernetes node does not have cilium metadata", &TimeoutConfig{Timeout: HelperTimeout})
	if err != nil {
		return false, err
	}
	return true, nil
}

// CiliumPolicyRevision returns the policy revision in the specified Cilium pod.
// Returns an error if the policy revision cannot be retrieved.
func (kub *Kubectl) CiliumPolicyRevision(pod string) (int, error) {
	// FIXME GH-1725
	res := kub.CiliumExec(pod, "cilium policy get | grep Revision | awk '{print $2}'")

	if !res.WasSuccessful() {
		return -1, fmt.Errorf("Cannot get the revision %s", res.Output())
	}
	revi, err := res.IntOutput()
	if err != nil {
		kub.logger.Errorf("Revision on pod '%s' is not valid '%s'", pod, res.CombineOutput())
		return -1, err
	}
	return revi, nil
}

// CiliumIsPolicyLoaded returns true if the policy is loaded in the given
// cilium Pod. it returns false in case that the policy is not in place
func (kub *Kubectl) CiliumIsPolicyLoaded(pod string, policyCmd string) bool {
	_, err := kub.ExecPodCmd(KubeSystemNamespace, pod, fmt.Sprintf("cilium policy get %s", policyCmd))
	if err == nil {
		return true
	}
	return false
}

// ResourceLifeCycleAction represents an action performed upon objects in
// Kubernetes.
type ResourceLifeCycleAction string

// CiliumPolicyAction performs the specified action in Kubernetes for the policy
// stored in path filepath and waits up  until timeout seconds for the policy
// to be applied in all Cilium endpoints. Returns an error if the policy is not
// imported before the timeout is
// exceeded.
func (kub *Kubectl) CiliumPolicyAction(namespace, filepath string, action ResourceLifeCycleAction, timeout time.Duration) (string, error) {
	revisions := map[string]int{}

	kub.logger.Infof("Performing %s action on resource '%s'", action, filepath)
	pods, err := kub.GetCiliumPods(namespace)
	if err != nil {
		return "", err
	}

	for _, v := range pods {
		revi, err := kub.CiliumPolicyRevision(v)
		if err != nil {
			return "", err
		}
		revisions[v] = revi
		kub.logger.Infof("CiliumPolicyAction: pod '%s' has revision '%v'", v, revi)
	}

	if status := kub.Action(action, filepath); !status.WasSuccessful() {
		return "", fmt.Errorf("cannot perform %q on resource %q", action, filepath)
	}

	body := func() bool {
		waitingRev := map[string]int{}

		valid := true
		for _, v := range pods {
			revi, err := kub.CiliumPolicyRevision(v)
			if err != nil {
				kub.logger.Errorf("CiliumPolicyAction: error on get revision %s", err)
				return false
			}
			if revi <= revisions[v] {
				kub.logger.Infof("CiliumPolicyAction: pod '%s' still on old revision '%v', need '%v'", v, revi, revisions[v])
				valid = false
			} else {
				waitingRev[v] = revi
			}
		}

		if valid == true {
			// Wait until all the pods are synced
			for pod, rev := range waitingRev {
				kub.logger.Infof("CiliumPolicyAction: Wait for endpoints to sync on pod '%s'", pod)
				kub.ExecPodCmd(namespace, pod, fmt.Sprintf("cilium policy wait %d", rev))
				kub.logger.Infof("CiliumPolicyAction: revision %d in pod '%s' is ready", rev, pod)
			}
			return true
		}
		return false
	}
	err = WithTimeout(
		body,
		"cannot change state of resource correctly; command timed out",
		&TimeoutConfig{Timeout: timeout})
	if err != nil {
		return "", err
	}
	return "", nil
}

//CiliumReport report the cilium pod to the log and apppend the logs for the
//given commands. Return err in case of any problem
func (kub *Kubectl) CiliumReport(namespace string, pod string, commands []string) error {
	wr := kub.logger.Logger.Out
	fmt.Fprint(wr, "StackTrace Begin\n")
	data := kub.Logs(namespace, pod)
	fmt.Fprintln(wr, data.Output())

	data = kub.Exec(fmt.Sprintf("%s get pods -o wide", KubectlCmd))
	fmt.Fprintln(wr, data.Output())

	for _, cmd := range commands {
		command := fmt.Sprintf("%s exec -n %s %s -- %s", KubectlCmd, namespace, pod, cmd)
		out := kub.Exec(command)
		fmt.Fprintln(wr, out.CombineOutput())
	}
	fmt.Fprint(wr, "StackTrace Ends\n")
	kub.CiliumReportDump(namespace, pod)
	kub.GatherLogs()
	return nil
}

// CiliumReportDump runs a variety of commands (CiliumKubCLICommands) and writes the results to
// TestResultsPath
func (kub *Kubectl) CiliumReportDump(namespace string, pod string) {
	reportEndpointCommands := map[string]string{
		"cilium endpoint get %s":   "endpoint_get_%s.txt",
		"cilium bpf policy get %s": "bpf_policy_get_%s.txt",
	}

	testPath, err := ReportDirectory()
	if err != nil {
		kub.logger.WithError(err).Errorf("cannot create test result path '%s'", testPath)
		return
	}

	reportCmds := map[string]string{}
	for cmd, logfile := range ciliumKubCLICommands {
		command := fmt.Sprintf("kubectl exec -n %s %s -- %s", namespace, pod, cmd)
		reportCmds[command] = logfile
	}
	reportMap(testPath, reportCmds, kub.SSHMeta)

	for _, ep := range kub.CiliumEndpointsIDs(pod) {
		for cmd, logfile := range reportEndpointCommands {
			command := fmt.Sprintf(cmd, ep)
			res := kub.Exec(fmt.Sprintf(
				"kubectl exec -n %s %s -- %s", namespace, pod, command))
			err = ioutil.WriteFile(
				fmt.Sprintf("%s/%s", testPath, fmt.Sprintf(logfile, ep)),
				res.CombineOutput().Bytes(),
				LogPerm)
			if err != nil {
				kub.logger.WithError(err).Errorf(
					"cannot create test results for command '%s'", command)
			}
		}
	}

	for _, id := range kub.CiliumEndpointsIdentityIDs(pod) {
		cmd := fmt.Sprintf("kubectl exec -n %s %s -- cilium identity get %s", namespace, pod, id)

		res := kub.Exec(cmd)
		err = ioutil.WriteFile(
			fmt.Sprintf("%s/%s", testPath, fmt.Sprintf("identity_%s.txt", id)),
			res.CombineOutput().Bytes(),
			LogPerm)
		if err != nil {
			kub.logger.WithError(err).Errorf("cannot create test results for command '%s'", cmd)
		}
	}
}

// GatherLogs dumps kubernetes pods, services, DaemonSet to the testResultsPath
// directory
func (kub *Kubectl) GatherLogs() {
	reportCmds := map[string]string{
		"kubectl get pods -o wide --all-namespaces":     "pods.txt",
		"kubectl get services -o wide --all-namespaces": "svc.txt",
		"kubectl get ds -o wide --all-namespaces":       "ds.txt",
		"kubectl get cnp --all-namespaces":              "cnp.txt",
		"kubectl describe pods --all-namespaces":        "pods_status.txt",
		"kubectl -n kube-system logs -l k8s-app=cilium": "cilium_logs.txt",
	}

	testPath, err := ReportDirectory()
	if err != nil {
		kub.logger.WithError(err).Errorf(
			"cannot create test results path '%s'", testPath)
		return
	}
	reportMap(testPath, reportCmds, kub.SSHMeta)
}

// GetCiliumPodOnNode returns the name of the Cilium pod that is running on / in
//the specified node / namespace.
func (kub *Kubectl) GetCiliumPodOnNode(namespace string, node string) (string, error) {
	filter := fmt.Sprintf(
		"-o jsonpath='{.items[?(@.spec.nodeName == \"%s\")].metadata.name}'", node)

	res := kub.Exec(fmt.Sprintf(
		"%s -n %s get pods -l k8s-app=cilium %s", KubectlCmd, namespace, filter))
	if !res.WasSuccessful() {
		return "", fmt.Errorf("Cilium pod not found on node '%s'", node)
	}

	return res.Output().String(), nil
}

// EndpointMap maps an endpoint's container name to its Cilium API endpoint model.
type EndpointMap map[string]models.Endpoint

// GetPolicyStatus returns a mapping of how many endpoints in epMap have policy
// enforcement enabled and disabled.
//
// map can be index with the following keys:
//	models.EndpointPolicyEnabledNone
//	models.EndpointPolicyEnabledIngress
//	models.EndpointPolicyEnabledEgress
//	models.EndpointPolicyEnabledBoth
func (epMap *EndpointMap) GetPolicyStatus() map[string]int {
	result := map[string]int{
		models.EndpointPolicyEnabledNone:    0,
		models.EndpointPolicyEnabledIngress: 0,
		models.EndpointPolicyEnabledEgress:  0,
		models.EndpointPolicyEnabledBoth:    0,
	}

	for _, ep := range *epMap {
		result[*ep.PolicyEnabled]++
	}
	return result
}

// AreReady returns true if all Cilium endpoints are in 'ready' state
func (epMap *EndpointMap) AreReady() bool {
	for _, ep := range *epMap {
		if ep.State != models.EndpointStateReady {
			return false
		}
	}
	return true
}
