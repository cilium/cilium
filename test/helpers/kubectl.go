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
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/annotation"

	"github.com/asaskevich/govalidator"
	"github.com/onsi/ginkgo"
	"github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sClient "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

const (
	// KubectlCmd Kubernetes controller command
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
	k8sClient.Clientset
}

// logHTTPTransport is a wrapper of http.Transport to log all http requests
type logHTTPTransport struct {
	transport *http.Transport
	logger    *logrus.Entry
}

func (l *logHTTPTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var reqURL, reqMethod, reqStr, rspStr string

	reqStr = "<empty>"
	if req != nil {
		reqURL = req.URL.String()
		reqMethod = req.Method
		if req.Body != nil {
			newBody, err := req.GetBody()
			if err == nil {
				body, _ := ioutil.ReadAll(newBody)
				reqStr = string(body)
			}
		}
	}

	resp, err := l.transport.RoundTrip(req)

	if err != nil {
		rspStr = "error: " + err.Error()
	} else {
		rspStr = resp.Status
	}
	reqLog := l.logger.WithFields(
		logrus.Fields{
			"to":     reqURL,
			"method": reqMethod,
			"data":   reqStr,
			"result": rspStr,
		})
	reqLog.Debugf("HTTPRequest")
	return resp, err
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

	k8sConfig, err := clientcmd.BuildConfigFromKubeconfigGetter("", func() (*clientcmdapi.Config, error) {
		res = node.Exec("cat ${HOME}/.kube/config")
		if res.WasSuccessful() {
			return clientcmd.Load(res.stdout.Bytes())
		}
		return nil, fmt.Errorf("unable to read kubeconfig file: %s", res.GetStdErr())
	})
	if err != nil {
		ginkgo.Fail(fmt.Sprintf(
			"Cannot set kubernetes configuration: %s", err), 1)
		return nil
	}

	k8sConfig.WrapTransport = func(rt http.RoundTripper) http.RoundTripper {
		httpTransport, ok := rt.(*http.Transport)
		if !ok {
			return rt
		}
		httpTransport.DialContext = func(_ context.Context, network, addr string) (net.Conn, error) {
			// Create a connection to the kubeapiserver via the ssh tunnel
			conn, err := ssh.Dial("tcp", node.sshClient.GetHostPort(), node.sshClient.Config)
			if err != nil {
				return nil, err
			}
			return conn.Dial(network, addr)
		}
		// Create a wrapper so we can log the requests
		return &logHTTPTransport{
			logger:    log,
			transport: httpTransport,
		}
	}

	c, err := k8sClient.NewForConfig(k8sConfig)
	if err != nil {
		ginkgo.Fail(fmt.Sprintf(
			"Cannot create kubernetes client: %s", err), 1)
		return nil
	}
	return &Kubectl{
		SSHMeta:   node,
		Clientset: *c,
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
// namespace. It returns a pointer to CmdRes with all the output
func (kub *Kubectl) ExecPodCmd(namespace string, pod string, cmd string) *CmdRes {
	command := fmt.Sprintf("%s exec -n %s %s -- %s", KubectlCmd, namespace, pod, cmd)
	return kub.Exec(command)
}

// ExecPodCmd executes command cmd in background in the specified pod residing
// in the specified namespace. It returns a pointer to CmdRes with all the
// output
func (kub *Kubectl) ExecPodCmdContext(ctx context.Context, namespace string, pod string, cmd string) *CmdRes {
	command := fmt.Sprintf("%s exec -n %s %s -- %s", KubectlCmd, namespace, pod, cmd)
	return kub.ExecContext(ctx, command)
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
			"%s get pods --all-namespaces -o jsonpath='{.items[*].metadata.deletionTimestamp}'",
			KubectlCmd))
		if !res.WasSuccessful() {
			return false
		}

		if res.Output().String() == "" {
			// Output is empty so no terminating containers
			return true
		}

		podsTerminating := len(strings.Split(res.Output().String(), " "))
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
		for _, orchLabel := range ep.Labels.Status.SecurityRelevant {
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
	res := kub.CiliumExec(pod, "cilium policy get -o json")
	if !res.WasSuccessful() {
		return -1, fmt.Errorf("cannot get the revision %s", res.Output())
	}

	revision, err := res.Filter("{.revision}")
	if err != nil {
		return -1, fmt.Errorf("cannot get revision from json: %s", err)
	}

	revi, err := strconv.Atoi(strings.Trim(revision.String(), "\n"))
	if err != nil {
		kub.logger.Errorf("revision on pod '%s' is not valid '%s'", pod, res.CombineOutput())
		return -1, err
	}
	return revi, nil
}

// CiliumIsPolicyLoaded returns true if the policy is loaded in the given
// cilium Pod. it returns false in case that the policy is not in place
func (kub *Kubectl) CiliumIsPolicyLoaded(pod string, policyCmd string) bool {
	res := kub.ExecPodCmd(KubeSystemNamespace, pod, fmt.Sprintf("cilium policy get %s", policyCmd))
	return res.WasSuccessful()
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

// CiliumReport report the cilium pod to the log and appends the logs for the
// given commands.
func (kub *Kubectl) CiliumReport(namespace string, commands ...[]string) {
	pods, err := kub.GetCiliumPods(namespace)
	if err != nil {
		kub.logger.WithError(err).Error("cannot retrieve cilium pods on ReportDump")
		return
	}

	wr := kub.logger.Logger.Out
	fmt.Fprint(wr, "StackTrace Begin\n")

	data := kub.Exec(fmt.Sprintf("%s get pods -o wide", KubectlCmd))
	fmt.Fprintln(wr, data.Output())

	for _, pod := range pods {
		res := kub.Logs(namespace, pod)
		fmt.Fprintln(wr, res.Output())

		for _, cmd := range commands {
			command := fmt.Sprintf("%s exec -n %s %s -- %s", KubectlCmd, namespace, pod, cmd)
			out := kub.Exec(command)
			fmt.Fprintln(wr, out.CombineOutput())
		}
	}
	fmt.Fprint(wr, "StackTrace Ends\n")
	kub.DumpCiliumCommandOutput(namespace)
	kub.GatherLogs()
	kub.CheckLogsForDeadlock()

}

// ValidateNoErrorsOnLogs checks in cilium logs since the given duration (By
// default `CurrentGinkgoTestDescription().Duration`) do not contain `panic` or
// `deadlocks` messages. In case of any of these messages, it'll mark the test
// as failed.
func (kub *Kubectl) ValidateNoErrorsOnLogs(duration time.Duration) {
	cmd := fmt.Sprintf("%s -n %s logs --timestamps=true -l k8s-app=cilium --since=%vs",
		KubectlCmd, KubeSystemNamespace, duration.Seconds())
	res := kub.Exec(fmt.Sprintf("%s --previous", cmd))
	if !res.WasSuccessful() {
		res = kub.Exec(cmd)
	}
	logs := res.Output().String()
	gomega.ExpectWithOffset(1, logs).ToNot(gomega.ContainSubstring("panic: "),
		"Found a panic in Cilium logs")
	gomega.ExpectWithOffset(1, logs).ToNot(gomega.ContainSubstring(deadLockHeader),
		"Found a deadlock in Cilium logs")
}

// CheckLogsForDeadlock checks if the logs for Cilium log messages that signify
// that a deadlock has occurred.
func (kub *Kubectl) CheckLogsForDeadlock() {
	deadlockCheckCmd := fmt.Sprintf("%s -n %s logs --timestamps=true -l k8s-app=cilium | grep -qi -B 5 -A 5 deadlock", KubectlCmd, KubeSystemNamespace)
	res := kub.Exec(deadlockCheckCmd)
	if res.WasSuccessful() {
		log.Errorf("Deadlock during test run detected, check Cilium logs for context")
	}
	// Also check for previous container
	deadlockCheckCmd = fmt.Sprintf("%s -n %s logs --timestamps=true --previous -l k8s-app=cilium | grep -qi -B 5 -A 5 deadlock", KubectlCmd, KubeSystemNamespace)
	res = kub.Exec(deadlockCheckCmd)
	if res.WasSuccessful() {
		log.Errorf("Deadlock during test run detected, check Cilium logs for context")
	}
}

// DumpCiliumCommandOutput runs a variety of commands (CiliumKubCLICommands) and writes the results to
// TestResultsPath
func (kub *Kubectl) DumpCiliumCommandOutput(namespace string) {
	ReportOnPod := func(pod string) {
		logger := kub.logger.WithField("CiliumPod", pod)

		testPath, err := CreateReportDirectory()
		if err != nil {
			logger.WithError(err).Errorf("cannot create test result path '%s'", testPath)
			return
		}

		reportCmds := map[string]string{}
		for cmd, logfile := range ciliumKubCLICommands {
			command := fmt.Sprintf("%s exec -n %s %s -- %s", KubectlCmd, namespace, pod, cmd)
			reportCmds[command] = fmt.Sprintf("%s_%s", pod, logfile)
		}
		reportMap(testPath, reportCmds, kub.SSHMeta)

		logsPath := filepath.Join(BasePath, testPath)

		// Get bugtool output. Since bugtool output is dumped in the pod's filesystem,
		// copy it over with `kubectl cp`.
		bugtoolCmd := fmt.Sprintf("%s exec -n %s %s -- %s",
			KubectlCmd, namespace, pod, CiliumBugtool)
		res := kub.Exec(bugtoolCmd, ExecOptions{SkipLog: true})
		if res.WasSuccessful() {
			// Default output directory is /tmp for bugtool.
			res = kub.Exec(fmt.Sprintf("%s exec -n %s %s -- ls /tmp/", KubectlCmd, namespace, pod))
			tmpList := res.ByLines()
			for _, line := range tmpList {
				// Only copy over bugtool output to directory.
				if strings.Contains(line, CiliumBugtool) {
					archiveName := fmt.Sprintf("%s-%s", pod, line)
					res = kub.Exec(fmt.Sprintf(
						"%s cp %s/%s:/tmp/%s /tmp/", KubectlCmd, namespace, pod, line),
						ExecOptions{SkipLog: true})
					if !res.WasSuccessful() {
						logger.Errorf("'%s' failed: %s", res.GetCmd(), res.CombineOutput())
					}
					res = kub.Exec(fmt.Sprintf(
						"cp %s %s",
						filepath.Join("/tmp/", line),
						filepath.Join(logsPath, archiveName)),
						ExecOptions{SkipLog: true})

					if !res.WasSuccessful() {
						logger.Errorf("'%s' failed: %s", res.GetCmd(), res.CombineOutput())
					}
				}
			}
		} else {
			logger.Errorf("%s failed: %s", bugtoolCmd, res.CombineOutput().String())
		}

		// Copy Cilium envoy logs. Since the logs are in the pod's filesystem,
		// copy them over with `kubectl cp`.
		ciliumEnvoyLogCmd := fmt.Sprintf("%s cp %s/%s:%s %s",
			KubectlCmd, namespace, pod, CiliumEnvoyLogPath,
			filepath.Join(logsPath, CiliumEnvoyLogName))
		res = kub.Exec(ciliumEnvoyLogCmd, ExecOptions{SkipLog: true})
		if !res.WasSuccessful() {
			log.Errorf("%s failed: %s", ciliumEnvoyLogCmd, res.CombineOutput().String())
		}
	}

	pods, err := kub.GetCiliumPods(namespace)
	if err != nil {
		kub.logger.WithError(err).Error("cannot retrieve cilium pods on ReportDump")
		return
	}
	for _, pod := range pods {
		ReportOnPod(pod)
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

	testPath, err := CreateReportDirectory()
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

// podHasExited returns true if the pod has finished up running.
func (kub *Kubectl) podHasExited(ns, podName string) (bool, error) {
	pod, err := kub.CoreV1().Pods(ns).Get(podName, metav1.GetOptions{})
	if err != nil {
		return false, err
	}
	switch pod.Status.Phase {
	case v1.PodFailed, v1.PodSucceeded:
		return true, nil
	}
	return false, nil
}

// WaitForPodExit waits for the given pod in the given namespace until the pod
// is finished running or until the given context deadline is reached.
func (kub *Kubectl) WaitForPodExit(ctx context.Context, ns, podName string) error {
	return WithTimeoutErr(ctx, func() (bool, error) {
		return kub.podHasExited(ns, podName)
	}, time.Second)
}

// isPodReady returns true if the given pod in the given namespace is running
// and in ready state.
func (kub *Kubectl) isPodReady(ns, podName string) (bool, error) {
	pod, err := kub.CoreV1().Pods(ns).Get(podName, metav1.GetOptions{})
	if err != nil {
		return false, err
	}
	switch pod.Status.Phase {
	case v1.PodFailed, v1.PodSucceeded:
		return false, errors.New("Pod is not running")
	case v1.PodRunning:
		for _, cond := range pod.Status.Conditions {
			if cond.Type == v1.PodReady && cond.Status == v1.ConditionTrue {
				return true, nil
			}
		}
	}
	return false, nil
}

// WaitForPodReady waits for the given pod in the given namespace until the pod
// is running and in ready state or until the given context deadline is reached.
func (kub *Kubectl) WaitForPodReady(ctx context.Context, ns, podName string) error {
	return WithTimeoutErr(ctx, func() (bool, error) {
		return kub.isPodReady(ns, podName)
	}, time.Second)
}

// podHasExitedSuccessfully returns true if the pod has finished up running. Error is returned
// if an unsuccessful exit has occurred.
func (kub *Kubectl) podHasExitedSuccessfully(ns, podName string) (bool, error) {
	pod, err := kub.CoreV1().Pods(ns).Get(podName, metav1.GetOptions{})
	if err != nil {
		return false, err
	}
	if pod.Spec.RestartPolicy == v1.RestartPolicyAlways {
		return true, fmt.Errorf("pod %q will never terminate with a succeeded state since its restart policy is Always", pod.Name)
	}
	switch pod.Status.Phase {
	case v1.PodSucceeded:
		return true, nil
	case v1.PodFailed:
		return true, fmt.Errorf("pod %q failed with status: %+v", pod.Name, pod.Status)
	default:
		return false, nil
	}
}

// WaitForPodSuccess waits for the given pod in the given namespace until the
// pod has successfully exited or until the given context deadline is reached.
func (kub *Kubectl) WaitForPodSuccess(ctx context.Context, ns, podName string) (bool, error) {
	err := WithTimeoutErr(ctx, func() (bool, error) {
		return kub.podHasExitedSuccessfully(ns, podName)
	}, time.Second)

	if err != nil {
		return false, err
	}
	return true, nil
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
