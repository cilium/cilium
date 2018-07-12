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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/annotation"
	cnpv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/test/config"
	"github.com/cilium/cilium/test/ginkgo-ext"

	"github.com/asaskevich/govalidator"
	"github.com/onsi/ginkgo"
	"github.com/sirupsen/logrus"
	"k8s.io/api/core/v1"
)

const (
	// KubectlCmd Kubernetes controller command
	KubectlCmd    = "kubectl"
	manifestsPath = "k8sT/manifests/"
	kubeDNSLabel  = "k8s-app=kube-dns"

	// DNSHelperTimeout is a predefined timeout value for K8s DNS commands. It
	// must be larger than 5 minutes because kubedns has a hardcoded resync
	// period of 5 minutes. We have experienced test failures because kubedns
	// needed this time to recover from a connection problem to kube-apiserver.
	// The kubedns resyncPeriod is defined at
	// https://github.com/kubernetes/dns/blob/80fdd88276adba36a87c4f424b66fdf37cd7c9a8/pkg/dns/dns.go#L53
	DNSHelperTimeout time.Duration = 420 // WithTimeout helper translates it to seconds
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

// CepGet returns the endpoint model for the given pod name in the specified
// namespaces. If the pod is not present it returns nil
func (kub *Kubectl) CepGet(namespace string, pod string) *models.Endpoint {
	log := kub.logger.WithFields(logrus.Fields{
		"cep":       pod,
		"namespace": namespace})

	cmd := fmt.Sprintf("%s -n %s get cep %s -o json | jq '.status'", KubectlCmd, namespace, pod)
	res := kub.Exec(cmd)
	if !res.WasSuccessful() {
		log.Debug("cep is not present")
		return nil
	}

	var data *models.Endpoint
	err := res.Unmarshal(&data)
	if err != nil {
		log.WithError(err).Error("cannot Unmarshal json")
		return nil
	}
	return data
}

// WaitCEPReady waits until all Cilium endpoints are sync in Kubernetes resource.
func (kub *Kubectl) WaitCEPReady() error {
	pods, err := kub.GetCiliumPods(KubeSystemNamespace)
	if err != nil {
		return err
	}
	body := func() bool {
		// Created a map of .id and IPv4 because endpoint id can be the same in different nodes.
		endpointFilter := `{range [*]}{@.id}{"_"}{@.status.networking.addressing[0].ipv4}{"="}{@.status.policy.spec.policy-revision}{"\n"}{end}`
		cepFilter := `{range .items[*]}{@.status.id}{"_"}{@.status.status.networking.addressing[0].ipv4}{"="}{@.status.status.policy.spec.policy-revision}{"\n"}{end}`
		endpoints := map[string]string{}
		for _, ciliumPod := range pods {
			res := kub.ExecPodCmd(
				KubeSystemNamespace,
				ciliumPod,
				fmt.Sprintf("cilium endpoint list -o jsonpath='%s'", endpointFilter))
			for k, v := range res.KVOutput() {
				endpoints[k] = v
			}
		}
		cepCMD := fmt.Sprintf("%s get cep --all-namespaces -o jsonpath='%s'", KubectlCmd, cepFilter)
		res := kub.Exec(cepCMD)
		if !res.WasSuccessful() {
			return false
		}
		cepValues := res.KVOutput()
		for k, v := range endpoints {
			cepPolicy, ok := cepValues[k]
			if !ok {
				kub.logger.Infof("Endpoint '%s' is not present in cep", k)
				return false
			}
			if cepPolicy != v {
				kub.logger.Infof("Endpoint '%s' policies mismatch '%s'='%s'", k, cepPolicy, v)
				return false
			}
		}
		return true
	}
	return WithTimeout(body, "CEP not ready after timeout", &TimeoutConfig{Timeout: HelperTimeout})
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
func (kub *Kubectl) ExecPodCmd(namespace string, pod string, cmd string, options ...ExecOptions) *CmdRes {
	command := fmt.Sprintf("%s exec -n %s %s -- %s", KubectlCmd, namespace, pod, cmd)
	return kub.Exec(command, options...)
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

// GetCNP retrieves the output of `kubectl get cnp` in the given namespace for
// the given CNP and return a CNP struct. If the CNP does not exists or cannot
// unmarshal the Json output will return nil.
func (kub *Kubectl) GetCNP(namespace string, cnp string) *cnpv2.CiliumNetworkPolicy {
	log := kub.logger.WithFields(logrus.Fields{
		"fn":  "GetCNP",
		"cnp": cnp,
		"ns":  namespace,
	})
	res := kub.Get(namespace, fmt.Sprintf("cnp %s", cnp))
	if !res.WasSuccessful() {
		log.WithField("error", res.CombineOutput()).Info("cannot get CNP")
		return nil
	}
	var result cnpv2.CiliumNetworkPolicy
	err := res.Unmarshal(&result)
	if err != nil {
		log.WithError(err).Errorf("cannot unmarshal CNP output")
		return nil
	}
	return &result
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

// GetAllPods returns a slice of all pods present in Kubernetes cluster, along
// with an error if the pods could not be retrieved via `kubectl`, or if the
// pod objects are unable to be marshaled from JSON.
func (kub *Kubectl) GetAllPods(options ...ExecOptions) ([]v1.Pod, error) {
	var ops ExecOptions
	if len(options) > 0 {
		ops = options[0]
	}

	var podsList v1.List
	err := kub.Exec(
		fmt.Sprintf("%s get pods --all-namespaces -o json", KubectlCmd),
		ExecOptions{SkipLog: ops.SkipLog}).Unmarshal(&podsList)
	if err != nil {
		return nil, err
	}

	pods := make([]v1.Pod, len(podsList.Items))
	for _, item := range podsList.Items {
		var pod v1.Pod
		err = json.Unmarshal(item.Raw, &pod)
		if err != nil {
			return nil, err
		}
		pods = append(pods, pod)
	}

	return pods, nil
}

// GetPodNames returns the names of all of the pods that are labeled with label
// in the specified namespace, along with an error if the pod names cannot be
// retrieved.
func (kub *Kubectl) GetPodNames(namespace string, label string) ([]string, error) {
	stdout := new(bytes.Buffer)
	filter := "-o jsonpath='{.items[*].metadata.name}'"

	cmd := fmt.Sprintf("%s -n %s get pods -l %s %s", KubectlCmd, namespace, label, filter)

	err := kub.Execute(
		cmd, stdout, nil)

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

// MicroscopeStart installs (if it is not installed) a new microscope pod,
// waits until pod is ready, and runs microscope in background. It returns an
// error in the case where microscope cannot be installed, or it is not ready after
// a timeout. Also it returns a callback function to stop the monitor and save
// the output to `helpers.monitorLogFileName` file.
func (kub *Kubectl) MicroscopeStart() (error, func() error) {
	microscope := "microscope"
	var microscopeCmd = microscope + "| ts '[%Y-%m-%d %H:%M:%S]'"
	var cb = func() error { return nil }
	cmd := fmt.Sprintf("%[1]s -ti -n %[2]s exec %[3]s -- %[4]s",
		KubectlCmd, KubeSystemNamespace, microscope, microscopeCmd)
	_ = kub.Apply(microscopeManifest)

	err := kub.WaitforPods(
		KubeSystemNamespace,
		fmt.Sprintf("-l k8s-app=%s", microscope),
		300)
	if err != nil {
		return err, cb
	}

	ctx, cancel := context.WithCancel(context.Background())
	res := kub.ExecContext(ctx, cmd, ExecOptions{SkipLog: true})

	cb = func() error {
		cancel()
		<-ctx.Done()
		testPath, err := CreateReportDirectory()
		if err != nil {
			kub.logger.WithError(err).Errorf(
				"cannot create test results path '%s'", testPath)
			return err
		}

		err = WriteOrAppendToFile(
			filepath.Join(testPath, MonitorLogFileName),
			res.CombineOutput().Bytes(),
			LogPerm)
		if err != nil {
			log.WithError(err).Errorf("cannot create monitor log file")
			return err
		}
		kub.Delete(microscopeManifest)
		return nil
	}

	return nil, cb
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
func (kub *Kubectl) WaitforPods(namespace string, filter string, timeout time.Duration) error {
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
	return WithTimeout(body, "could not get Pods", &TimeoutConfig{Timeout: timeout})
}

// WaitForServiceEndpoints waits up until timeout seconds have elapsed for all
// endpoints in the specified namespace that match the provided JSONPath filter
// to have their port equal to the provided port. Returns true if all pods achieve
// the aforementioned desired state within timeout seconds. Returns false and
// an error if the command failed or the timeout was exceeded.
func (kub *Kubectl) WaitForServiceEndpoints(namespace string, filter string, service string, port string, timeout time.Duration) error {
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
			"service":   service,
			"port":      port,
		}).Info("WaitForServiceEndpoints: service endpoint not ready")
		return false
	}

	return WithTimeout(body, "could not get service endpoints", &TimeoutConfig{Timeout: timeout})
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
	return kub.WaitforPods(KubeSystemNamespace, fmt.Sprintf("-l %s", kubeDNSLabel), DNSHelperTimeout)
}

// WaitForKubeDNSEntry waits until the given DNS entry is ready in kube-dns
// pod. If the container is not ready after timeout it returns an error. The
// name's format query should be `${name}.${namespace}`. If `svc.cluster.local`
// is not present it appends to the given name and it checks  the full FQDN
func (kub *Kubectl) WaitForKubeDNSEntry(name string) error {
	svcSuffix := "svc.cluster.local"
	logger := kub.logger.WithField("dnsName", name)

	if !strings.HasSuffix(name, svcSuffix) {
		name = fmt.Sprintf("%s.%s", name, svcSuffix)
	}
	// https://bugs.launchpad.net/ubuntu/+source/bind9/+bug/854705
	digCMD := "dig +short %s @%s | grep -v -e '^;'"

	// If it fails we want to know if it's because of connection cannot be
	// established or DNS does not exist.
	digCMDFallback := "dig +tcp %s @%s"

	host, _, err := kub.GetServiceHostPort(KubeSystemNamespace, "kube-dns")
	if err != nil {
		logger.WithError(err).Error("cannot get kube-dns service IP")
		return err
	}

	body := func() bool {
		res := kub.Exec(fmt.Sprintf(digCMD, name, host))
		if !res.WasSuccessful() {
			_ = kub.Exec(fmt.Sprintf(digCMDFallback, name, host))
		}
		return res.WasSuccessful()
	}

	return WithTimeout(
		body,
		fmt.Sprintf("DNS %q is not ready after timeout", name),
		&TimeoutConfig{Timeout: DNSHelperTimeout})
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

// CiliumInstall receives a manifestName which needs to be in jsonnet format
// and will be used in `kubecfg show` and applied to Kubernetes. It will return
// a error if any action fails.
func (kub *Kubectl) CiliumInstall(manifestName string) error {
	ciliumDSManifest := ManifestGet(manifestName)
	// debugYaml only dumps the full created yaml file to the test output if
	// the cilium manifest can not be created correctly.
	debugYaml := func() {
		_ = kub.Exec(fmt.Sprintf("kubecfg show %s", ciliumDSManifest))
	}

	res := kub.Exec(fmt.Sprintf("kubecfg validate %s", ciliumDSManifest))
	if !res.WasSuccessful() {
		debugYaml()
		return fmt.Errorf(res.GetDebugMessage())
	}

	res = kub.Exec(fmt.Sprintf("kubecfg update %s", ciliumDSManifest))
	if !res.WasSuccessful() {
		debugYaml()
		return fmt.Errorf(res.GetDebugMessage())
	}
	return nil
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

// CiliumEndpointsStatus returns a mapping  of a pod name to it is corresponding
// endpoint's status
func (kub *Kubectl) CiliumEndpointsStatus(pod string) map[string]string {
	filter := `{range [*]}{@.status.external-identifiers.pod-name}{"="}{@.status.state}{"\n"}{end}`
	return kub.CiliumExec(pod, fmt.Sprintf(
		"cilium endpoint list -o jsonpath='%s'", filter)).KVOutput()
}

// CiliumEndpointWaitReady waits until all endpoints managed by all Cilium pod
// are ready. Returns an error if the Cilium pods cannot be retrieved via
// Kubernetes, or endpoints are not ready after a specified timeout
func (kub *Kubectl) CiliumEndpointWaitReady() error {
	ciliumPods, err := kub.GetCiliumPods(KubeSystemNamespace)
	if err != nil {
		kub.logger.WithError(err).Error("cannot get Cilium pods")
		return err
	}

	body := func() bool {
		for _, pod := range ciliumPods {
			logCtx := kub.logger.WithField("pod", pod)
			status, err := kub.CiliumEndpointsList(pod).Filter(`{range [*]}{.status.state}{"="}{.status.identity.id}{"\n"}{end}`)
			if err != nil {
				logCtx.WithError(err).Errorf("cannot get endpoints states on Cilium pod")
				return false
			}
			total := 0
			invalid := 0
			for _, line := range strings.Split(status.String(), "\n") {
				if line == "" {
					continue
				}
				// each line is like status=identityID.
				// IdentityID is needed because the reserved:init identity
				// means that the pod is not ready to accept traffic.
				total++
				vals := strings.Split(line, "=")
				if len(vals) != 2 {
					logCtx.Errorf("Endpoint list does not have a correct output '%s'", line)
					return false
				}
				if vals[0] != "ready" {
					invalid++
				}
				// Consider an endpoint with reserved identity 5 (reserved:init) as not ready.
				if vals[1] == "5" {
					invalid++
				}
			}
			logCtx.WithFields(logrus.Fields{
				"total":   total,
				"invalid": invalid,
			}).Info("Waiting for cilium endpoints to be ready")

			if invalid != 0 {
				return false
			}
		}
		return true
	}
	return WithTimeout(body, "cannot retrieve endpoints", &TimeoutConfig{Timeout: HelperTimeout})
}

// CiliumExec runs cmd in the specified Cilium pod.
func (kub *Kubectl) CiliumExec(pod string, cmd string) *CmdRes {
	limitTimes := 5
	execute := func() *CmdRes {
		command := fmt.Sprintf("%s exec -n kube-system %s -- %s", KubectlCmd, pod, cmd)
		return kub.Exec(command)
	}
	var res *CmdRes
	// Sometimes Kubectl returns 126 exit code, It use to happen in Nightly
	// tests when a lot of exec are in place (Cgroups issue). The upstream
	// changes did not fix the isse, and we need to make this workaround to
	// avoid Kubectl issue.
	// https://github.com/openshift/origin/issues/16246
	for i := 0; i < limitTimes; i++ {
		res = execute()
		if res.GetExitCode() != 126 {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	return res
}

// CiliumExecUntilMatch executes the specified command repeatedly for the
// specified Cilium pod until the given substring is present in stdout.
// If the timeout is reached it will return an error.
func (kub *Kubectl) CiliumExecUntilMatch(pod, cmd, substr string) error {
	body := func() bool {
		res := kub.CiliumExec(pod, cmd)
		return strings.Contains(res.Output().String(), substr)
	}

	return WithTimeout(
		body,
		fmt.Sprintf("%s is not in the output after timeout", substr),
		&TimeoutConfig{Timeout: HelperTimeout})
}

// CiliumExecAll runs cmd in all cilium instances
func (kub *Kubectl) CiliumExecAll(cmd string) error {
	pods, err := kub.GetCiliumPods(KubeSystemNamespace)
	if err != nil {
		return err
	}
	if len(pods) == 0 {
		return fmt.Errorf("No cilium pods available")
	}

	for _, pod := range pods {
		res := kub.CiliumExec(pod, cmd)
		if !res.WasSuccessful() {
			return fmt.Errorf("Command failed on %s: %s", pod, res.CombineOutput())
		}
	}
	return nil
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

// CiliumIsPolicyLoaded returns true if the policy is loaded in the given
// cilium Pod. it returns false in case that the policy is not in place
func (kub *Kubectl) CiliumIsPolicyLoaded(pod string, policyCmd string) bool {
	res := kub.CiliumExec(pod, fmt.Sprintf("cilium policy get %s", policyCmd))
	return res.WasSuccessful()
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
				res := kub.CiliumExec(pod, fmt.Sprintf("cilium policy wait %d", rev))
				if !res.WasSuccessful() {
					return false
				}
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
func (kub *Kubectl) CiliumReport(namespace string, commands ...string) {
	if config.CiliumTestConfig.HoldEnvironment {
		ginkgoext.GinkgoPrint("Skipped gathering logs (-cilium.holdEnvironment=true)\n")
		return
	}

	pods, err := kub.GetCiliumPods(namespace)
	if err != nil {
		kub.logger.WithError(err).Error("cannot retrieve cilium pods on ReportDump")
		return
	}
	res := kub.Exec(fmt.Sprintf("%s get pods -o wide --all-namespaces", KubectlCmd))
	ginkgoext.GinkgoPrint(res.GetDebugMessage())

	for _, pod := range pods {
		for _, cmd := range commands {
			res = kub.ExecPodCmd(namespace, pod, cmd, ExecOptions{SkipLog: true})
			ginkgoext.GinkgoPrint(res.GetDebugMessage())
		}
	}

	kub.DumpCiliumCommandOutput(namespace)
	kub.GatherLogs()
}

// ValidateNoErrorsOnLogs checks in cilium logs since the given duration (By
// default `CurrentGinkgoTestDescription().Duration`) do not contain `panic`,
// `deadlocks` or `segmentation faults` messages. In case of any of these
// messages, it'll mark the test as failed.
func (kub *Kubectl) ValidateNoErrorsOnLogs(duration time.Duration) {
	var logs string
	cmd := fmt.Sprintf("%s -n %s logs --timestamps=true -l k8s-app=cilium --since=%vs",
		KubectlCmd, KubeSystemNamespace, duration.Seconds())
	res := kub.Exec(fmt.Sprintf("%s --previous", cmd), ExecOptions{SkipLog: true})
	if res.WasSuccessful() {
		logs += res.Output().String()
	}
	res = kub.Exec(cmd, ExecOptions{SkipLog: true})
	if res.WasSuccessful() {
		logs += res.Output().String()
	}

	for _, message := range checkLogsMessages {
		if strings.Contains(logs, message) {
			fmt.Fprintf(CheckLogs, "Found a %q in logs", message)
			ginkgoext.Fail(fmt.Sprintf("Found a %q in Cilium Logs", message))
		}
	}
}

// GatherCiliumCoreDumps copies core dumps if are present in the /tmp folder
// into the test report folder for further analysis.
func (kub *Kubectl) GatherCiliumCoreDumps(ciliumPod string) {
	log := kub.logger.WithField("pod", ciliumPod)

	cores := kub.CiliumExec(ciliumPod, "ls /tmp/ | grep core")
	if !cores.WasSuccessful() {
		log.Debug("There is no core dumps in the pod")
		return
	}

	testPath, err := CreateReportDirectory()
	if err != nil {
		log.WithError(err).Errorf("cannot create test result path '%s'", testPath)
		return
	}
	resultPath := filepath.Join(BasePath, testPath)

	for _, core := range cores.ByLines() {
		dst := filepath.Join(resultPath, core)
		src := filepath.Join("/tmp/", core)
		cmd := fmt.Sprintf("%s -n %s cp %s:%s %s",
			KubectlCmd, KubeSystemNamespace,
			ciliumPod, src, dst)
		res := kub.Exec(cmd, ExecOptions{SkipLog: true})
		if !res.WasSuccessful() {
			log.WithField("output", res.CombineOutput()).Error("Cannot get core from pod")
		}
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
		if !res.WasSuccessful() {
			logger.Errorf("%s failed: %s", bugtoolCmd, res.CombineOutput().String())
			return
		}
		// Default output directory is /tmp for bugtool.
		res = kub.Exec(fmt.Sprintf("%s exec -n %s %s -- ls /tmp/", KubectlCmd, namespace, pod))
		tmpList := res.ByLines()
		for _, line := range tmpList {
			// Only copy over bugtool output to directory.
			if !strings.Contains(line, CiliumBugtool) {
				continue
			}

			res = kub.Exec(fmt.Sprintf("%[1]s cp %[2]s/%[3]s:/tmp/%[4]s /tmp/%[4]s",
				KubectlCmd, namespace, pod, line),
				ExecOptions{SkipLog: true})
			if !res.WasSuccessful() {
				logger.Errorf("'%s' failed: %s", res.GetCmd(), res.CombineOutput())
				continue
			}

			archiveName := filepath.Join(logsPath, fmt.Sprintf("bugtool-%s", pod))
			res = kub.Exec(fmt.Sprintf("mkdir -p %s", archiveName))
			if !res.WasSuccessful() {
				logger.WithField("cmd", res.GetCmd()).Errorf(
					"cannot create bugtool archive folder: %s", res.CombineOutput())
				continue
			}

			cmd := fmt.Sprintf("tar -xf /tmp/%s -C %s --strip-components=1", line, archiveName)
			res = kub.Exec(cmd, ExecOptions{SkipLog: true})
			if !res.WasSuccessful() {
				logger.WithField("cmd", cmd).Errorf(
					"Cannot untar bugtool output: %s", res.CombineOutput())
				continue
			}
			//Remove bugtool artifact, so it'll be not used if any other fail test
			_ = kub.ExecPodCmd(KubeSystemNamespace, pod, fmt.Sprintf("rm /tmp/%s", line))
		}
	}

	pods, err := kub.GetCiliumPods(namespace)
	if err != nil {
		kub.logger.WithError(err).Error("cannot retrieve cilium pods on ReportDump")
		return
	}
	for _, pod := range pods {
		ReportOnPod(pod)
		kub.GatherCiliumCoreDumps(pod)
	}
}

// GatherLogs dumps kubernetes pods, services, DaemonSet to the testResultsPath
// directory
func (kub *Kubectl) GatherLogs() {
	reportCmds := map[string]string{
		"kubectl get pods --all-namespaces -o json":                  "pods.txt",
		"kubectl get services --all-namespaces -o json":              "svc.txt",
		"kubectl get nodes -o json":                                  "nodes.txt",
		"kubectl get ds --all-namespaces -o json":                    "ds.txt",
		"kubectl get cnp --all-namespaces -o json":                   "cnp.txt",
		"kubectl get cep --all-namespaces -o json":                   "cep.txt",
		"kubectl get netpol --all-namespaces -o json":                "netpol.txt",
		"kubectl describe pods --all-namespaces":                     "pods_status.txt",
		"kubectl get replicationcontroller --all-namespaces -o json": "replicationcontroller.txt",
		"kubectl get deployment --all-namespaces -o json":            "deployment.txt",
	}

	kub.GeneratePodLogGatheringCommands(reportCmds)

	testPath, err := CreateReportDirectory()
	if err != nil {
		kub.logger.WithError(err).Errorf(
			"cannot create test results path '%s'", testPath)
		return
	}
	reportMap(testPath, reportCmds, kub.SSHMeta)

	for _, node := range []string{K8s1VMName(), K8s2VMName()} {
		vm := GetVagrantSSHMeta(node)
		reportCmds := map[string]string{
			"journalctl --no-pager -au kubelet": fmt.Sprintf("kubelet-%s.log", node),
			"sudo top -n 1":                     fmt.Sprintf("top-%s.log", node),
			"sudo ps aux":                       fmt.Sprintf("ps-%s.log", node),
		}
		reportMap(testPath, reportCmds, vm)
	}
}

// GeneratePodLogGatheringCommands generates the commands to gather logs for
// all pods in the Kubernetes cluster, and maps the commands to the filename
// in which they will be stored in reportCmds.
func (kub *Kubectl) GeneratePodLogGatheringCommands(reportCmds map[string]string) {
	if reportCmds == nil {
		reportCmds = make(map[string]string)
	}
	pods, err := kub.GetAllPods(ExecOptions{SkipLog: true})
	if err != nil {
		kub.logger.WithError(err).Error("Unable to get pods from Kubernetes via kubectl")
	}

	for _, pod := range pods {
		for _, containerStatus := range pod.Status.ContainerStatuses {
			logCmd := fmt.Sprintf("%s -n %s logs --timestamps %s -c %s", KubectlCmd, pod.Namespace, pod.Name, containerStatus.Name)
			logfileName := fmt.Sprintf("pod-%s-%s-%s.log", pod.Namespace, pod.Name, containerStatus.Name)
			reportCmds[logCmd] = logfileName

			if containerStatus.RestartCount > 0 {
				previousLogCmd := fmt.Sprintf("%s -n %s logs --timestamps %s -c %s --previous", KubectlCmd, pod.Namespace, pod.Name, containerStatus.Name)
				previousLogfileName := fmt.Sprintf("pod-%s-%s-%s-previous.log", pod.Namespace, pod.Name, containerStatus.Name)
				reportCmds[previousLogCmd] = previousLogfileName
			}
		}
	}
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

// CiliumPreFlightCheck specify that it checks that various subsystems within
// Cilium are in a good state. If one of the multiple preflight fails it'll
// return an error.
func (kub *Kubectl) CiliumPreFlightCheck() error {
	// Doing this withTimeout because the Status can be ready, but the other
	// nodes cannot be show up yet, and the cilium-health can fail as a false positive.
	var err error
	body := func() bool {
		err = kub.CiliumControllersPreFlightCheck()
		if err != nil {
			return false
		}
		err = kub.CiliumHealthPreFlightCheck()
		if err != nil {
			return false
		}
		return true
	}
	timeoutErr := WithTimeout(body, "PreflightCheck failed", &TimeoutConfig{Timeout: HelperTimeout})
	if timeoutErr != nil {
		return fmt.Errorf("CiliumPreFlightCheck error: %s: %s", timeoutErr, err)
	}
	return nil
}

// CiliumControllersPreFlightCheck validates that all controllers are not
// failing. If any of the controllers fails will return an error.
func (kub *Kubectl) CiliumControllersPreFlightCheck() error {
	var controllersFilter = `{range .controllers[*]}{.name}{"="}{.status.consecutive-failure-count}{"\n"}{end}`
	ciliumPods, err := kub.GetCiliumPods(KubeSystemNamespace)
	if err != nil {
		return err
	}
	for _, pod := range ciliumPods {
		status := kub.CiliumExec(pod, fmt.Sprintf(
			"cilium status --all-controllers -o jsonpath='%s'", controllersFilter))
		if !status.WasSuccessful() {
			return fmt.Errorf("cilium-agent %q: Cannot run cilium status: %s",
				pod, status.OutputPrettyPrint())
		}
		for controller, status := range status.KVOutput() {
			if status != "0" {
				failmsg := kub.CiliumExec(pod, "cilium status --all-controllers")
				return fmt.Errorf(
					"cilium-agent %q: controller %s is failing: %s",
					pod, controller, failmsg.OutputPrettyPrint())
			}
		}
	}
	return nil
}

// CiliumHealthPreFlightCheck checks that the health status is working
// correctly and the number of nodes does not mistmatch with the running pods.
// It return an error if health mark a node as failed.
func (kub *Kubectl) CiliumHealthPreFlightCheck() error {
	var nodesFilter = `{.nodes[*].name}`
	var statusFilter = `{range .nodes[*]}{.name}{"="}{.host.primary-address.http.status}{"\n"}{end}`

	ciliumPods, err := kub.GetCiliumPods(KubeSystemNamespace)
	if err != nil {
		return err
	}
	for _, pod := range ciliumPods {
		status := kub.CiliumExec(pod, "cilium-health status -o json --probe")
		if !status.WasSuccessful() {
			return fmt.Errorf(
				"Cluster connectivity is unhealthy on %q: %s",
				pod, status.OutputPrettyPrint())
		}

		// By Checking that the node list is the same
		nodes, err := status.Filter(nodesFilter)
		if err != nil {
			return fmt.Errorf("Cannot unmarshal health status: %s", err)
		}

		nodeCount := strings.Split(nodes.String(), " ")
		if len(ciliumPods) != len(nodeCount) {
			return fmt.Errorf(
				"cilium-agent %q: Only %d/%d nodes appeared in cilium-health status. nodes = '%+v'",
				pod, len(nodeCount), len(ciliumPods), nodeCount)
		}

		healthStatus, err := status.Filter(statusFilter)
		if err != nil {
			return fmt.Errorf("Cannot unmarshal health status: %s", err)
		}

		for node, status := range healthStatus.KVOutput() {
			if status != "" {
				return fmt.Errorf("cilium-agent %q: connectivity to node %q is unhealthy: %q",
					pod, node, status)
			}
		}
	}
	return nil
}
