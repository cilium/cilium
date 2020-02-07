// Copyright 2018-2019 Authors of Cilium
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
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/annotation"
	cnpv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/test/config"
	ginkgoext "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers/logutils"

	"github.com/asaskevich/govalidator"
	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
)

const (
	// KubectlCmd Kubernetes controller command
	KubectlCmd      = "kubectl"
	manifestsPath   = "k8sT/manifests/"
	descriptorsPath = "../examples/kubernetes"
	kubeDNSLabel    = "k8s-app=kube-dns"

	// DNSHelperTimeout is a predefined timeout value for K8s DNS commands. It
	// must be larger than 5 minutes because kubedns has a hardcoded resync
	// period of 5 minutes. We have experienced test failures because kubedns
	// needed this time to recover from a connection problem to kube-apiserver.
	// The kubedns resyncPeriod is defined at
	// https://github.com/kubernetes/dns/blob/80fdd88276adba36a87c4f424b66fdf37cd7c9a8/pkg/dns/dns.go#L53
	DNSHelperTimeout = 7 * time.Minute

	// CIIntegrationFlannel contains the constant to be used when flannel is
	// used in the CI.
	CIIntegrationFlannel = "flannel"

	// CIIntegrationEKS contains the constants to be used when running tests on EKS.
	CIIntegrationEKS = "eks"

	// CIIntegrationGKE contains the constants to be used when running tests on GKE.
	CIIntegrationGKE = "gke"

	// CIIntegrationMicrok8s contains the constant to be used when running tests on microk8s.
	CIIntegrationMicrok8s = "microk8s"

	// CIIntegrationMicrok8s is the value to set CNI_INTEGRATION when running with minikube.
	CIIntegrationMinikube = "minikube"

	LogGathererSelector = "k8s-app=cilium-test-logs"
	CiliumSelector      = "k8s-app=cilium"
)

var (
	// defaultHelmOptions are passed to helm in ciliumInstallHelm, unless
	// overridden by options passed in at invocation. In those cases, the test
	// has a specific need to override the option.
	// These defaults are made to match some environment variables in init(),
	// below. These overrides represent a desire to set the default for all
	// tests, instead of test-specific variations.
	defaultHelmOptions = map[string]string{
		"global.registry":               "k8s1:5000/cilium",
		"agent.image":                   "cilium-dev",
		"global.tag":                    "latest",
		"operator.image":                "operator",
		"managed-etcd.registry":         "docker.io/cilium",
		"global.debug.enabled":          "true",
		"global.k8s.requireIPv4PodCIDR": "true",
		"global.pprof.enabled":          "true",
		"global.logSystemLoad":          "true",
		"global.bpf.preallocateMaps":    "true",
		"global.etcd.leaseTTL":          "30s",
		"global.ipv4.enabled":           "true",
		"global.ipv6.enabled":           "true",
	}

	flannelHelmOverrides = map[string]string{
		"global.flannel.enabled": "true",
		"global.ipv6.enabled":    "false",
		"global.tunnel":          "disabled",
	}

	eksHelmOverrides = map[string]string{
		"global.k8s.requireIPv4PodCIDR": "false",
		"global.cni.chainingMode":       "aws-cni",
		"global.masquerade":             "false",
		"global.tunnel":                 "disabled",
		"global.nodeinit.enabled":       "true",
	}

	gkeHelmOverrides = map[string]string{
		"global.ipv6.enabled":         "false",
		"global.nodeinit.enabled":     "true",
		"nodeinit.reconfigureKubelet": "true",
		"nodeinit.removeCbrBridge":    "true",
		"global.cni.binPath":          "/home/kubernetes/bin",
	}

	microk8sHelmOverrides = map[string]string{
		"global.cni.confPath":                 "/var/snap/microk8s/current/args/cni-network",
		"global.cni.binPath":                  "/var/snap/microk8s/current/opt/cni/bin",
		"global.cni.customConf":               "true",
		"global.containerRuntime.integration": "containerd",
		"global.containerRuntime.socketPath":  "/var/snap/microk8s/common/run/containerd.sock",
		"global.daemon.runPath":               "/var/snap/microk8s/current/var/run/cilium",
	}
	minikubeHelmOverrides = map[string]string{
		"global.ipv6.enabled":           "false",
		"global.bpf.preallocateMaps":    "false",
		"global.k8s.requireIPv4PodCIDR": "false",
	}

	// helmOverrides allows overriding of cilium-agent options for
	// specific CI environment integrations.
	// The key must be a string consisting of lower case characters.
	helmOverrides = map[string]map[string]string{
		CIIntegrationFlannel:  flannelHelmOverrides,
		CIIntegrationEKS:      eksHelmOverrides,
		CIIntegrationGKE:      gkeHelmOverrides,
		CIIntegrationMicrok8s: microk8sHelmOverrides,
		CIIntegrationMinikube: minikubeHelmOverrides,
	}
)

func init() {
	// Copy over envronment variables that are passed in.
	for envVar, helmVar := range map[string]string{
		"CILIUM_REGISTRY":       "global.registry",
		"CILIUM_TAG":            "global.tag",
		"CILIUM_IMAGE":          "agent.image",
		"CILIUM_OPERATOR_IMAGE": "operator.image",
	} {
		if v := os.Getenv(envVar); v != "" {
			defaultHelmOptions[helmVar] = v
		}
	}
}

// GetCurrentK8SEnv returns the value of K8S_VERSION from the OS environment.
func GetCurrentK8SEnv() string { return os.Getenv("K8S_VERSION") }

// GetCurrentIntegration returns CI integration set up to run against Cilium.
func GetCurrentIntegration() string {
	integration := strings.ToLower(os.Getenv("CNI_INTEGRATION"))
	if _, exists := helmOverrides[integration]; exists {
		return integration
	}
	return ""
}

// IsIntegration returns true when integration matches the configuration of
// this test run
func IsIntegration(integration string) bool {
	return GetCurrentIntegration() == integration
}

// GetCiliumNamespace returns the namespace into which cilium should be
// installed for this integration.
func GetCiliumNamespace(integration string) string {
	switch integration {
	case CIIntegrationGKE:
		return CiliumNamespaceGKE
	default:
		return CiliumNamespaceDefault
	}
}

// Kubectl is a wrapper around an SSHMeta. It is used to run Kubernetes-specific
// commands on the node which is accessible via the SSH metadata stored in its
// SSHMeta.
type Kubectl struct {
	Executor
	*serviceCache
}

// CreateKubectl initializes a Kubectl helper with the provided vmName and log
// It marks the test as Fail if cannot get the ssh meta information or cannot
// execute a `ls` on the virtual machine.
func CreateKubectl(vmName string, log *logrus.Entry) (k *Kubectl) {
	if config.CiliumTestConfig.Kubeconfig == "" {
		node := GetVagrantSSHMeta(vmName)
		if node == nil {
			ginkgoext.Fail(fmt.Sprintf("Cannot connect to vmName  '%s'", vmName), 1)
			return nil
		}
		// This `ls` command is a sanity check, sometimes the meta ssh info is not
		// nil but new commands cannot be executed using SSH, tests failed and it
		// was hard to debug.
		res := node.ExecShort("ls /tmp/")
		if !res.WasSuccessful() {
			ginkgoext.Fail(fmt.Sprintf(
				"Cannot execute ls command on vmName '%s'", vmName), 1)
			return nil
		}
		node.logger = log

		k = &Kubectl{
			Executor: node,
		}
		k.setBasePath()
	} else {
		// Prepare environment variables
		// NOTE: order matters and we want the KUBECONFIG from config to win
		var environ []string
		if config.CiliumTestConfig.PassCLIEnvironment {
			environ = append(environ, os.Environ()...)
		}
		environ = append(environ, "KUBECONFIG="+config.CiliumTestConfig.Kubeconfig)

		// Create the executor
		exec := CreateLocalExecutor(environ)
		exec.logger = log

		k = &Kubectl{
			Executor: exec,
		}
		k.setBasePath()
	}

	// config flags are already parsed here
	if config.CiliumTestConfig.Registry != "" {
		defaultHelmOptions["global.registry"] = config.CiliumTestConfig.Registry + "/cilium"
	}

	res := k.Apply(ApplyOptions{FilePath: filepath.Join(k.BasePath(), manifestsPath, "log-gatherer.yaml"), Namespace: LogGathererNamespace})

	if !res.WasSuccessful() {
		ginkgoext.Fail(fmt.Sprintf("Cannot connect to k8s cluster, output:\n%s", res.CombineOutput().String()), 1)
		return nil
	}

	return k
}

// LabelNodes labels nodes in vagrant env. If you are running tests on different cluster you need to label your nodes by yourself
func (kub *Kubectl) LabelNodes() {
	kub.ExecMiddle(fmt.Sprintf("%s label --overwrite node k8s1 cilium.io/ci-node=k8s1", KubectlCmd))
	kub.ExecMiddle(fmt.Sprintf("%s label --overwrite node k8s2 cilium.io/ci-node=k8s2", KubectlCmd))
	kub.ExecMiddle(fmt.Sprintf("%s label --overwrite node k8s3 cilium.io/ci-node=k8s3", KubectlCmd))

	node := GetNodeWithoutCilium()
	if node != "" {
		// Prevent scheduling any pods on the node, as it will be used as an external client
		// to send requests to k8s{1,2}
		kub.ExecMiddle(fmt.Sprintf("%s taint nodes %s key=value:NoSchedule", KubectlCmd, node))
	}
}

// CepGet returns the endpoint model for the given pod name in the specified
// namespaces. If the pod is not present it returns nil
func (kub *Kubectl) CepGet(namespace string, pod string) *cnpv2.EndpointStatus {
	log := kub.Logger().WithFields(logrus.Fields{
		"cep":       pod,
		"namespace": namespace})

	cmd := fmt.Sprintf("%s -n %s get cep %s -o json | jq '.status'", KubectlCmd, namespace, pod)
	res := kub.ExecShort(cmd)
	if !res.WasSuccessful() {
		log.Debug("cep is not present")
		return nil
	}

	var data *cnpv2.EndpointStatus
	err := res.Unmarshal(&data)
	if err != nil {
		log.WithError(err).Error("cannot Unmarshal json")
		return nil
	}
	return data
}

// GetNumCiliumNodes returns the number of Kubernetes nodes running cilium
func (kub *Kubectl) GetNumCiliumNodes() int {
	getNodesCmd := fmt.Sprintf("%s get nodes -o jsonpath='{.items.*.metadata.name}'", KubectlCmd)
	res := kub.ExecShort(getNodesCmd)
	if !res.WasSuccessful() {
		return 0
	}
	sub := 0
	if ExistNodeWithoutCilium() {
		sub = 1
	}

	return len(strings.Split(res.SingleOut(), " ")) - sub
}

// CreateSecret is a wrapper around `kubernetes create secret
// <resourceName>.
func (kub *Kubectl) CreateSecret(secretType, name, namespace, args string) *CmdRes {
	kub.Logger().Debug(fmt.Sprintf("creating secret %s in namespace %s", name, namespace))
	kub.ExecShort(fmt.Sprintf("kubectl delete secret %s %s -n %s", secretType, name, namespace))
	return kub.ExecShort(fmt.Sprintf("kubectl create secret %s %s -n %s %s", secretType, name, namespace, args))
}

// CopyFileToPod copies a file to a pod's file-system.
func (kub *Kubectl) CopyFileToPod(namespace string, pod string, fromFile, toFile string) *CmdRes {
	kub.Logger().Debug(fmt.Sprintf("copyiong file %s to pod %s/%s:%s", fromFile, namespace, pod, toFile))
	return kub.Exec(fmt.Sprintf("%s cp %s %s/%s:%s", KubectlCmd, fromFile, namespace, pod, toFile))
}

// ExecKafkaPodCmd executes shell command with arguments arg in the specified pod residing in the specified
// namespace. It returns the stdout of the command that was executed.
// The kafka producer and consumer scripts do not return error if command
// leads to TopicAuthorizationException or any other error. Hence the
// function needs to also take into account the stderr messages returned.
func (kub *Kubectl) ExecKafkaPodCmd(namespace string, pod string, arg string) error {
	command := fmt.Sprintf("%s exec -n %s %s sh -- %s", KubectlCmd, namespace, pod, arg)
	res := kub.Exec(command)
	if !res.WasSuccessful() {
		return fmt.Errorf("ExecKafkaPodCmd: command '%s' failed %s",
			res.GetCmd(), res.OutputPrettyPrint())
	}

	if strings.Contains(res.GetStdErr(), "ERROR") {
		return fmt.Errorf("ExecKafkaPodCmd: command '%s' failed '%s'",
			res.GetCmd(), res.OutputPrettyPrint())
	}
	return nil
}

// ExecPodCmd executes command cmd in the specified pod residing in the specified
// namespace. It returns a pointer to CmdRes with all the output
func (kub *Kubectl) ExecPodCmd(namespace string, pod string, cmd string, options ...ExecOptions) *CmdRes {
	command := fmt.Sprintf("%s exec -n %s %s -- %s", KubectlCmd, namespace, pod, cmd)
	return kub.Exec(command, options...)
}

// ExecPodContainerCmd executes command cmd in the specified container residing
// in the specified namespace and pod. It returns a pointer to CmdRes with all
// the output
func (kub *Kubectl) ExecPodContainerCmd(namespace, pod, container, cmd string, options ...ExecOptions) *CmdRes {
	command := fmt.Sprintf("%s exec -n %s %s -c %s -- %s", KubectlCmd, namespace, pod, container, cmd)
	return kub.Exec(command, options...)
}

// ExecPodCmdContext synchronously executes command cmd in the specified pod residing in the
// specified namespace. It returns a pointer to CmdRes with all the output.
func (kub *Kubectl) ExecPodCmdContext(ctx context.Context, namespace string, pod string, cmd string, options ...ExecOptions) *CmdRes {
	command := fmt.Sprintf("%s exec -n %s %s -- %s", KubectlCmd, namespace, pod, cmd)
	return kub.ExecContext(ctx, command, options...)
}

// ExecPodCmdBackground executes command cmd in background in the specified pod residing
// in the specified namespace. It returns a pointer to CmdRes with all the
// output
//
// To receive the output of this function, the caller must invoke either
// kub.WaitUntilFinish() or kub.WaitUntilMatch() then subsequently fetch the
// output out of the result.
func (kub *Kubectl) ExecPodCmdBackground(ctx context.Context, namespace string, pod string, cmd string, options ...ExecOptions) *CmdRes {
	command := fmt.Sprintf("%s exec -n %s %s -- %s", KubectlCmd, namespace, pod, cmd)
	return kub.ExecInBackground(ctx, command, options...)
}

// Get retrieves the provided Kubernetes objects from the specified namespace.
func (kub *Kubectl) Get(namespace string, command string) *CmdRes {
	return kub.ExecShort(fmt.Sprintf(
		"%s -n %s get %s -o json", KubectlCmd, namespace, command))
}

// GetFromAllNS retrieves provided Kubernetes objects from all namespaces
func (kub *Kubectl) GetFromAllNS(kind string) *CmdRes {
	return kub.ExecShort(fmt.Sprintf(
		"%s get %s --all-namespaces -o json", KubectlCmd, kind))
}

// GetCNP retrieves the output of `kubectl get cnp` in the given namespace for
// the given CNP and return a CNP struct. If the CNP does not exists or cannot
// unmarshal the Json output will return nil.
func (kub *Kubectl) GetCNP(namespace string, cnp string) *cnpv2.CiliumNetworkPolicy {
	log := kub.Logger().WithFields(logrus.Fields{
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

func (kub *Kubectl) WaitForCRDCount(filter string, count int, timeout time.Duration) error {
	// Set regexp flag m for multi-line matching, then add the
	// matches for beginning and end of a line, so that we count
	// at most one match per line (like "grep <filter> | wc -l")
	regex := regexp.MustCompile("(?m:^.*(?:" + filter + ").*$)")
	body := func() bool {
		res := kub.ExecShort(fmt.Sprintf("%s get crds", KubectlCmd))
		if !res.WasSuccessful() {
			log.Error(res.GetErr("kubectl get crds failed"))
			return false
		}
		return len(regex.FindAllString(res.GetStdOut(), -1)) == count
	}
	return WithTimeout(
		body,
		fmt.Sprintf("timed out waiting for %d CRDs matching filter \"%s\" to be ready", count, filter),
		&TimeoutConfig{Timeout: timeout})
}

// GetPods gets all of the pods in the given namespace that match the provided
// filter.
func (kub *Kubectl) GetPods(namespace string, filter string) *CmdRes {
	return kub.ExecShort(fmt.Sprintf("%s -n %s get pods %s -o json", KubectlCmd, namespace, filter))
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

// GetSvcIP returns the cluster IP for the given service. If the service
// does not contain a cluster IP, the function keeps retrying until it has or
// the context timesout.
func (kub *Kubectl) GetSvcIP(ctx context.Context, namespace, name string) (string, error) {
	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		default:
		}
		jsonFilter := `{.spec.clusterIP}`
		res := kub.ExecContext(ctx, fmt.Sprintf("%s -n %s get svc %s -o jsonpath='%s'",
			KubectlCmd, namespace, name, jsonFilter))
		if !res.WasSuccessful() {
			return "", fmt.Errorf("cannot retrieve pods: %s", res.CombineOutput())
		}
		clusterIP := res.CombineOutput().String()
		if clusterIP != "" {
			return clusterIP, nil
		}
		time.Sleep(time.Second)
	}
}

// GetPodsIPs returns a map with pod name as a key and pod IP name as value. It
// only gets pods in the given namespace that match the provided filter. It
// returns an error if pods cannot be retrieved correctly
func (kub *Kubectl) GetPodsIPs(namespace string, filter string) (map[string]string, error) {
	jsonFilter := `{range .items[*]}{@.metadata.name}{"="}{@.status.podIP}{"\n"}{end}`
	res := kub.ExecShort(fmt.Sprintf("%s -n %s get pods -l %s -o jsonpath='%s'",
		KubectlCmd, namespace, filter, jsonFilter))
	if !res.WasSuccessful() {
		return nil, fmt.Errorf("cannot retrieve pods: %s", res.CombineOutput())
	}
	return res.KVOutput(), nil
}

// GetEndpoints gets all of the endpoints in the given namespace that match the
// provided filter.
func (kub *Kubectl) GetEndpoints(namespace string, filter string) *CmdRes {
	return kub.ExecShort(fmt.Sprintf("%s -n %s get endpoints %s -o json", KubectlCmd, namespace, filter))
}

// GetAllPods returns a slice of all pods present in Kubernetes cluster, along
// with an error if the pods could not be retrieved via `kubectl`, or if the
// pod objects are unable to be marshaled from JSON.
func (kub *Kubectl) GetAllPods(ctx context.Context, options ...ExecOptions) ([]v1.Pod, error) {
	var ops ExecOptions
	if len(options) > 0 {
		ops = options[0]
	}

	getPodsCtx, cancel := context.WithTimeout(ctx, ShortCommandTimeout)
	defer cancel()

	var podsList v1.List
	err := kub.ExecContext(getPodsCtx,
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
	ctx, cancel := context.WithTimeout(context.Background(), ShortCommandTimeout)
	defer cancel()
	return kub.GetPodNamesContext(ctx, namespace, label)
}

// GetPodNamesContext returns the names of all of the pods that are labeled with
// label in the specified namespace, along with an error if the pod names cannot
// be retrieved.
func (kub *Kubectl) GetPodNamesContext(ctx context.Context, namespace string, label string) ([]string, error) {
	stdout := new(bytes.Buffer)
	filter := "-o jsonpath='{.items[*].metadata.name}'"

	cmd := fmt.Sprintf("%s -n %s get pods -l %s %s", KubectlCmd, namespace, label, filter)

	// Taking more than 30 seconds to get pods means that something is wrong
	// connecting to the node.
	podNamesCtx, cancel := context.WithTimeout(ctx, ShortCommandTimeout)
	defer cancel()
	err := kub.ExecuteContext(podNamesCtx, cmd, stdout, nil)

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

// GetNodeNameByLabel returns the names of the node with a matching cilium.io/ci-node label
func (kub *Kubectl) GetNodeNameByLabel(label string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), ShortCommandTimeout)
	defer cancel()
	return kub.GetNodeNameByLabelContext(ctx, label)
}

// GetNodeNameByLabelContext returns the names of all nodes with a matching label
func (kub *Kubectl) GetNodeNameByLabelContext(ctx context.Context, label string) (string, error) {
	filter := `{.items[*].metadata.name}`

	res := kub.ExecShort(fmt.Sprintf("%s get nodes -l cilium.io/ci-node=%s -o jsonpath='%s'",
		KubectlCmd, label, filter))
	if !res.WasSuccessful() {
		return "", fmt.Errorf("cannot retrieve node to read name: %s", res.CombineOutput())
	}

	out := strings.Trim(res.GetStdOut(), "\n")

	if len(out) == 0 {
		return "", fmt.Errorf("no matching node to read name with label '%v'", label)
	}

	return out, nil
}

// GetNodeIPByLabel returns the IP of the node with cilium.io/ci-node=label.
// An error is returned if a node cannot be found.
func (kub *Kubectl) GetNodeIPByLabel(label string) (string, error) {
	filter := `{@.items[*].status.addresses[?(@.type == "InternalIP")].address}`
	res := kub.ExecShort(fmt.Sprintf("%s get nodes -l cilium.io/ci-node=%s -o jsonpath='%s'",
		KubectlCmd, label, filter))
	if !res.WasSuccessful() {
		return "", fmt.Errorf("cannot retrieve node to read IP: %s", res.CombineOutput())
	}

	out := strings.Trim(res.GetStdOut(), "\n")
	if len(out) == 0 {
		return "", fmt.Errorf("no matching node to read IP with label '%v'", label)
	}

	return out, nil
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
		return "", 0, fmt.Errorf("Service '%s' does not have ports defined", service)
	}
	return data.Spec.ClusterIP, int(data.Spec.Ports[0].Port), nil
}

// GetLoadBalancerIP waits until a loadbalancer IP addr has been assigned for
// the given service, and then returns the IP addr.
func (kub *Kubectl) GetLoadBalancerIP(namespace string, service string, timeout time.Duration) (string, error) {
	var data v1.Service

	body := func() bool {
		err := kub.Get(namespace, fmt.Sprintf("service %s", service)).Unmarshal(&data)
		if err != nil {
			kub.Logger().WithError(err)
			return false
		}

		if len(data.Status.LoadBalancer.Ingress) != 0 {
			return true
		}

		kub.Logger().WithFields(logrus.Fields{
			"namespace": namespace,
			"service":   service,
		}).Info("GetLoadBalancerIP: loadbalancer IP was not assigned")

		return false
	}

	err := WithTimeout(body, "could not get service LoadBalancer IP addr",
		&TimeoutConfig{Timeout: timeout})
	if err != nil {
		return "", err
	}

	return data.Status.LoadBalancer.Ingress[0].IP, nil
}

// Logs returns a CmdRes with containing the resulting metadata from the
// execution of `kubectl logs <pod> -n <namespace>`.
func (kub *Kubectl) Logs(namespace string, pod string) *CmdRes {
	return kub.Exec(
		fmt.Sprintf("%s -n %s logs %s", KubectlCmd, namespace, pod))
}

// MonitorStart runs cilium monitor in the background and dumps the contents
// into a log file for later debugging
func (kub *Kubectl) MonitorStart(namespace, pod, filename string) func() error {
	cmd := fmt.Sprintf("%s exec -n %s %s -- cilium monitor -v", KubectlCmd, namespace, pod)
	ctx, cancel := context.WithCancel(context.Background())
	res := kub.ExecInBackground(ctx, cmd, ExecOptions{SkipLog: true})

	cb := func() error {
		cancel()
		<-ctx.Done()
		testPath, err := CreateReportDirectory()
		if err != nil {
			kub.Logger().WithError(err).Errorf(
				"cannot create test results path '%s'", testPath)
			return err
		}

		err = WriteOrAppendToFile(
			filepath.Join(testPath, filename),
			res.CombineOutput().Bytes(),
			LogPerm)
		if err != nil {
			log.WithError(err).Errorf("cannot create monitor log file %s", filename)
			return err
		}
		return nil
	}

	return cb
}

// BackgroundReport dumps the result of the given commands on cilium pods each
// five seconds.
func (kub *Kubectl) BackgroundReport(commands ...string) (context.CancelFunc, error) {
	backgroundCtx, cancel := context.WithCancel(context.Background())
	pods, err := kub.GetCiliumPods(GetCiliumNamespace(GetCurrentIntegration()))
	if err != nil {
		return cancel, fmt.Errorf("Cannot retrieve cilium pods: %s", err)
	}
	retrieveInfo := func() {
		for _, pod := range pods {
			for _, cmd := range commands {
				kub.CiliumExec(pod, cmd)
			}
		}
	}
	go func(ctx context.Context) {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				retrieveInfo()
			}
		}
	}(backgroundCtx)
	return cancel, nil
}

// PprofReport runs pprof on cilium nodes each 5 minutes and saves the data
// into the test folder saved with pprof suffix.
func (kub *Kubectl) PprofReport() {
	PProfCadence := 5 * time.Minute
	ticker := time.NewTicker(PProfCadence)
	log := kub.Logger().WithField("subsys", "pprofReport")

	retrievePProf := func(pod, testPath string) {
		res := kub.ExecPodCmd(GetCiliumNamespace(GetCurrentIntegration()), pod, "gops pprof-cpu 1")
		if !res.WasSuccessful() {
			log.Errorf("cannot execute pprof: %s", res.OutputPrettyPrint())
			return
		}
		files := kub.ExecPodCmd(GetCiliumNamespace(GetCurrentIntegration()), pod, `ls -1 /tmp/`)
		for _, file := range files.ByLines() {
			if !strings.Contains(file, "profile") {
				continue
			}

			dest := filepath.Join(
				kub.BasePath(), testPath,
				fmt.Sprintf("%s-profile-%s.pprof", pod, file))
			_ = kub.Exec(fmt.Sprintf("%[1]s cp %[2]s/%[3]s:/tmp/%[4]s %[5]s",
				KubectlCmd, GetCiliumNamespace(GetCurrentIntegration()), pod, file, dest),
				ExecOptions{SkipLog: true})

			_ = kub.ExecPodCmd(GetCiliumNamespace(GetCurrentIntegration()), pod, fmt.Sprintf(
				"rm %s", filepath.Join("/tmp/", file)))
		}
	}

	for {
		select {
		case <-ticker.C:

			testPath, err := CreateReportDirectory()
			if err != nil {
				log.WithError(err).Errorf("cannot create test result path '%s'", testPath)
				return
			}

			pods, err := kub.GetCiliumPods(GetCiliumNamespace(GetCurrentIntegration()))
			if err != nil {
				log.Errorf("cannot get cilium pods")
			}

			for _, pod := range pods {
				retrievePProf(pod, testPath)
			}

		}
	}
}

// NodeCleanMetadata annotates each node in the Kubernetes cluster with the
// annotation.V4CIDRName and annotation.V6CIDRName annotations. It returns an
// error if the nodes cannot be retrieved via the Kubernetes API.
func (kub *Kubectl) NodeCleanMetadata() error {
	metadata := []string{
		annotation.V4CIDRName,
		annotation.V6CIDRName,
	}

	data := kub.ExecShort(fmt.Sprintf("%s get nodes -o jsonpath='{.items[*].metadata.name}'", KubectlCmd))
	if !data.WasSuccessful() {
		return fmt.Errorf("could not get nodes via %s: %s", KubectlCmd, data.CombineOutput())
	}
	for _, node := range strings.Split(data.Output().String(), " ") {
		for _, label := range metadata {
			kub.ExecShort(fmt.Sprintf("%s annotate --overwrite nodes %s %s=''", KubectlCmd, node, label))
		}
	}
	return nil
}

// NamespaceCreate creates a new Kubernetes namespace with the given name
func (kub *Kubectl) NamespaceCreate(name string) *CmdRes {
	ginkgoext.By("Creating namespace %s", name)
	kub.ExecShort(fmt.Sprintf("%s delete namespace %s", KubectlCmd, name))
	return kub.ExecShort(fmt.Sprintf("%s create namespace %s", KubectlCmd, name))
}

// NamespaceDelete deletes a given Kubernetes namespace
func (kub *Kubectl) NamespaceDelete(name string) *CmdRes {
	return kub.ExecShort(fmt.Sprintf("%s delete namespace %s", KubectlCmd, name))
}

// WaitforPods waits up until timeout seconds have elapsed for all pods in the
// specified namespace that match the provided JSONPath filter to have their
// containterStatuses equal to "ready". Returns true if all pods achieve
// the aforementioned desired state within timeout seconds. Returns false and
// an error if the command failed or the timeout was exceeded.
func (kub *Kubectl) WaitforPods(namespace string, filter string, timeout time.Duration) error {
	return kub.waitForNPods(checkReady, namespace, filter, 0, timeout)
}

// checkPodStatusFunc returns true if the pod is in the desired state, or false
// otherwise.
type checkPodStatusFunc func(v1.Pod) bool

// checkRunning checks that the pods are running, but not necessarily ready.
func checkRunning(pod v1.Pod) bool {
	if pod.Status.Phase != v1.PodRunning || pod.ObjectMeta.DeletionTimestamp != nil {
		return false
	}
	return true
}

// checkReady determines whether the pods are running and ready.
func checkReady(pod v1.Pod) bool {
	if !checkRunning(pod) {
		return false
	}

	for _, container := range pod.Status.ContainerStatuses {
		if !container.Ready {
			return false
		}
	}
	return true
}

// WaitforNPodsRunning waits up until timeout duration has elapsed for at least
// minRequired pods in the specified namespace that match the provided JSONPath
// filter to have their containterStatuses equal to "running".
// Returns no error if minRequired pods achieve the aforementioned desired
// state within timeout seconds. Returns an error if the command failed or the
// timeout was exceeded.
// When minRequired is 0, the function will derive required pod count from number
// of pods in the cluster for every iteration.
func (kub *Kubectl) WaitforNPodsRunning(namespace string, filter string, minRequired int, timeout time.Duration) error {
	return kub.waitForNPods(checkRunning, namespace, filter, minRequired, timeout)
}

// WaitforNPods waits up until timeout seconds have elapsed for at least
// minRequired pods in the specified namespace that match the provided JSONPath
// filter to have their containterStatuses equal to "ready".
// Returns no error if minRequired pods achieve the aforementioned desired
// state within timeout seconds. Returns an error if the command failed or the
// timeout was exceeded.
// When minRequired is 0, the function will derive required pod count from number
// of pods in the cluster for every iteration.
func (kub *Kubectl) WaitforNPods(namespace string, filter string, minRequired int, timeout time.Duration) error {
	return kub.waitForNPods(checkReady, namespace, filter, minRequired, timeout)
}

func (kub *Kubectl) waitForNPods(checkStatus checkPodStatusFunc, namespace string, filter string, minRequired int, timeout time.Duration) error {
	body := func() bool {
		podList := &v1.PodList{}
		err := kub.GetPods(namespace, filter).Unmarshal(podList)
		if err != nil {
			kub.Logger().Infof("Error while getting PodList: %s", err)
			return false
		}

		var required int

		if minRequired == 0 {
			required = len(podList.Items)
		} else {
			required = minRequired
		}

		if len(podList.Items) < required {
			return false
		}

		// For each pod, count it as running when all conditions are true:
		//  - It is scheduled via Phase == v1.PodRunning
		//  - It is not scheduled for deletion when DeletionTimestamp is set
		//  - All containers in the pod have passed the liveness check via
		//  containerStatuses.Ready
		currScheduled := 0
		for _, pod := range podList.Items {
			if checkStatus(pod) {
				currScheduled++
			}
		}

		return currScheduled >= required
	}

	return WithTimeout(
		body,
		fmt.Sprintf("timed out waiting for pods with filter %s to be ready", filter),
		&TimeoutConfig{Timeout: timeout})
}

// WaitForServiceEndpoints waits up until timeout seconds have elapsed for all
// endpoints in the specified namespace that match the provided JSONPath
// filter. Returns true if all pods achieve the aforementioned desired state
// within timeout seconds. Returns false and an error if the command failed or
// the timeout was exceeded.
func (kub *Kubectl) WaitForServiceEndpoints(namespace string, filter string, service string, timeout time.Duration) error {
	body := func() bool {
		var jsonPath = fmt.Sprintf("{.items[?(@.metadata.name == '%s')].subsets[0].ports[0].port}", service)
		data, err := kub.GetEndpoints(namespace, filter).Filter(jsonPath)

		if err != nil {
			kub.Logger().WithError(err)
			return false
		}

		if data.String() != "" {
			return true
		}

		kub.Logger().WithFields(logrus.Fields{
			"namespace": namespace,
			"filter":    filter,
			"data":      data,
			"service":   service,
		}).Info("WaitForServiceEndpoints: service endpoint not ready")
		return false
	}

	return WithTimeout(body, "could not get service endpoints", &TimeoutConfig{Timeout: timeout})
}

// Action performs the specified ResourceLifeCycleAction on the Kubernetes
// manifest located at path filepath in the given namespace
func (kub *Kubectl) Action(action ResourceLifeCycleAction, filePath string, namespace ...string) *CmdRes {
	if len(namespace) == 0 {
		kub.Logger().Debugf("performing '%v' on '%v'", action, filePath)
		return kub.ExecShort(fmt.Sprintf("%s %s -f %s", KubectlCmd, action, filePath))
	}

	kub.Logger().Debugf("performing '%v' on '%v' in namespace '%v'", action, filePath, namespace[0])
	return kub.ExecShort(fmt.Sprintf("%s %s -f %s -n %s", KubectlCmd, action, filePath, namespace[0]))
}

// ApplyOptions stores options for kubectl apply command
type ApplyOptions struct {
	FilePath  string
	Namespace string
	Force     bool
	DryRun    bool
	Output    string
	Piped     string
}

// Apply applies the Kubernetes manifest located at path filepath.
func (kub *Kubectl) Apply(options ApplyOptions) *CmdRes {
	var force string
	if options.Force {
		force = "--force=true"
	} else {
		force = "--force=false"
	}

	cmd := fmt.Sprintf("%s apply %s -f %s", KubectlCmd, force, options.FilePath)

	if options.DryRun {
		cmd = cmd + " --dry-run"
	}

	if len(options.Output) > 0 {
		cmd = cmd + " -o " + options.Output
	}

	if len(options.Namespace) == 0 {
		kub.Logger().Debugf("applying %s", options.FilePath)
	} else {
		kub.Logger().Debugf("applying %s in namespace %s", options.FilePath, options.Namespace)
		cmd = cmd + " -n " + options.Namespace
	}

	if len(options.Piped) > 0 {
		cmd = options.Piped + " | " + cmd
	}
	return kub.ExecMiddle(cmd)
}

// ApplyDefault applies give filepath with other options set to default
func (kub *Kubectl) ApplyDefault(filePath string) *CmdRes {
	return kub.Apply(ApplyOptions{FilePath: filePath})
}

// Create creates the Kubernetes kanifest located at path filepath.
func (kub *Kubectl) Create(filePath string) *CmdRes {
	kub.Logger().Debugf("creating %s", filePath)
	return kub.ExecShort(
		fmt.Sprintf("%s create -f  %s", KubectlCmd, filePath))
}

// CreateResource is a wrapper around `kubernetes create <resource>
// <resourceName>.
func (kub *Kubectl) CreateResource(resource, resourceName string) *CmdRes {
	kub.Logger().Debug(fmt.Sprintf("creating resource %s with name %s", resource, resourceName))
	return kub.ExecShort(fmt.Sprintf("kubectl create %s %s", resource, resourceName))
}

// DeleteResource is a wrapper around `kubernetes delete <resource>
// resourceName>.
func (kub *Kubectl) DeleteResource(resource, resourceName string) *CmdRes {
	kub.Logger().Debug(fmt.Sprintf("deleting resource %s with name %s", resource, resourceName))
	return kub.Exec(fmt.Sprintf("kubectl delete %s %s", resource, resourceName))
}

// Delete deletes the Kubernetes manifest at path filepath.
func (kub *Kubectl) Delete(filePath string) *CmdRes {
	kub.Logger().Debugf("deleting %s", filePath)
	return kub.ExecShort(
		fmt.Sprintf("%s delete -f  %s", KubectlCmd, filePath))
}

// WaitKubeDNS waits until the kubeDNS pods are ready. In case of exceeding the
// default timeout it returns an error.
func (kub *Kubectl) WaitKubeDNS() error {
	return kub.WaitforPods(KubeSystemNamespace, fmt.Sprintf("-l %s", kubeDNSLabel), DNSHelperTimeout)
}

// WaitForKubeDNSEntry waits until the given DNS entry exists in the kube-dns
// service. If the container is not ready after timeout it returns an error. The
// name's format query should be `${name}.${namespace}`. If `svc.cluster.local`
// is not present, it appends to the given name and it checks the service's FQDN.
func (kub *Kubectl) WaitForKubeDNSEntry(serviceName, serviceNamespace string) error {
	svcSuffix := "svc.cluster.local"
	logger := kub.Logger().WithFields(logrus.Fields{"serviceName": serviceName, "serviceNamespace": serviceNamespace})

	serviceNameWithNamespace := fmt.Sprintf("%s.%s", serviceName, serviceNamespace)
	if !strings.HasSuffix(serviceNameWithNamespace, svcSuffix) {
		serviceNameWithNamespace = fmt.Sprintf("%s.%s", serviceNameWithNamespace, svcSuffix)
	}
	// https://bugs.launchpad.net/ubuntu/+source/bind9/+bug/854705
	digCMD := "dig +short %s @%s | grep -v -e '^;'"

	// If it fails we want to know if it's because of connection cannot be
	// established or DNS does not exist.
	digCMDFallback := "dig +tcp %s @%s"

	dnsClusterIP, _, err := kub.GetServiceHostPort(KubeSystemNamespace, "kube-dns")
	if err != nil {
		logger.WithError(err).Error("cannot get kube-dns service IP")
		return err
	}

	body := func() bool {
		serviceIP, _, err := kub.GetServiceHostPort(serviceNamespace, serviceName)
		if err != nil {
			log.WithError(err).Errorf("cannot get service IP for service %s", serviceNameWithNamespace)
			return false
		}

		ctx, cancel := context.WithTimeout(context.Background(), MidCommandTimeout)
		defer cancel()
		// ClusterIPNone denotes that this service is headless; there is no
		// service IP for this service, and thus the IP returned by `dig` is
		// an IP of the pod itself, not ClusterIPNone, which is what Kubernetes
		// shows as the IP for the service for headless services.
		if serviceIP == v1.ClusterIPNone {
			res, err := kub.ExecInFirstPod(ctx, LogGathererNamespace, logGathererSelector(false), fmt.Sprintf(digCMD, serviceNameWithNamespace, dnsClusterIP))
			if err != nil {
				logger.Debugf("failed to run dig in log-gatherer pod")
				return false
			}
			kub.ExecInFirstPod(ctx, LogGathererNamespace, logGathererSelector(false), fmt.Sprintf(digCMDFallback, serviceNameWithNamespace, dnsClusterIP))

			return res.WasSuccessful()
		}
		log.Debugf("service is not headless; checking whether IP retrieved from DNS matches the IP for the service stored in Kubernetes")

		res, err := kub.ExecInFirstPod(ctx, LogGathererNamespace, logGathererSelector(false), fmt.Sprintf(digCMD, serviceNameWithNamespace, dnsClusterIP))
		if err != nil {
			logger.Debugf("failed to run dig in log-gatherer pod")
			return false
		}
		serviceIPFromDNS := res.SingleOut()
		if !govalidator.IsIP(serviceIPFromDNS) {
			logger.Debugf("output of dig (%s) did not return an IP", serviceIPFromDNS)
			return false
		}

		// Due to lag between new IPs for the same service being synced between // kube-apiserver and DNS, check if the IP for the service that is
		// stored in K8s matches the IP of the service cached in DNS. These
		// can be different, because some tests use the same service names.
		// Wait accordingly for services to match, and for resolving the service
		// name to resolve via DNS.
		if !strings.Contains(serviceIPFromDNS, serviceIP) {
			logger.Debugf("service IP retrieved from DNS (%s) does not match the IP for the service stored in Kubernetes (%s)", serviceIPFromDNS, serviceIP)
			kub.ExecInFirstPod(ctx, LogGathererNamespace, logGathererSelector(false), fmt.Sprintf(digCMDFallback, serviceNameWithNamespace, dnsClusterIP))
			return false
		}
		logger.Debugf("service IP retrieved from DNS (%s) matches the IP for the service stored in Kubernetes (%s)", serviceIPFromDNS, serviceIP)
		return true
	}

	return WithTimeout(
		body,
		fmt.Sprintf("DNS '%s' is not ready after timeout", serviceNameWithNamespace),
		&TimeoutConfig{Timeout: DNSHelperTimeout})
}

// WaitCleanAllTerminatingPods waits until all nodes that are in `Terminating`
// state are deleted correctly in the platform. In case of excedding the
// given timeout (in seconds) it returns an error
func (kub *Kubectl) WaitCleanAllTerminatingPods(timeout time.Duration) error {
	body := func() bool {
		res := kub.ExecShort(fmt.Sprintf(
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
		kub.Logger().WithField("Terminating pods", podsTerminating).Info("List of pods terminating")
		if podsTerminating > 0 {
			return false
		}
		return true
	}

	err := WithTimeout(
		body,
		"Pods are still not deleted after a timeout",
		&TimeoutConfig{Timeout: timeout})
	return err
}

// DeployPatchStdIn deploys the original kubernetes descriptor with the given patch.
func (kub *Kubectl) DeployPatchStdIn(original, patch string) error {
	// debugYaml only dumps the full created yaml file to the test output if
	// the cilium manifest can not be created correctly.
	debugYaml := func(original, patch string) {
		// dry-run is only available since k8s 1.11
		switch GetCurrentK8SEnv() {
		case "1.8", "1.9", "1.10":
			_ = kub.ExecShort(fmt.Sprintf(
				`%s patch --filename='%s' --patch %s --local -o yaml`,
				KubectlCmd, original, patch))
		default:
			_ = kub.ExecShort(fmt.Sprintf(
				`%s patch --filename='%s' --patch %s --local --dry-run -o yaml`,
				KubectlCmd, original, patch))
		}
	}

	var res *CmdRes
	// validation 1st
	// dry-run is only available since k8s 1.11
	switch GetCurrentK8SEnv() {
	case "1.8", "1.9", "1.10":
	default:
		res = kub.ExecShort(fmt.Sprintf(
			`%s patch --filename='%s' --patch %s --local --dry-run`,
			KubectlCmd, original, patch))
		if !res.WasSuccessful() {
			debugYaml(original, patch)
			return res.GetErr("Cilium patch validation failed")
		}
	}

	res = kub.Apply(ApplyOptions{
		FilePath: "-",
		Force:    true,
		Piped: fmt.Sprintf(
			`%s patch --filename='%s' --patch %s --local -o yaml`,
			KubectlCmd, original, patch),
	})
	if !res.WasSuccessful() {
		debugYaml(original, patch)
		return res.GetErr("Cilium manifest patch installation failed")
	}
	return nil
}

// DeployPatch deploys the original kubernetes descriptor with the given patch.
func (kub *Kubectl) DeployPatch(original, patchFileName string) error {
	// debugYaml only dumps the full created yaml file to the test output if
	// the cilium manifest can not be created correctly.
	debugYaml := func(original, patch string) {
		// dry-run is only available since k8s 1.11
		switch GetCurrentK8SEnv() {
		case "1.8", "1.9", "1.10":
			_ = kub.ExecShort(fmt.Sprintf(
				`%s patch --filename='%s' --patch "$(cat '%s')" --local -o yaml`,
				KubectlCmd, original, patch))
		default:
			_ = kub.ExecShort(fmt.Sprintf(
				`%s patch --filename='%s' --patch "$(cat '%s')" --local --dry-run -o yaml`,
				KubectlCmd, original, patch))
		}
	}

	var res *CmdRes
	// validation 1st
	// dry-run is only available since k8s 1.11
	switch GetCurrentK8SEnv() {
	case "1.8", "1.9", "1.10":
	default:
		res = kub.ExecShort(fmt.Sprintf(
			`%s patch --filename='%s' --patch "$(cat '%s')" --local --dry-run`,
			KubectlCmd, original, patchFileName))
		if !res.WasSuccessful() {
			debugYaml(original, patchFileName)
			return res.GetErr("Cilium patch validation failed")
		}
	}

	res = kub.Apply(ApplyOptions{
		FilePath: "-",
		Force:    true,
		Piped: fmt.Sprintf(
			`%s patch --filename='%s' --patch "$(cat '%s')" --local -o yaml`,
			KubectlCmd, original, patchFileName),
	})
	if !res.WasSuccessful() {
		debugYaml(original, patchFileName)
		return res.GetErr("Cilium manifest patch installation failed")
	}
	return nil
}

// ciliumInstall installs all Cilium descriptors into kubernetes.
// dsPatchName corresponds to the DaemonSet patch, found by
// getK8sDescriptorPatch, that will be applied to the original Cilium DaemonSet
// descriptor, found by getK8sDescriptor.
// cmPatchName corresponds to the ConfigMap patch, found by
// getK8sDescriptorPatch, that will be applied to the original Cilium ConfigMap
// descriptor, found by getK8sDescriptor.
// Returns an error if any patch or if any original descriptors files were not
// found.
func (kub *Kubectl) ciliumInstall(ciliumFilename, dsPatchName, cmPatchName string, getK8sDescriptor, getK8sDescriptorPatch func(filename string) string) error {
	cmPathname := getK8sDescriptor("cilium-cm.yaml")
	if cmPathname == "" {
		return fmt.Errorf("Cilium ConfigMap descriptor not found")
	}
	dsPathname := getK8sDescriptor("cilium-ds.yaml")
	if dsPathname == "" {
		return fmt.Errorf("Cilium DaemonSet descriptor not found")
	}
	rbacPathname := getK8sDescriptor("cilium-rbac.yaml")
	if rbacPathname == "" {
		return fmt.Errorf("Cilium RBAC descriptor not found")
	}

	deployOriginal := func(original string) error {
		// debugYaml only dumps the full created yaml file to the test output if
		// the cilium manifest can not be created correctly.
		debugYaml := func(original string) {
			kub.Apply(ApplyOptions{
				FilePath: original,
				DryRun:   true,
				Output:   "yaml",
			})
		}

		// validation 1st
		res := kub.Apply(ApplyOptions{
			FilePath: original,
			DryRun:   true,
		})
		if !res.WasSuccessful() {
			debugYaml(original)
			return res.GetErr("Cilium manifest validation fails")
		}

		res = kub.ApplyDefault(original)
		if !res.WasSuccessful() {
			debugYaml(original)
			return res.GetErr("Cannot apply Cilium manifest")
		}
		return nil
	}

	if err := deployOriginal(rbacPathname); err != nil {
		return err
	}

	if err := kub.DeployPatch(cmPathname, getK8sDescriptorPatch(cmPatchName)); err != nil {
		return err
	}

	if err := kub.DeployPatch(dsPathname, getK8sDescriptorPatch(dsPatchName)); err != nil {
		return err
	}

	cmdRes := kub.ApplyDefault(getK8sDescriptor(ciliumEtcdOperatorSA))
	if !cmdRes.WasSuccessful() {
		return fmt.Errorf("Unable to deploy descriptor of etcd-operator SA %s: %s", ciliumEtcdOperatorSA, cmdRes.OutputPrettyPrint())
	}

	cmdRes = kub.ApplyDefault(getK8sDescriptor(ciliumEtcdOperatorRBAC))
	if !cmdRes.WasSuccessful() {
		return fmt.Errorf("Unable to deploy descriptor of etcd-operator RBAC %s: %s", ciliumEtcdOperatorRBAC, cmdRes.OutputPrettyPrint())
	}

	cmdRes = kub.ApplyDefault(getK8sDescriptor(ciliumEtcdOperator))
	if !cmdRes.WasSuccessful() {
		return fmt.Errorf("Unable to deploy descriptor of etcd-operator %s: %s", ciliumEtcdOperator, cmdRes.OutputPrettyPrint())
	}

	_ = kub.ApplyDefault(getK8sDescriptor("cilium-operator-sa.yaml"))
	err := kub.DeployPatch(getK8sDescriptor("cilium-operator.yaml"), getK8sDescriptorPatch("cilium-operator-patch.yaml"))
	if err != nil {
		return fmt.Errorf("Unable to deploy descriptor of cilium-operators: %s", err)
	}

	return nil
}

func addIfNotOverwritten(options map[string]string, field, value string) map[string]string {
	if _, ok := options[field]; !ok {
		options[field] = value
	}
	return options
}

func (kub *Kubectl) generateCiliumYaml(options map[string]string, filename string) error {
	for key, value := range defaultHelmOptions {
		options = addIfNotOverwritten(options, key, value)
	}

	// Do not schedule cilium-agent on the NO_CILIUM_ON_NODE node
	if node := GetNodeWithoutCilium(); node != "" {
		opts := map[string]string{
			"global.affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[0].matchExpressions[0].key":       "cilium.io/ci-node",
			"global.affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[0].matchExpressions[0].operator":  "NotIn",
			"global.affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[0].matchExpressions[0].values[0]": node,
		}
		for key, value := range opts {
			options = addIfNotOverwritten(options, key, value)
		}
	}

	if !RunsWithKubeProxy() {
		nodeIP, err := kub.GetNodeIPByLabel(K8s1)
		if err != nil {
			return fmt.Errorf("Cannot retrieve Node IP for k8s1: %s", err)
		}

		opts := map[string]string{
			"global.kubeProxyReplacement": "strict",
			"global.nodePort.device":      PrivateIface,
			"global.k8sServiceHost":       nodeIP,
			"global.k8sServicePort":       "6443",
		}
		for key, value := range opts {
			options = addIfNotOverwritten(options, key, value)
		}
	}

	if integration := GetCurrentIntegration(); integration != "" {
		overrides := helmOverrides[integration]
		for k, v := range overrides {
			options[k] = v
		}
	}

	// TODO GH-8753: Use helm rendering library instead of shelling out to
	// helm template
	helmTemplate := kub.GetFilePath(HelmTemplate)
	res := kub.HelmTemplate(helmTemplate, GetCiliumNamespace(GetCurrentIntegration()), filename, options)
	if !res.WasSuccessful() {
		return res.GetErr("Unable to generate YAML")
	}

	return nil
}

// ciliumInstallHelm installs Cilium with the Helm options provided.
//
// The method Deletes cilium DS before the installation.
func (kub *Kubectl) ciliumInstallHelm(filename string, options map[string]string) error {
	if err := kub.generateCiliumYaml(options, filename); err != nil {
		return err
	}

	// Remove cilium DS to ensure that new instances of cilium-agent are started
	// for the newly generated ConfigMap. Otherwise, the CM changes will stay
	// inactive until each cilium-agent has been restarted.
	if err := kub.DeleteCiliumDS(); err != nil {
		return err
	}

	res := kub.Apply(ApplyOptions{FilePath: filename, Force: true, Namespace: GetCiliumNamespace(GetCurrentIntegration())})
	if !res.WasSuccessful() {
		return res.GetErr("Unable to apply YAML")
	}

	return nil
}

func (kub *Kubectl) DeleteCiliumDS() error {
	// Do not assert on success in AfterEach intentionally to avoid
	// incomplete teardown.

	_ = kub.DeleteResource("ds", fmt.Sprintf("-n %s cilium", GetCiliumNamespace(GetCurrentIntegration())))
	return kub.waitToDeleteCilium()
}

func (kub *Kubectl) waitToDeleteCilium() error {
	var (
		pods []string
		err  error
	)

	ctx, cancel := context.WithTimeout(context.Background(), HelperTimeout)
	defer cancel()

	status := 1
	for status > 0 {

		select {
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting to delete Cilium: pods still remaining: %s", pods)
		default:
		}

		pods, err = kub.GetCiliumPodsContext(ctx, GetCiliumNamespace(GetCurrentIntegration()))
		status := len(pods)
		kub.Logger().Infof("Cilium pods terminating '%d' err='%v' pods='%v'", status, err, pods)
		if status == 0 {
			return nil
		}
		time.Sleep(1 * time.Second)
	}
	return nil
}

// ciliumUninstallHelm uninstalls Cilium with the Helm options provided.
func (kub *Kubectl) ciliumUninstallHelm(filename string, options map[string]string) error {
	if err := kub.generateCiliumYaml(options, filename); err != nil {
		return err
	}

	res := kub.Delete(filename)
	if !res.WasSuccessful() {
		return res.GetErr("Unable to delete YAML")
	}

	return nil
}

// CiliumInstall installs Cilium with the provided Helm options.
func (kub *Kubectl) CiliumInstall(filename string, options map[string]string) error {
	return kub.ciliumInstallHelm(filename, options)
}

// CiliumUninstall uninstalls Cilium with the provided Helm options.
func (kub *Kubectl) CiliumUninstall(filename string, options map[string]string) error {
	return kub.ciliumUninstallHelm(filename, options)
}

// CiliumInstallVersion installs all Cilium descriptors into kubernetes for
// a given Cilium Version tag.
// dsPatchName corresponds to the DaemonSet patch that will be applied to the
// original Cilium DaemonSet descriptor of that given Cilium Version tag.
// cmPatchName corresponds to the ConfigMap patch that will be applied to the
// original Cilium ConfigMap descriptor of that given Cilium Version tag.
// Returns an error if any patch or if any original descriptors files were not
// found.
func (kub *Kubectl) CiliumInstallVersion(ciliumFilename, dsPatchName, cmPatchName, versionTag string) error {
	getK8sDescriptorPatch := func(filename string) string {
		// try dependent Cilium, k8s and integration version patch file
		ginkgoVersionedPath := filepath.Join(manifestsPath, versionTag, GetCurrentK8SEnv(), GetCurrentIntegration(), filename)
		_, err := os.Stat(ginkgoVersionedPath)
		if err == nil {
			return filepath.Join(kub.BasePath(), ginkgoVersionedPath)
		}
		// try dependent Cilium version and integration patch file
		ginkgoVersionedPath = filepath.Join(manifestsPath, versionTag, GetCurrentIntegration(), filename)
		_, err = os.Stat(ginkgoVersionedPath)
		if err == nil {
			return filepath.Join(kub.BasePath(), ginkgoVersionedPath)
		}
		// try dependent Cilium and k8s version patch file
		ginkgoVersionedPath = filepath.Join(manifestsPath, versionTag, GetCurrentK8SEnv(), filename)
		_, err = os.Stat(ginkgoVersionedPath)
		if err == nil {
			return filepath.Join(kub.BasePath(), ginkgoVersionedPath)
		}
		// try dependent Cilium version patch file
		ginkgoVersionedPath = filepath.Join(manifestsPath, versionTag, filename)
		_, err = os.Stat(ginkgoVersionedPath)
		if err == nil {
			return filepath.Join(kub.BasePath(), ginkgoVersionedPath)
		}
		// try dependent integration patch file
		ginkgoVersionedPath = filepath.Join(manifestsPath, GetCurrentIntegration(), filename)
		_, err = os.Stat(ginkgoVersionedPath)
		if err == nil {
			return filepath.Join(kub.BasePath(), ginkgoVersionedPath)
		}
		return filepath.Join(kub.BasePath(), manifestsPath, filename)
	}
	getK8sDescriptor := func(filename string) string {
		return fmt.Sprintf("https://raw.githubusercontent.com/cilium/cilium/%s/examples/kubernetes/%s/%s", versionTag, GetCurrentK8SEnv(), filename)
	}
	return kub.ciliumInstall(ciliumFilename, dsPatchName, cmPatchName, getK8sDescriptor, getK8sDescriptorPatch)
}

// GetCiliumPods returns a list of all Cilium pods in the specified namespace,
// and an error if the Cilium pods were not able to be retrieved.
func (kub *Kubectl) GetCiliumPods(namespace string) ([]string, error) {
	return kub.GetPodNames(namespace, "k8s-app=cilium")
}

// GetCiliumPodsContext returns a list of all Cilium pods in the specified
// namespace, and an error if the Cilium pods were not able to be retrieved.
func (kub *Kubectl) GetCiliumPodsContext(ctx context.Context, namespace string) ([]string, error) {
	return kub.GetPodNamesContext(ctx, namespace, "k8s-app=cilium")
}

// CiliumEndpointsList returns the result of `cilium endpoint list` from the
// specified pod.
func (kub *Kubectl) CiliumEndpointsList(ctx context.Context, pod string) *CmdRes {
	return kub.CiliumExecContext(ctx, pod, "cilium endpoint list -o json")
}

// CiliumEndpointsStatus returns a mapping  of a pod name to it is corresponding
// endpoint's status
func (kub *Kubectl) CiliumEndpointsStatus(pod string) map[string]string {
	filter := `{range [*]}{@.status.external-identifiers.pod-name}{"="}{@.status.state}{"\n"}{end}`
	ctx, cancel := context.WithTimeout(context.Background(), ShortCommandTimeout)
	defer cancel()
	return kub.CiliumExecContext(ctx, pod, fmt.Sprintf(
		"cilium endpoint list -o jsonpath='%s'", filter)).KVOutput()
}

// CiliumEndpointWaitReady waits until all endpoints managed by all Cilium pod
// are ready. Returns an error if the Cilium pods cannot be retrieved via
// Kubernetes, or endpoints are not ready after a specified timeout
func (kub *Kubectl) CiliumEndpointWaitReady() error {
	ciliumPods, err := kub.GetCiliumPods(GetCiliumNamespace(GetCurrentIntegration()))
	if err != nil {
		kub.Logger().WithError(err).Error("cannot get Cilium pods")
		return err
	}

	body := func(ctx context.Context) (bool, error) {
		var wg sync.WaitGroup
		queue := make(chan bool, len(ciliumPods))
		endpointsReady := func(pod string) {
			valid := false
			defer func() {
				queue <- valid
				wg.Done()
			}()
			logCtx := kub.Logger().WithField("pod", pod)
			status, err := kub.CiliumEndpointsList(ctx, pod).Filter(`{range [*]}{.status.state}{"="}{.status.identity.id}{"\n"}{end}`)
			if err != nil {
				logCtx.WithError(err).Errorf("cannot get endpoints states on Cilium pod")
				return
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
					return
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
				return
			}
			valid = true
			return
		}
		wg.Add(len(ciliumPods))
		for _, pod := range ciliumPods {
			go endpointsReady(pod)
		}

		wg.Wait()
		close(queue)

		for status := range queue {
			if status == false {
				return false, nil
			}
		}
		return true, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), HelperTimeout)
	defer cancel()
	err = WithContext(ctx, body, 1*time.Second)
	if err == nil {
		return err
	}

	callback := func() string {
		ctx, cancel := context.WithTimeout(context.Background(), HelperTimeout)
		defer cancel()

		var errorMessage string
		for _, pod := range ciliumPods {
			var endpoints []models.Endpoint
			cmdRes := kub.CiliumEndpointsList(ctx, pod)
			if !cmdRes.WasSuccessful() {
				errorMessage += fmt.Sprintf(
					"\tCilium Pod: %s \terror: unable to get endpoint list: %s",
					pod, cmdRes.err)
				continue
			}
			err := cmdRes.Unmarshal(&endpoints)
			if err != nil {
				errorMessage += fmt.Sprintf(
					"\tCilium Pod: %s \terror: unable to parse endpoint list: %s",
					pod, err)
				continue
			}
			for _, ep := range endpoints {
				errorMessage += fmt.Sprintf(
					"\tCilium Pod: %s \tEndpoint: %d \tIdentity: %d\t State: %s\n",
					pod, ep.ID, ep.Status.Identity.ID, ep.Status.State)
			}
		}
		return errorMessage
	}
	return NewSSHMetaError(err.Error(), callback)
}

// WaitForCEPIdentity waits for a particular CEP to have an identity present.
func (kub *Kubectl) WaitForCEPIdentity(ns, podName string) error {
	body := func(ctx context.Context) (bool, error) {
		ep := kub.CepGet(ns, podName)
		if ep == nil {
			return false, nil
		}
		if ep.Identity == nil {
			return false, nil
		}
		return ep.Identity.ID != 0, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), HelperTimeout)
	defer cancel()
	return WithContext(ctx, body, 1*time.Second)
}

// CiliumExecContext runs cmd in the specified Cilium pod with the given context.
func (kub *Kubectl) CiliumExecContext(ctx context.Context, pod string, cmd string) *CmdRes {
	limitTimes := 5
	execute := func() *CmdRes {
		command := fmt.Sprintf("%s exec -n %s %s -- %s", KubectlCmd, GetCiliumNamespace(GetCurrentIntegration()), pod, cmd)
		return kub.ExecContext(ctx, command)
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

// CiliumExec runs cmd in the specified Cilium pod.
// Deprecated: use CiliumExecContext instead
func (kub *Kubectl) CiliumExec(pod string, cmd string) *CmdRes {
	ctx, cancel := context.WithTimeout(context.Background(), HelperTimeout)
	defer cancel()
	return kub.CiliumExecContext(ctx, pod, cmd)
}

// CiliumExecUntilMatch executes the specified command repeatedly for the
// specified Cilium pod until the given substring is present in stdout.
// If the timeout is reached it will return an error.
func (kub *Kubectl) CiliumExecUntilMatch(pod, cmd, substr string) error {
	body := func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), ShortCommandTimeout)
		defer cancel()
		res := kub.CiliumExecContext(ctx, pod, cmd)
		return strings.Contains(res.Output().String(), substr)
	}

	return WithTimeout(
		body,
		fmt.Sprintf("%s is not in the output after timeout", substr),
		&TimeoutConfig{Timeout: HelperTimeout})
}

// WaitForCiliumInitContainerToFinish waits for all Cilium init containers to
// finish
func (kub *Kubectl) WaitForCiliumInitContainerToFinish() error {
	body := func() bool {
		podList := &v1.PodList{}
		err := kub.GetPods(CiliumNamespace, "-l k8s-app=cilium").Unmarshal(podList)
		if err != nil {
			kub.Logger().Infof("Error while getting PodList: %s", err)
			return false
		}
		if len(podList.Items) == 0 {
			return false
		}
		for _, pod := range podList.Items {
			for _, v := range pod.Status.InitContainerStatuses {
				if v.State.Terminated != nil && (v.State.Terminated.Reason != "Completed" || v.State.Terminated.ExitCode != 0) {
					kub.Logger().WithFields(logrus.Fields{
						"podName":      pod.Name,
						"currentState": v.State.String(),
					}).Infof("Cilium Init container not completed")
					return false
				}
			}
		}
		return true
	}

	return WithTimeout(body, "Cilium Init Container was not able to initialize or had a successful run", &TimeoutConfig{Timeout: HelperTimeout})
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
		data := kub.ExecShort(fmt.Sprintf(
			"%s get nodes -o jsonpath='%s'", KubectlCmd, filter))
		if !data.WasSuccessful() {
			return false
		}
		result := data.KVOutput()
		ignoreNode := GetNodeWithoutCilium()
		for k, v := range result {
			if k == ignoreNode {
				continue
			}
			if v == "" {
				kub.Logger().Infof("Kubernetes node '%v' does not have Cilium metadata", k)
				return false
			}
			kub.Logger().Infof("Kubernetes node '%v' IPv4 address: '%v'", k, v)
		}
		return true
	}
	err := WithTimeout(body, "Kubernetes node does not have cilium metadata", &TimeoutConfig{Timeout: HelperTimeout})
	if err != nil {
		return false, err
	}
	return true, nil
}

// WaitPolicyDeleted waits for policy policyName to be deleted from the
// cilium-agent running in pod. Returns an error if policyName was unable to
// be deleted after some amount of time.
func (kub *Kubectl) WaitPolicyDeleted(pod string, policyName string) error {
	body := func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), ShortCommandTimeout)
		defer cancel()
		res := kub.CiliumExecContext(ctx, pod, fmt.Sprintf("cilium policy get %s", policyName))

		// `cilium policy get <policy name>` fails if the policy is not loaded,
		// which is the condition we want.
		return !res.WasSuccessful()
	}

	return WithTimeout(body, fmt.Sprintf("Policy %s was not deleted in time", policyName), &TimeoutConfig{Timeout: HelperTimeout})
}

// CiliumIsPolicyLoaded returns true if the policy is loaded in the given
// cilium Pod. it returns false in case that the policy is not in place
func (kub *Kubectl) CiliumIsPolicyLoaded(pod string, policyCmd string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), ShortCommandTimeout)
	defer cancel()
	res := kub.CiliumExecContext(ctx, pod, fmt.Sprintf("cilium policy get %s", policyCmd))
	return res.WasSuccessful()
}

// CiliumPolicyRevision returns the policy revision in the specified Cilium pod.
// Returns an error if the policy revision cannot be retrieved.
func (kub *Kubectl) CiliumPolicyRevision(pod string) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), ShortCommandTimeout)
	defer cancel()
	res := kub.CiliumExecContext(ctx, pod, "cilium policy get -o json")
	if !res.WasSuccessful() {
		return -1, fmt.Errorf("cannot get the revision %s", res.Output())
	}

	revision, err := res.Filter("{.revision}")
	if err != nil {
		return -1, fmt.Errorf("cannot get revision from json: %s", err)
	}

	revi, err := strconv.Atoi(strings.Trim(revision.String(), "\n"))
	if err != nil {
		kub.Logger().Errorf("revision on pod '%s' is not valid '%s'", pod, res.CombineOutput())
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
	numNodes := kub.GetNumCiliumNodes()

	// Test filter: https://jqplay.org/s/EgNzc06Cgn
	jqFilter := fmt.Sprintf(
		`[.items[]|{name:.metadata.name, enforcing: (.status|if has("nodes") then .nodes |to_entries|map_values(.value.enforcing) + [(.|length >= %d)]|all else true end)|tostring, status: has("status")|tostring}]`,
		numNodes)
	npFilter := fmt.Sprintf(
		`{range .items[*]}{"%s="}{.metadata.name}{" %s="}{.metadata.namespace}{"\n"}{end}`,
		KubectlPolicyNameLabel, KubectlPolicyNameSpaceLabel)
	kub.Logger().Infof("Performing %s action on resource '%s'", action, filepath)

	if status := kub.Action(action, filepath, namespace); !status.WasSuccessful() {
		return "", status.GetErr(fmt.Sprintf("Cannot perform '%s' on resorce '%s'", action, filepath))
	}

	if action == KubectlDelete {
		// Due policy is uninstalled, there is no need to validate that the policy is enforce.
		return "", nil
	}

	body := func() bool {
		var data []map[string]string
		cmd := fmt.Sprintf("%s get cnp --all-namespaces -o json | jq '%s'",
			KubectlCmd, jqFilter)

		res := kub.ExecShort(cmd)
		if !res.WasSuccessful() {
			kub.Logger().WithError(res.GetErr("")).Error("cannot get cnp status")
			return false

		}

		err := res.Unmarshal(&data)
		if err != nil {
			kub.Logger().WithError(err).Error("Cannot unmarshal json")
			return false
		}

		for _, item := range data {
			if item["enforcing"] != "true" || item["status"] != "true" {
				kub.Logger().Errorf("Policy '%s' is not enforcing yet", item["name"])
				return false
			}
		}
		return true
	}

	err := WithTimeout(
		body,
		"cannot change state of resource correctly; command timed out",
		&TimeoutConfig{Timeout: timeout})

	if err != nil {
		return "", err
	}

	knpBody := func() bool {
		knp := kub.ExecShort(fmt.Sprintf("%s get --all-namespaces netpol -o jsonpath='%s'",
			KubectlCmd, npFilter))
		result := knp.ByLines()
		if len(result) == 0 {
			return true
		}

		pods, err := kub.GetCiliumPods(GetCiliumNamespace(GetCurrentIntegration()))
		if err != nil {
			kub.Logger().WithError(err).Error("cannot retrieve cilium pods")
			return false
		}
		for _, item := range result {
			for _, ciliumPod := range pods {
				if !kub.CiliumIsPolicyLoaded(ciliumPod, item) {
					kub.Logger().Infof("Policy '%s' is not ready on Cilium pod '%s'", item, ciliumPod)
					return false
				}
			}
		}
		return true
	}

	err = WithTimeout(
		knpBody,
		"cannot change state of Kubernetes network policies correctly; command timed out",
		&TimeoutConfig{Timeout: timeout})
	return "", err
}

// CiliumClusterwidePolicyAction applies a clusterwide policy action as described in action argument. It
// then wait till timeout Duration for the policy to be applied to all the cilium endpoints.
func (kub *Kubectl) CiliumClusterwidePolicyAction(filepath string, action ResourceLifeCycleAction, timeout time.Duration) (string, error) {
	numNodes := kub.GetNumCiliumNodes()

	kub.Logger().Infof("Performing %s action on resource '%s'", action, filepath)

	if status := kub.Action(action, filepath); !status.WasSuccessful() {
		return "", status.GetErr(fmt.Sprintf("Cannot perform '%s' on resource '%s'", action, filepath))
	}

	if action == KubectlDelete {
		// Due policy is uninstalled, there is no need to validate that the policy is enforced.
		return "", nil
	}

	jqFilter := fmt.Sprintf(
		`[.items[]|{name:.metadata.name, enforcing: (.status|if has("nodes") then .nodes |to_entries|map_values(.value.enforcing) + [(.|length >= %d)]|all else true end)|tostring, status: has("status")|tostring}]`,
		numNodes)

	body := func() bool {
		var data []map[string]string
		cmd := fmt.Sprintf("%s get ccnp -o json | jq '%s'",
			KubectlCmd, jqFilter)

		res := kub.ExecShort(cmd)
		if !res.WasSuccessful() {
			kub.Logger().WithError(res.GetErr("")).Error("cannot get ccnp status")
			return false

		}

		err := res.Unmarshal(&data)
		if err != nil {
			kub.Logger().WithError(err).Error("Cannot unmarshal json")
			return false
		}

		for _, item := range data {
			if item["enforcing"] != "true" || item["status"] != "true" {
				kub.Logger().Errorf("Clusterwide policy '%s' is not enforcing yet", item["name"])
				return false
			}
		}
		return true
	}

	err := WithTimeout(
		body,
		"cannot change state of resource correctly; command timed out",
		&TimeoutConfig{Timeout: timeout})

	return "", err
}

// CiliumReport report the cilium pod to the log and appends the logs for the
// given commands.
func (kub *Kubectl) CiliumReport(namespace string, commands ...string) {
	if config.CiliumTestConfig.SkipLogGathering {
		ginkgoext.GinkgoPrint("Skipped gathering logs (-cilium.skipLogs=true)\n")
		return
	}

	// Log gathering for Cilium should take at most 5 minutes. This ensures that
	// the CiliumReport stage doesn't cause the entire CI to hang.

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		kub.DumpCiliumCommandOutput(ctx, namespace)
		kub.GatherLogs(ctx)
	}()

	kub.CiliumCheckReport(ctx)

	pods, err := kub.GetCiliumPodsContext(ctx, namespace)
	if err != nil {
		kub.Logger().WithError(err).Error("cannot retrieve cilium pods on ReportDump")
	}
	res := kub.ExecContextShort(ctx, fmt.Sprintf("%s get pods -o wide --all-namespaces", KubectlCmd))
	ginkgoext.GinkgoPrint(res.GetDebugMessage())

	results := make([]*CmdRes, 0, len(pods)*len(commands))
	ginkgoext.GinkgoPrint("Fetching command output from pods %s", pods)
	for _, pod := range pods {
		for _, cmd := range commands {
			res = kub.ExecPodCmdBackground(ctx, namespace, pod, cmd, ExecOptions{SkipLog: true})
			results = append(results, res)
		}
	}

	wg.Wait()

	for _, res := range results {
		res.WaitUntilFinish()
		ginkgoext.GinkgoPrint(res.GetDebugMessage())
	}
}

// EtcdOperatorReport dump etcd pods data into the report directory to be able
// to debug etcd operator status in case of fail test.
func (kub *Kubectl) EtcdOperatorReport(ctx context.Context, reportCmds map[string]string) {
	if reportCmds == nil {
		reportCmds = make(map[string]string)
	}

	pods, err := kub.GetPodNamesContext(ctx, GetCiliumNamespace(GetCurrentIntegration()), "etcd_cluster=cilium-etcd")
	if err != nil {
		kub.Logger().WithError(err).Error("No etcd pods")
		return
	}

	etcdctl := "etcdctl --endpoints=https://%s.cilium-etcd.%s.svc:2379 " +
		"--cert-file /etc/etcdtls/member/peer-tls/peer.crt " +
		"--key-file /etc/etcdtls/member/peer-tls/peer.key " +
		"--ca-file /etc/etcdtls/member/peer-tls/peer-ca.crt " +
		" %s"

	etcdDumpCommands := map[string]string{
		"member list":    "etcd_%s_member_list",
		"cluster-health": "etcd_%s_cluster_health",
	}

	for _, pod := range pods {
		for cmd, reportFile := range etcdDumpCommands {
			etcdCmd := fmt.Sprintf(etcdctl, pod, CiliumNamespace, cmd)
			command := fmt.Sprintf("%s -n %s exec -ti %s -- %s",
				KubectlCmd, GetCiliumNamespace(GetCurrentIntegration()), pod, etcdCmd)
			reportCmds[command] = fmt.Sprintf(reportFile, pod)
		}
	}
}

// CiliumCheckReport prints a few checks on the Junit output to provide more
// context to users. The list of checks that prints are the following:
// - Number of Kubernetes and Cilium policies installed.
// - Policy enforcement status by endpoint.
// - Controller, health, kvstore status.
func (kub *Kubectl) CiliumCheckReport(ctx context.Context) {
	pods, _ := kub.GetCiliumPods(GetCiliumNamespace(GetCurrentIntegration()))
	fmt.Fprintf(CheckLogs, "Cilium pods: %v\n", pods)

	var policiesFilter = `{range .items[*]}{.metadata.namespace}{"::"}{.metadata.name}{" "}{end}`
	netpols := kub.ExecContextShort(ctx, fmt.Sprintf(
		"%s get netpol -o jsonpath='%s' --all-namespaces",
		KubectlCmd, policiesFilter))
	fmt.Fprintf(CheckLogs, "Netpols loaded: %v\n", netpols.Output())

	cnp := kub.ExecContextShort(ctx, fmt.Sprintf(
		"%s get cnp -o jsonpath='%s' --all-namespaces",
		KubectlCmd, policiesFilter))
	fmt.Fprintf(CheckLogs, "CiliumNetworkPolicies loaded: %v\n", cnp.Output())

	cepFilter := `{range .items[*]}{.metadata.name}{"="}{.status.policy.ingress.enforcing}{":"}{.status.policy.egress.enforcing}{"\n"}{end}`
	cepStatus := kub.ExecContextShort(ctx, fmt.Sprintf(
		"%s get cep -o jsonpath='%s' --all-namespaces",
		KubectlCmd, cepFilter))

	fmt.Fprintf(CheckLogs, "Endpoint Policy Enforcement:\n")

	table := tabwriter.NewWriter(CheckLogs, 5, 0, 3, ' ', 0)
	fmt.Fprintf(table, "Pod\tIngress\tEgress\n")
	for pod, policy := range cepStatus.KVOutput() {
		data := strings.SplitN(policy, ":", 2)
		if len(data) != 2 {
			data[0] = "invalid value"
			data[1] = "invalid value"
		}
		fmt.Fprintf(table, "%s\t%s\t%s\n", pod, data[0], data[1])
	}
	table.Flush()

	var controllersFilter = `{range .controllers[*]}{.name}{"="}{.status.consecutive-failure-count}::{.status.last-failure-msg}{"\n"}{end}`
	var failedControllers string
	for _, pod := range pods {
		var prefix = ""
		status := kub.CiliumExecContext(ctx, pod, "cilium status --all-controllers -o json")
		result, err := status.Filter(controllersFilter)
		if err != nil {
			kub.Logger().WithError(err).Error("Cannot filter controller status output")
			continue
		}
		var total = 0
		var failed = 0
		for name, data := range result.KVOutput() {
			total++
			status := strings.SplitN(data, "::", 2)
			if len(status) != 2 {
				// Just make sure that the the len of the output is 2 to not
				// fail on index error in the following lines.
				continue
			}
			if status[0] != "" {
				failed++
				prefix = "⚠️  "
				failedControllers += fmt.Sprintf("controller %s failure '%s'\n", name, status[1])
			}
		}
		statusFilter := `Status: {.cilium.state}  Health: {.cluster.ciliumHealth.state}` +
			` Nodes "{.cluster.nodes[*].name}" ContinerRuntime: {.container-runtime.state}` +
			` Kubernetes: {.kubernetes.state} KVstore: {.kvstore.state}`
		data, _ := status.Filter(statusFilter)
		fmt.Fprintf(CheckLogs, "%sCilium agent '%s': %s Controllers: Total %d Failed %d\n",
			prefix, pod, data, total, failed)
		if failedControllers != "" {
			fmt.Fprintf(CheckLogs, "Failed controllers:\n %s", failedControllers)
		}
	}
}

// ValidateNoErrorsInLogs checks in cilium logs since the given duration (By
// default `CurrentGinkgoTestDescription().Duration`) do not contain `panic`,
// `deadlocks` or `segmentation faults` messages. In case of any of these
// messages, it'll mark the test as failed.
func (kub *Kubectl) ValidateNoErrorsInLogs(duration time.Duration) {

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	var logs string
	cmd := fmt.Sprintf("%s -n %s logs --timestamps=true -l k8s-app=cilium --since=%vs",
		KubectlCmd, GetCiliumNamespace(GetCurrentIntegration()), duration.Seconds())
	res := kub.ExecContext(ctx, fmt.Sprintf("%s --previous", cmd), ExecOptions{SkipLog: true})
	if res.WasSuccessful() {
		logs += res.Output().String()
	}
	res = kub.ExecContext(ctx, cmd, ExecOptions{SkipLog: true})
	if res.WasSuccessful() {
		logs += res.Output().String()
	}
	defer func() {
		// Keep the cilium logs for the given test in a separate file.
		testPath, err := CreateReportDirectory()
		if err != nil {
			kub.Logger().WithError(err).Error("Cannot create report directory")
			return
		}
		err = ioutil.WriteFile(
			fmt.Sprintf("%s/%s", testPath, CiliumTestLog),
			[]byte(logs), LogPerm)

		if err != nil {
			kub.Logger().WithError(err).Errorf("Cannot create %s", CiliumTestLog)
		}
	}()

	failIfContainsBadLogMsg(logs)

	fmt.Fprintf(CheckLogs, logutils.LogErrorsSummary(logs))
}

// GatherCiliumCoreDumps copies core dumps if are present in the /tmp folder
// into the test report folder for further analysis.
func (kub *Kubectl) GatherCiliumCoreDumps(ctx context.Context, ciliumPod string) {
	log := kub.Logger().WithField("pod", ciliumPod)

	cores := kub.CiliumExecContext(ctx, ciliumPod, "ls /tmp/ | grep core")
	if !cores.WasSuccessful() {
		log.Debug("There is no core dumps in the pod")
		return
	}

	testPath, err := CreateReportDirectory()
	if err != nil {
		log.WithError(err).Errorf("cannot create test result path '%s'", testPath)
		return
	}
	resultPath := filepath.Join(kub.BasePath(), testPath)

	for _, core := range cores.ByLines() {
		dst := filepath.Join(resultPath, core)
		src := filepath.Join("/tmp/", core)
		cmd := fmt.Sprintf("%s -n %s cp %s:%s %s",
			KubectlCmd, GetCiliumNamespace(GetCurrentIntegration()),
			ciliumPod, src, dst)
		res := kub.ExecContext(ctx, cmd, ExecOptions{SkipLog: true})
		if !res.WasSuccessful() {
			log.WithField("output", res.CombineOutput()).Error("Cannot get core from pod")
		}
	}
}

// ExecInFirstPod runs given command in one pod that matches given selector and namespace
// An error is returned if no pods can be found
func (kub *Kubectl) ExecInFirstPod(ctx context.Context, namespace, selector, cmd string, options ...ExecOptions) (result *CmdRes, err error) {
	names, err := kub.GetPodNamesContext(ctx, namespace, selector)
	if err != nil {
		return nil, err
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("Cannot find pods matching %s to execute %s", selector, cmd)
	}

	for _, name := range names {
		command := fmt.Sprintf("%s exec -n %s %s -- %s", KubectlCmd, namespace, name, cmd)
		result = kub.ExecContext(ctx, command)
		break
	}

	return result, nil
}

// ExecInPods runs given command on all pods in given namespace that match selector and returns map pod-name->CmdRes
func (kub *Kubectl) ExecInPods(ctx context.Context, namespace, selector, cmd string, wait bool, options ...ExecOptions) (results map[string]*CmdRes, err error) {
	if wait {
		kub.WaitforPods(namespace, "-l "+selector, HelperTimeout)
	}
	names, err := kub.GetPodNamesContext(ctx, namespace, selector)
	if err != nil {
		return nil, err
	}

	results = make(map[string]*CmdRes)
	for _, name := range names {
		command := fmt.Sprintf("%s exec -n %s %s -- %s", KubectlCmd, namespace, name, cmd)
		results[name] = kub.ExecContext(ctx, command)
	}

	return results, nil
}

// ExecInHostNetNS runs given command in a pod running in a host network namespace
func (kub *Kubectl) ExecInHostNetNS(ctx context.Context, node, cmd string) (result *CmdRes, err error) {
	// This is a hack, as we execute the given cmd in the log-gathering pod
	// which runs in the host netns. Also, the log-gathering pods lack some
	// packages, e.g. iproute2.
	selector := fmt.Sprintf("%s --field-selector spec.nodeName=%s",
		logGathererSelector(true), node)

	return kub.ExecInFirstPod(ctx, LogGathererNamespace, selector, cmd)
}

// GetCiliumHostIPv4 retrieves cilium_host IPv4 addr of the given node.
func (kub *Kubectl) GetCiliumHostIPv4(ctx context.Context, node string) (string, error) {
	pod, err := kub.GetCiliumPodOnNode(GetCiliumNamespace(GetCurrentIntegration()), node)
	if err != nil {
		return "", fmt.Errorf("unable to retrieve cilium pod: %s", err)
	}

	cmd := "ip -4 -o a show dev cilium_host | grep -o -e 'inet [0-9.]*' | cut -d' ' -f2"
	res := kub.ExecPodCmd(GetCiliumNamespace(GetCurrentIntegration()), pod, cmd)
	if !res.WasSuccessful() {
		return "", fmt.Errorf("unable to retrieve cilium_host ipv4 addr: %s", res.GetError())
	}
	addr := res.SingleOut()
	if addr == "" {
		return "", fmt.Errorf("unable to retrieve cilium_host ipv4 addr")
	}

	return addr, nil
}

// DumpCiliumCommandOutput runs a variety of commands (CiliumKubCLICommands) and writes the results to
// TestResultsPath
func (kub *Kubectl) DumpCiliumCommandOutput(ctx context.Context, namespace string) {
	testPath, err := CreateReportDirectory()
	if err != nil {
		log.WithError(err).Errorf("cannot create test result path '%s'", testPath)
		return
	}

	ReportOnPod := func(pod string) {
		logger := kub.Logger().WithField("CiliumPod", pod)

		logsPath := filepath.Join(kub.BasePath(), testPath)

		// Get bugtool output. Since bugtool output is dumped in the pod's filesystem,
		// copy it over with `kubectl cp`.
		bugtoolCmd := fmt.Sprintf("%s exec -n %s %s -- %s",
			KubectlCmd, namespace, pod, CiliumBugtool)
		res := kub.ExecContext(ctx, bugtoolCmd, ExecOptions{SkipLog: true})
		if !res.WasSuccessful() {
			logger.Errorf("%s failed: %s", bugtoolCmd, res.CombineOutput().String())
			return
		}
		// Default output directory is /tmp for bugtool.
		res = kub.ExecContext(ctx, fmt.Sprintf("%s exec -n %s %s -- ls /tmp/", KubectlCmd, namespace, pod))
		tmpList := res.ByLines()
		for _, line := range tmpList {
			// Only copy over bugtool output to directory.
			if !strings.Contains(line, CiliumBugtool) {
				continue
			}

			res = kub.ExecContext(ctx, fmt.Sprintf("%[1]s cp %[2]s/%[3]s:/tmp/%[4]s /tmp/%[4]s",
				KubectlCmd, namespace, pod, line),
				ExecOptions{SkipLog: true})
			if !res.WasSuccessful() {
				logger.Errorf("'%s' failed: %s", res.GetCmd(), res.CombineOutput())
				continue
			}

			archiveName := filepath.Join(logsPath, fmt.Sprintf("bugtool-%s", pod))
			res = kub.ExecContext(ctx, fmt.Sprintf("mkdir -p %s", archiveName))
			if !res.WasSuccessful() {
				logger.WithField("cmd", res.GetCmd()).Errorf(
					"cannot create bugtool archive folder: %s", res.CombineOutput())
				continue
			}

			cmd := fmt.Sprintf("tar -xf /tmp/%s -C %s --strip-components=1", line, archiveName)
			res = kub.ExecContext(ctx, cmd, ExecOptions{SkipLog: true})
			if !res.WasSuccessful() {
				logger.WithField("cmd", cmd).Errorf(
					"Cannot untar bugtool output: %s", res.CombineOutput())
				continue
			}
			//Remove bugtool artifact, so it'll be not used if any other fail test
			_ = kub.ExecPodCmdBackground(ctx, namespace, pod, fmt.Sprintf("rm /tmp/%s", line))
		}

	}

	pods, err := kub.GetCiliumPodsContext(ctx, namespace)
	if err != nil {
		kub.Logger().WithError(err).Error("cannot retrieve cilium pods on ReportDump")
		return
	}

	kub.reportMapContext(ctx, testPath, ciliumKubCLICommands, namespace, CiliumSelector)

	// Finally, get kvstore output - this is best effort; we do this last
	// because if connectivity to the kvstore is broken from a cilium pod,
	// we don't want the context above to timeout and as a result, get none
	// of the other logs from the tests.

	// Use a shorter context for kvstore-related commands to avoid having
	// further log-gathering fail as well if the first Cilium pod fails to
	// gather kvstore logs.
	kvstoreCmdCtx, cancel := context.WithTimeout(ctx, MidCommandTimeout)
	defer cancel()
	kub.reportMapContext(kvstoreCmdCtx, testPath, ciliumKubCLICommandsKVStore, namespace, CiliumSelector)

	for _, pod := range pods {
		ReportOnPod(pod)
		kub.GatherCiliumCoreDumps(ctx, pod)
	}
}

// GatherLogs dumps kubernetes pods, services, DaemonSet to the testResultsPath
// directory
func (kub *Kubectl) GatherLogs(ctx context.Context) {
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

	kub.GeneratePodLogGatheringCommands(ctx, reportCmds)
	kub.EtcdOperatorReport(ctx, reportCmds)

	res := kub.ExecContext(ctx, fmt.Sprintf(`%s api-resources | grep -v "^NAME" | awk '{print $1}'`, KubectlCmd))
	if res.WasSuccessful() {
		for _, line := range res.ByLines() {
			key := fmt.Sprintf("%s get %s --all-namespaces -o wide", KubectlCmd, line)
			reportCmds[key] = fmt.Sprintf("api-resource-%s.txt", line)
		}
	} else {
		kub.Logger().Errorf("Cannot get api-resoureces: %s", res.GetDebugMessage())
	}

	testPath, err := CreateReportDirectory()
	if err != nil {
		kub.Logger().WithError(err).Errorf(
			"cannot create test results path '%s'", testPath)
		return
	}
	kub.reportMapHost(ctx, testPath, reportCmds)

	reportCmds = map[string]string{
		"journalctl --no-pager -au kubelet": "kubelet.log",
		"top -n 1 -b":                       "top.log",
		"ps aux":                            "ps.log",
	}

	kub.reportMapContext(ctx, testPath, reportCmds, LogGathererNamespace, logGathererSelector(false))
}

// GeneratePodLogGatheringCommands generates the commands to gather logs for
// all pods in the Kubernetes cluster, and maps the commands to the filename
// in which they will be stored in reportCmds.
func (kub *Kubectl) GeneratePodLogGatheringCommands(ctx context.Context, reportCmds map[string]string) {
	if reportCmds == nil {
		reportCmds = make(map[string]string)
	}
	pods, err := kub.GetAllPods(ctx, ExecOptions{SkipLog: true})
	if err != nil {
		kub.Logger().WithError(err).Error("Unable to get pods from Kubernetes via kubectl")
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

	res := kub.ExecShort(fmt.Sprintf(
		"%s -n %s get pods -l k8s-app=cilium %s", KubectlCmd, namespace, filter))
	if !res.WasSuccessful() {
		return "", fmt.Errorf("Cilium pod not found on node '%s'", node)
	}

	return res.Output().String(), nil
}

// GetCiliumPodOnNodeWithLabel returns the name of the Cilium pod that is running on node with cilium.io/ci-node label
func (kub *Kubectl) GetCiliumPodOnNodeWithLabel(namespace string, label string) (string, error) {
	node, err := kub.GetNodeNameByLabel(label)
	if err != nil {
		return "", fmt.Errorf("Unable to get nodes with label '%s': %s", label, err)
	}

	return kub.GetCiliumPodOnNode(namespace, node)
}

func (kub *Kubectl) ciliumPreFlightCheck() error {
	err := kub.ciliumStatusPreFlightCheck()
	if err != nil {
		return fmt.Errorf("status is unhealthy: %s", err)
	}

	err = kub.ciliumControllersPreFlightCheck()
	if err != nil {
		return fmt.Errorf("controllers are failing: %s", err)
	}

	switch GetCurrentIntegration() {
	case CIIntegrationFlannel:
	default:
		err = kub.ciliumHealthPreFlightCheck()
		if err != nil {
			return fmt.Errorf("connectivity health is failing: %s", err)
		}
	}
	err = kub.fillServiceCache()
	if err != nil {
		return fmt.Errorf("unable to fill service cache: %s", err)
	}
	err = kub.ciliumServicePreFlightCheck()
	if err != nil {
		return fmt.Errorf("cilium services are not set up correctly: %s", err)
	}
	err = kub.servicePreFlightCheck("kubernetes", "default")
	if err != nil {
		return fmt.Errorf("kubernetes service is not ready: %s", err)
	}

	return nil
}

// CiliumPreFlightCheck specify that it checks that various subsystems within
// Cilium are in a good state. If one of the multiple preflight fails it'll
// return an error.
func (kub *Kubectl) CiliumPreFlightCheck() error {
	ginkgoext.By("Performing Cilium preflight check")
	// Doing this withTimeout because the Status can be ready, but the other
	// nodes cannot be show up yet, and the cilium-health can fail as a false positive.
	var (
		lastError           string
		consecutiveFailures int
	)

	body := func() bool {
		if err := kub.ciliumPreFlightCheck(); err != nil {
			newError := err.Error()
			if lastError != newError || consecutiveFailures >= 5 {
				ginkgoext.GinkgoPrint("Cilium is not ready yet: %s", newError)
				lastError = newError
				consecutiveFailures = 0
			} else {
				consecutiveFailures++
			}
			return false
		}
		return true

	}
	timeoutErr := WithTimeout(body, "PreflightCheck failed", &TimeoutConfig{Timeout: HelperTimeout})
	if timeoutErr != nil {
		return fmt.Errorf("CiliumPreFlightCheck error: %s: Last polled error: %s", timeoutErr, lastError)
	}
	return nil
}

func (kub *Kubectl) ciliumStatusPreFlightCheck() error {
	ginkgoext.By("Performing Cilium status preflight check")
	ciliumPods, err := kub.GetCiliumPods(GetCiliumNamespace(GetCurrentIntegration()))
	if err != nil {
		return fmt.Errorf("cannot retrieve cilium pods: %s", err)
	}
	for _, pod := range ciliumPods {
		status := kub.CiliumExec(pod, "cilium status --all-health --all-nodes")
		if !status.WasSuccessful() {
			return fmt.Errorf("cilium-agent '%s' is unhealthy: %s", pod, status.OutputPrettyPrint())
		}
		noQuorum, err := regexp.Match(`^.*KVStore:.*has-quorum=false.*$`, status.Output().Bytes())
		if err != nil {
			return fmt.Errorf("Failed to check for kvstore quorum: %s", err.Error())
		}
		if noQuorum {
			return fmt.Errorf("KVStore doesn't have quorum: %s", status.OutputPrettyPrint())
		}
	}

	return nil
}

func (kub *Kubectl) ciliumControllersPreFlightCheck() error {
	ginkgoext.By("Performing Cilium controllers preflight check")
	var controllersFilter = `{range .controllers[*]}{.name}{"="}{.status.consecutive-failure-count}{"\n"}{end}`
	ciliumPods, err := kub.GetCiliumPods(GetCiliumNamespace(GetCurrentIntegration()))
	if err != nil {
		return fmt.Errorf("cannot retrieve cilium pods: %s", err)
	}
	for _, pod := range ciliumPods {
		status := kub.CiliumExec(pod, fmt.Sprintf(
			"cilium status --all-controllers -o jsonpath='%s'", controllersFilter))
		if !status.WasSuccessful() {
			return fmt.Errorf("cilium-agent '%s': Cannot run cilium status: %s",
				pod, status.OutputPrettyPrint())
		}
		for controller, status := range status.KVOutput() {
			if status != "0" {
				failmsg := kub.CiliumExec(pod, "cilium status --all-controllers")
				return fmt.Errorf("cilium-agent '%s': controller %s is failing: %s",
					pod, controller, failmsg.OutputPrettyPrint())
			}
		}
	}

	return nil
}

func (kub *Kubectl) ciliumHealthPreFlightCheck() error {
	if IsIntegration(CIIntegrationEKS) {
		ginkgoext.By("Skipping cilium-health --probe in EKS")
		return nil
	}

	ginkgoext.By("Performing Cilium health check")
	var nodesFilter = `{.nodes[*].name}`
	var statusFilter = `{range .nodes[*]}{.name}{"="}{.host.primary-address.http.status}{"\n"}{end}`

	ciliumPods, err := kub.GetCiliumPods(GetCiliumNamespace(GetCurrentIntegration()))
	if err != nil {
		return fmt.Errorf("cannot retrieve cilium pods: %s", err)
	}
	for _, pod := range ciliumPods {
		status := kub.CiliumExec(pod, "cilium-health status -o json --probe")
		if !status.WasSuccessful() {
			return fmt.Errorf(
				"Cluster connectivity is unhealthy on '%s': %s",
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
				"cilium-agent '%s': Only %d/%d nodes appeared in cilium-health status. nodes = '%+v'",
				pod, len(nodeCount), len(ciliumPods), nodeCount)
		}

		healthStatus, err := status.Filter(statusFilter)
		if err != nil {
			return fmt.Errorf("Cannot unmarshal health status: %s", err)
		}

		for node, status := range healthStatus.KVOutput() {
			if status != "" {
				return fmt.Errorf("cilium-agent '%s': connectivity to node '%s' is unhealthy: '%s'",
					pod, node, status)
			}
		}
	}
	return nil
}

// GetFilePath is a utility function which returns path to give fale relative to BasePath
func (kub *Kubectl) GetFilePath(filename string) string {
	return filepath.Join(kub.BasePath(), filename)
}

// serviceCache keeps service information from
// k8s, Cilium services and Cilium bpf load balancer map
type serviceCache struct {
	services  v1.ServiceList
	endpoints v1.EndpointsList
	pods      []ciliumPodServiceCache
}

// ciliumPodServiceCache
type ciliumPodServiceCache struct {
	name          string
	services      []models.Service
	loadBalancers map[string][]string
}

func (kub *Kubectl) fillServiceCache() error {
	cache := serviceCache{}

	svcRes := kub.GetFromAllNS("service")
	err := svcRes.GetErr("Unable to get k8s services")
	if err != nil {
		return err
	}
	err = svcRes.Unmarshal(&cache.services)

	if err != nil {
		return fmt.Errorf("Unable to unmarshal K8s services: %s", err.Error())
	}

	epRes := kub.GetFromAllNS("endpoints")
	err = epRes.GetErr("Unable to get k8s endpoints")
	if err != nil {
		return err
	}
	err = epRes.Unmarshal(&cache.endpoints)
	if err != nil {
		return fmt.Errorf("Unable to unmarshal K8s endpoints: %s", err.Error())
	}

	ciliumPods, err := kub.GetCiliumPods(GetCiliumNamespace(GetCurrentIntegration()))
	if err != nil {
		return fmt.Errorf("cannot retrieve cilium pods: %s", err)
	}
	ciliumSvcCmd := "cilium service list -o json"
	ciliumBpfLbCmd := "cilium bpf lb list -o json"

	cache.pods = make([]ciliumPodServiceCache, 0, len(ciliumPods))
	for _, pod := range ciliumPods {
		podCache := ciliumPodServiceCache{name: pod}

		ciliumServicesRes := kub.CiliumExec(pod, ciliumSvcCmd)
		err := ciliumServicesRes.GetErr(
			fmt.Sprintf("Unable to retrieve Cilium services on %s", pod))
		if err != nil {
			return err
		}

		err = ciliumServicesRes.Unmarshal(&podCache.services)
		if err != nil {
			return fmt.Errorf("Unable to unmarshal Cilium services: %s", err.Error())
		}

		ciliumLbRes := kub.CiliumExec(pod, ciliumBpfLbCmd)
		err = ciliumLbRes.GetErr(
			fmt.Sprintf("Unable to retrieve Cilium bpf lb list on %s", pod))
		if err != nil {
			return err
		}

		err = ciliumLbRes.Unmarshal(&podCache.loadBalancers)
		if err != nil {
			return fmt.Errorf("Unable to unmarshal Cilium bpf lb list: %s", err.Error())
		}
		cache.pods = append(cache.pods, podCache)
	}
	kub.serviceCache = &cache
	return nil
}

// KubeDNSPreFlightCheck makes sure that kube-dns is plumbed into Cilium.
func (kub *Kubectl) KubeDNSPreFlightCheck() error {
	err := kub.fillServiceCache()
	if err != nil {
		return err
	}
	return kub.servicePreFlightCheck("kube-dns", KubeSystemNamespace)
}

// servicePreFlightCheck makes sure that k8s service with given name and
// namespace is properly plumbed in Cilium
func (kub *Kubectl) servicePreFlightCheck(serviceName, serviceNamespace string) error {
	ginkgoext.By("Performing K8s service preflight check")
	var service *v1.Service
	for _, s := range kub.serviceCache.services.Items {
		if s.Name == serviceName && s.Namespace == serviceNamespace {
			service = &s
			break
		}
	}

	if service == nil {
		return fmt.Errorf("%s/%s service not found in service cache", serviceName, serviceNamespace)
	}

	for _, pod := range kub.serviceCache.pods {

		err := validateK8sService(*service, kub.serviceCache.endpoints.Items, pod.services, pod.loadBalancers)
		if err != nil {
			return fmt.Errorf("Error validating Cilium service on pod %v: %s", pod, err.Error())
		}
	}
	return nil
}

func validateK8sService(k8sService v1.Service, k8sEndpoints []v1.Endpoints, ciliumSvcs []models.Service, ciliumLB map[string][]string) error {
	var ciliumService *models.Service
CILIUM_SERVICES:
	for _, cSvc := range ciliumSvcs {
		if cSvc.Status.Realized.FrontendAddress.IP == k8sService.Spec.ClusterIP {
			for _, port := range k8sService.Spec.Ports {
				if int32(cSvc.Status.Realized.FrontendAddress.Port) == port.Port {
					ciliumService = &cSvc
					break CILIUM_SERVICES
				}
			}
		}
	}

	if ciliumService == nil {
		return fmt.Errorf("Failed to find Cilium service corresponding to %s/%s k8s service", k8sService.Namespace, k8sService.Name)
	}

	temp := map[string]bool{}
	err := validateCiliumSvc(*ciliumService, []v1.Service{k8sService}, k8sEndpoints, temp)
	if err != nil {
		return err
	}
	return validateCiliumSvcLB(*ciliumService, ciliumLB)
}

// ciliumServicePreFlightCheck checks that k8s service is plumbed correctly
func (kub *Kubectl) ciliumServicePreFlightCheck() error {
	ginkgoext.By("Performing Cilium service preflight check")
	for _, pod := range kub.serviceCache.pods {
		k8sServicesFound := map[string]bool{}

		for _, cSvc := range pod.services {
			err := validateCiliumSvc(cSvc, kub.serviceCache.services.Items, kub.serviceCache.endpoints.Items, k8sServicesFound)
			if err != nil {
				return fmt.Errorf("Error validating Cilium service on pod %v: %s", pod, err.Error())
			}
		}

		notFoundServices := make([]string, 0, len(kub.serviceCache.services.Items))
		for _, k8sSvc := range kub.serviceCache.services.Items {
			key := serviceKey(k8sSvc)
			// ignore headless services
			if k8sSvc.Spec.Type == v1.ServiceTypeClusterIP &&
				k8sSvc.Spec.ClusterIP == v1.ClusterIPNone {
				continue
			}
			// TODO(brb) check NodePort and LoadBalancer services
			if k8sSvc.Spec.Type == v1.ServiceTypeNodePort ||
				k8sSvc.Spec.Type == v1.ServiceTypeLoadBalancer {
				continue
			}
			if _, ok := k8sServicesFound[key]; !ok {
				notFoundServices = append(notFoundServices, key)
			}
		}

		if len(notFoundServices) > 0 {
			return fmt.Errorf("Failed to find Cilium service corresponding to k8s services %s on pod %v",
				strings.Join(notFoundServices, ", "), pod)
		}

		for _, cSvc := range pod.services {
			err := validateCiliumSvcLB(cSvc, pod.loadBalancers)
			if err != nil {
				return fmt.Errorf("Error validating Cilium service on pod %v: %s", pod, err.Error())
			}
		}
		if len(pod.services) != len(pod.loadBalancers) {
			return fmt.Errorf("Length of Cilium services doesn't match length of bpf LB map on pod %v", pod)
		}
	}
	return nil
}

// DeleteETCDOperator delete the etcd-operator from the cluster pointed by kub.
func (kub *Kubectl) DeleteETCDOperator() {
	if res := kub.ExecShort(fmt.Sprintf("%s -n %s delete crd etcdclusters.etcd.database.coreos.com", KubectlCmd, GetCiliumNamespace(GetCurrentIntegration()))); !res.WasSuccessful() {
		log.Warningf("Unable to delete etcdclusters.etcd.database.coreos.com CRD: %s", res.OutputPrettyPrint())
	}

	if res := kub.ExecShort(fmt.Sprintf("%s -n %s delete deployment cilium-etcd-operator", KubectlCmd, GetCiliumNamespace(GetCurrentIntegration()))); !res.WasSuccessful() {
		log.Warningf("Unable to delete cilium-etcd-operator Deployment: %s", res.OutputPrettyPrint())
	}

	if res := kub.ExecShort(fmt.Sprintf("%s delete clusterrolebinding cilium-etcd-operator", KubectlCmd)); !res.WasSuccessful() {
		log.Warningf("Unable to delete cilium-etcd-operator ClusterRoleBinding: %s", res.OutputPrettyPrint())
	}

	if res := kub.ExecShort(fmt.Sprintf("%s delete clusterrole cilium-etcd-operator", KubectlCmd)); !res.WasSuccessful() {
		log.Warningf("Unable to delete cilium-etcd-operator ClusterRole: %s", res.OutputPrettyPrint())
	}

	if res := kub.ExecShort(fmt.Sprintf("%s -n %s delete serviceaccount cilium-etcd-operator", KubectlCmd, GetCiliumNamespace(GetCurrentIntegration()))); !res.WasSuccessful() {
		log.Warningf("Unable to delete cilium-etcd-operator ServiceAccount: %s", res.OutputPrettyPrint())
	}

	if res := kub.ExecShort(fmt.Sprintf("%s delete clusterrolebinding etcd-operator", KubectlCmd)); !res.WasSuccessful() {
		log.Warningf("Unable to delete etcd-operator ClusterRoleBinding: %s", res.OutputPrettyPrint())
	}

	if res := kub.ExecShort(fmt.Sprintf("%s delete clusterrole etcd-operator", KubectlCmd)); !res.WasSuccessful() {
		log.Warningf("Unable to delete etcd-operator ClusterRole: %s", res.OutputPrettyPrint())
	}

	if res := kub.ExecShort(fmt.Sprintf("%s -n %s delete serviceaccount cilium-etcd-sa", KubectlCmd, GetCiliumNamespace(GetCurrentIntegration()))); !res.WasSuccessful() {
		log.Warningf("Unable to delete cilium-etcd-sa ServiceAccount: %s", res.OutputPrettyPrint())
	}
}

// reportMap saves the output of the given commands to the specified filename.
// Function needs a directory path where the files are going to be written
// commands are run on all pods matching selector in given namespace
func (kub *Kubectl) reportMap(path string, reportCmds map[string]string, ns, selector string) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	kub.reportMapContext(ctx, path, reportCmds, ns, selector)
}

// reportMapContext saves the output of the given commands to the specified filename.
// Function needs a directory path where the files are going to be written
// commands are run on all pods matching selector
func (kub *Kubectl) reportMapContext(ctx context.Context, path string, reportCmds map[string]string, ns, selector string) {
	for cmd, logfile := range reportCmds {
		results, err := kub.ExecInPods(ctx, ns, selector, cmd, true, ExecOptions{SkipLog: true})
		if err != nil {
			log.WithError(err).Errorf("cannot retrieve command output '%s': %s", cmd, err)
		}

		for name, res := range results {
			err := ioutil.WriteFile(
				fmt.Sprintf("%s/%s-%s", path, name, logfile),
				res.CombineOutput().Bytes(),
				LogPerm)
			if err != nil {
				log.WithError(err).Errorf("cannot create test results for command '%s' from pod %s", cmd, name)
			}
		}
	}
}

// reportMapHost saves executed commands to files based on provided map
func (kub *Kubectl) reportMapHost(ctx context.Context, path string, reportCmds map[string]string) {
	for cmd, logfile := range reportCmds {
		res := kub.ExecContext(ctx, cmd)

		if !res.WasSuccessful() {
			log.WithError(res.GetErr("reportMapHost")).Errorf("command %s failed", cmd)
		}

		err := ioutil.WriteFile(
			fmt.Sprintf("%s/%s", path, logfile),
			res.CombineOutput().Bytes(),
			LogPerm)
		if err != nil {
			log.WithError(err).Errorf("cannot create test results for command '%s'", cmd)
		}
	}
}

// HelmTemplate renders given helm template. TODO: use go helm library for that
func (kub *Kubectl) HelmTemplate(chartDir, namespace, filename string, options map[string]string) *CmdRes {
	optionsString := ""

	for k, v := range options {
		optionsString += fmt.Sprintf(" --set %s=%s ", k, v)
	}

	return kub.ExecMiddle("helm template " +
		chartDir + " " +
		fmt.Sprintf("--namespace=%s %s > %s", namespace, optionsString, filename))
}

func serviceKey(s v1.Service) string {
	return s.Namespace + "/" + s.Name
}

// validateCiliumSvc checks if given Cilium service has corresponding k8s services and endpoints in given slices
func validateCiliumSvc(cSvc models.Service, k8sSvcs []v1.Service, k8sEps []v1.Endpoints, k8sServicesFound map[string]bool) error {
	var k8sService *v1.Service

	// TODO(brb) validate NodePort and LoadBalancer services
	if cSvc.Status.Realized.Flags != nil {
		switch cSvc.Status.Realized.Flags.Type {
		case models.ServiceSpecFlagsTypeNodePort,
			models.ServiceSpecFlagsTypeExternalIPs:
			return nil
		case "LoadBalancer":
			return nil
		}
	}

	for _, k8sSvc := range k8sSvcs {
		if k8sSvc.Spec.ClusterIP == cSvc.Status.Realized.FrontendAddress.IP {
			k8sService = &k8sSvc
			break
		}
	}
	if k8sService == nil {
		return fmt.Errorf("Could not find Cilium service with ip %s in k8s", cSvc.Spec.FrontendAddress.IP)
	}

	var k8sServicePort *v1.ServicePort
	for _, k8sPort := range k8sService.Spec.Ports {
		if k8sPort.Port == int32(cSvc.Status.Realized.FrontendAddress.Port) {
			k8sServicePort = &k8sPort
			k8sServicesFound[serviceKey(*k8sService)] = true
			break
		}
	}
	if k8sServicePort == nil {
		return fmt.Errorf("Could not find Cilium service with address %s:%d in k8s", cSvc.Spec.FrontendAddress.IP, cSvc.Spec.FrontendAddress.Port)
	}

	for _, backAddr := range cSvc.Status.Realized.BackendAddresses {
		foundEp := false
		for _, k8sEp := range k8sEps {
			for _, epAddr := range getK8sEndpointAddresses(k8sEp) {
				if addrsEqual(backAddr, epAddr) {
					foundEp = true
				}
			}
		}
		if !foundEp {
			return fmt.Errorf(
				"Could not match cilium service backend address %s:%d with k8s endpoint",
				*backAddr.IP, backAddr.Port)
		}
	}
	return nil
}

func validateCiliumSvcLB(cSvc models.Service, lbMap map[string][]string) error {
	frontendAddress := cSvc.Status.Realized.FrontendAddress.IP + ":" + strconv.Itoa(int(cSvc.Status.Realized.FrontendAddress.Port))
	bpfBackends, ok := lbMap[frontendAddress]
	if !ok {
		return fmt.Errorf("%s bpf lb map entry not found", frontendAddress)
	}

BACKENDS:
	for _, addr := range cSvc.Status.Realized.BackendAddresses {
		backend := *addr.IP + ":" + strconv.Itoa(int(addr.Port))
		for _, bpfAddr := range bpfBackends {
			if strings.Contains(bpfAddr, backend) {
				continue BACKENDS
			}
		}
		return fmt.Errorf("%s not found in bpf map", backend)
	}
	return nil
}

func getK8sEndpointAddresses(ep v1.Endpoints) []*models.BackendAddress {
	result := []*models.BackendAddress{}
	for _, subset := range ep.Subsets {
		for _, addr := range subset.Addresses {
			ip := addr.IP
			for _, port := range subset.Ports {
				ba := &models.BackendAddress{
					IP:   &ip,
					Port: uint16(port.Port),
				}
				result = append(result, ba)
			}
		}
	}
	return result
}

func addrsEqual(addr1, addr2 *models.BackendAddress) bool {
	return *addr1.IP == *addr2.IP && addr1.Port == addr2.Port
}

// GenerateNamespaceForTest generates a namespace based off of the current test
// which is running.
// Note: Namespaces can only be 63 characters long (to comply with DNS). We
// ensure that the namespace here is shorter than that, but keep it unique by
// hashing the complete name.
func GenerateNamespaceForTest() string {
	lowered := strings.ToLower(ginkgoext.CurrentGinkgoTestDescription().FullTestText)
	// K8s namespaces cannot have spaces or underscores.
	replaced := strings.Replace(lowered, " ", "", -1)
	replaced = strings.Replace(replaced, "_", "", -1)

	if len(replaced) <= 63 {
		return replaced
	}

	// We need to shorten the name to <=63 characters
	// Hash the name, encode it as hex, then put it all together
	h := md5.Sum(([]byte)(replaced[0:]))
	hash := hex.EncodeToString(h[:])
	out := []byte(replaced[:56])
	out = append(out, []byte("-")...)
	out = append(out, hash[:6]...)
	return string(out)
}

// TimestampFilename appends a "timestamp" to the name. The goal is to make this
// name unique to avoid collisions in tests. The nanosecond precision should be
// more than enough for that.
func TimestampFilename(name string) string {
	// Split the name, then reassemble it so we can generate
	// filename-abcdef.extension
	parts := strings.Split(name, ".")
	extension := parts[len(parts)-1]
	filename := strings.Join(parts[:len(parts)-1], "")

	return fmt.Sprintf("%s-%x.%s", filename, time.Now().UnixNano(), extension)
}

// logGathererSelector returns selector for log-gatherer pods which run on each
// node in a host netns.
//
// If NO_CILIUM_ON_NODE is non empty and allNodes is not set, then the returned
// selector will exclude log-gatherer running on the NO_CILIUM_ON_NODE node.
func logGathererSelector(allNodes bool) string {
	selector := "k8s-app=cilium-test-logs"

	if allNodes {
		return selector
	}

	if nodeName := GetNodeWithoutCilium(); nodeName != "" {
		selector = fmt.Sprintf("%s --field-selector='spec.nodeName!=%s'", selector, nodeName)
	}

	return selector
}
