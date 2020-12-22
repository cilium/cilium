// Copyright 2018-2020 Authors of Cilium
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
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	cnpv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/test/config"
	ginkgoext "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers/logutils"

	"github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
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
	DNSHelperTimeout = 7 * time.Minute

	// CIIntegrationFlannel contains the constant to be used when flannel is
	// used in the CI.
	CIIntegrationFlannel = "flannel"

	// CIIntegrationEKSChaining contains the constants to be used when running tests on EKS with aws-cni in chaining mode.
	CIIntegrationEKSChaining = "eks-chaining"

	// CIIntegrationEKS contains the constants to be used when running tests on EKS in ENI mode.
	CIIntegrationEKS = "eks"

	// CIIntegrationGKE contains the constants to be used when running tests on GKE.
	CIIntegrationGKE = "gke"

	// CIIntegrationKind contains the constant to be used when running tests on kind.
	CIIntegrationKind = "kind"

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
		"image.repository":              "k8s1:5000/cilium/cilium-dev",
		"image.tag":                     "latest",
		"preflight.image.repository":    "k8s1:5000/cilium/cilium-dev", // Set again in init to match agent.image!
		"preflight.image.tag":           "latest",
		"operator.image.repository":     "k8s1:5000/cilium/operator",
		"operator.image.tag":            "latest",
		"hubble.relay.image.repository": "k8s1:5000/cilium/hubble-relay",
		"hubble.relay.image.tag":        "latest",
		"debug.enabled":                 "true",
		"k8s.requireIPv4PodCIDR":        "true",
		"pprof.enabled":                 "true",
		"logSystemLoad":                 "true",
		"bpf.preallocateMaps":           "true",
		"etcd.leaseTTL":                 "30s",
		"ipv4.enabled":                  "true",
		"ipv6.enabled":                  "true",
		// "extraEnv[0].name":              "KUBE_CACHE_MUTATION_DETECTOR",
		// "extraEnv[0].value":             "true",
		"bpf.masquerade": "true",
		// Disable by default, so that 4.9 CI build does not panic due to
		// missing LRU support. On 4.19 and net-next we enable it with
		// kubeProxyReplacement=strict.
		"sessionAffinity": "false",

		// Enable embedded Hubble, both on unix socket and TCP port 4244.
		"hubble.enabled":       "true",
		"hubble.listenAddress": ":4244",

		// We need CNP node status to know when a policy is being enforced
		"enableCnpStatusUpdates": "true",
		"nativeRoutingCIDR":      "10.0.0.0/8",
	}

	flannelHelmOverrides = map[string]string{
		"flannel.enabled": "true",
		"ipv6.enabled":    "false",
		"tunnel":          "disabled",
	}

	eksChainingHelmOverrides = map[string]string{
		"k8s.requireIPv4PodCIDR": "false",
		"cni.chainingMode":       "aws-cni",
		"masquerade":             "false",
		"tunnel":                 "disabled",
		"nodeinit.enabled":       "true",
	}

	eksHelmOverrides = map[string]string{
		"egressMasqueradeInterfaces": "eth0",
		"eni":                        "true",
		"ipam.mode":                  "eni",
		"ipv6.enabled":               "false",
		"k8s.requireIPv4PodCIDR":     "false",
		"nodeinit.enabled":           "true",
		"tunnel":                     "disabled",
	}

	gkeHelmOverrides = map[string]string{
		"ipv6.enabled":                "false",
		"nodeinit.enabled":            "true",
		"nodeinit.reconfigureKubelet": "true",
		"nodeinit.removeCbrBridge":    "true",
		"nodeinit.restartPods":        "true",
		"cni.binPath":                 "/home/kubernetes/bin",
		"gke.enabled":                 "true",
		"loadBalancer.mode":           "snat",
		"nativeRoutingCIDR":           "10.0.0.0/8",
		"hostFirewall":                "false",
		"ipam.mode":                   "kubernetes",
		"devices":                     "", // Override "eth0 eth0\neth0"
	}

	microk8sHelmOverrides = map[string]string{
		"cni.confPath":      "/var/snap/microk8s/current/args/cni-network",
		"cni.binPath":       "/var/snap/microk8s/current/opt/cni/bin",
		"cni.customConf":    "true",
		"daemon.runPath":    "/var/snap/microk8s/current/var/run/cilium",
		"image.pullPolicy":  "IfNotPresent",
		"ipv6.enabled":      "false",
		"operator.replicas": "1",
	}
	minikubeHelmOverrides = map[string]string{
		"ipv6.enabled":           "false",
		"bpf.preallocateMaps":    "false",
		"k8s.requireIPv4PodCIDR": "false",
	}
	kindHelmOverrides = map[string]string{
		"ipv6.enabled":         "false",
		"hostFirewall":         "false",
		"nodeinit.enabled":     "true",
		"kubeProxyReplacement": "partial",
		"externalIPs.enabled":  "true",
		"ipam.mode":            "kubernetes",
	}

	// helmOverrides allows overriding of cilium-agent options for
	// specific CI environment integrations.
	// The key must be a string consisting of lower case characters.
	helmOverrides = map[string]map[string]string{
		CIIntegrationFlannel:     flannelHelmOverrides,
		CIIntegrationEKSChaining: eksChainingHelmOverrides,
		CIIntegrationEKS:         eksHelmOverrides,
		CIIntegrationGKE:         gkeHelmOverrides,
		CIIntegrationKind:        kindHelmOverrides,
		CIIntegrationMicrok8s:    microk8sHelmOverrides,
		CIIntegrationMinikube:    minikubeHelmOverrides,
	}

	// resourcesToClean is the list of resources which should be cleaned
	// from default namespace before tests are being run. It's not possible
	// to delete all resources as services like "kubernetes" must be
	// preserved. This helps reduce contamination between tests if tests
	// are leaking resources into the default namespace for some reason.
	resourcesToClean = []string{
		"deployment",
		"daemonset",
		"rs",
		"rc",
		"statefulset",
		"pods",
		"netpol",
		"cnp",
		"cep",
	}
)

// HelmOverride returns the value of a Helm override option for the currently
// enabled CNI_INTEGRATION
func HelmOverride(option string) string {
	integration := strings.ToLower(os.Getenv("CNI_INTEGRATION"))
	if overrides, exists := helmOverrides[integration]; exists {
		return overrides[option]
	}
	return ""
}

// NativeRoutingEnabled returns true when native routing is enabled for a
// particular CNI_INTEGRATION
func NativeRoutingEnabled() bool {
	tunnelDisabled := HelmOverride("tunnel") == "disabled"
	gkeEnabled := HelmOverride("gke.enabled") == "true"
	return tunnelDisabled || gkeEnabled
}

func Init() {
	if config.CiliumTestConfig.CiliumImage != "" {
		os.Setenv("CILIUM_IMAGE", config.CiliumTestConfig.CiliumImage)
	}

	if config.CiliumTestConfig.CiliumTag != "" {
		os.Setenv("CILIUM_TAG", config.CiliumTestConfig.CiliumTag)
	}

	if config.CiliumTestConfig.CiliumOperatorImage != "" {
		os.Setenv("CILIUM_OPERATOR_IMAGE", config.CiliumTestConfig.CiliumOperatorImage)
	}

	if config.CiliumTestConfig.CiliumOperatorTag != "" {
		os.Setenv("CILIUM_OPERATOR_TAG", config.CiliumTestConfig.CiliumOperatorTag)
	}

	if config.CiliumTestConfig.HubbleRelayImage != "" {
		os.Setenv("HUBBLE_RELAY_IMAGE", config.CiliumTestConfig.HubbleRelayImage)
	}

	if config.CiliumTestConfig.HubbleRelayTag != "" {
		os.Setenv("HUBBLE_RELAY_TAG", config.CiliumTestConfig.HubbleRelayTag)
	}

	if config.CiliumTestConfig.ProvisionK8s == false {
		os.Setenv("SKIP_K8S_PROVISION", "true")
	}

	// Copy over envronment variables that are passed in.
	for envVar, helmVar := range map[string]string{
		"CILIUM_TAG":            "image.tag",
		"CILIUM_IMAGE":          "image.repository",
		"CILIUM_OPERATOR_TAG":   "operator.image.tag",
		"CILIUM_OPERATOR_IMAGE": "operator.image.repository",
		"HUBBLE_RELAY_IMAGE":    "hubble.relay.image.repository",
		"HUBBLE_RELAY_TAG":      "hubble.relay.image.tag",
	} {
		if v := os.Getenv(envVar); v != "" {
			defaultHelmOptions[helmVar] = v
		}
	}

	// preflight must match the cilium agent image (that's the point)
	defaultHelmOptions["preflight.image.repository"] = defaultHelmOptions["image.repository"]
	defaultHelmOptions["preflight.image.tag"] = defaultHelmOptions["image.tag"]
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

	// Make sure the namespace Cilium uses exists.
	if err := k.EnsureNamespaceExists(CiliumNamespace); err != nil {
		ginkgoext.Failf("failed to ensure the namespace %s exists: %s", CiliumNamespace, err)
	}

	res := k.Apply(ApplyOptions{FilePath: filepath.Join(k.BasePath(), manifestsPath, "log-gatherer.yaml"), Namespace: LogGathererNamespace})
	if !res.WasSuccessful() {
		ginkgoext.Fail(fmt.Sprintf("Cannot connect to k8s cluster, output:\n%s", res.CombineOutput().String()), 1)
		return nil
	}
	if err := k.WaitforPods(LogGathererNamespace, "-l "+logGathererSelector(true), HelperTimeout); err != nil {
		ginkgoext.Fail(fmt.Sprintf("Failed waiting for log-gatherer pods: %s", err), 1)
		return nil
	}

	// Clean any leftover resources in the default namespace
	k.CleanNamespace(DefaultNamespace)

	return k
}

// DaemonSetIsReady validate that a DaemonSet is scheduled on all required
// nodes and all pods are ready. If this condition is not met, an error is
// returned. If all pods are ready, then the number of pods is returned.
func (kub *Kubectl) DaemonSetIsReady(namespace, daemonset string) (int, error) {
	fullName := namespace + "/" + daemonset

	res := kub.ExecShort(fmt.Sprintf("%s -n %s get daemonset %s -o json", KubectlCmd, namespace, daemonset))
	if !res.WasSuccessful() {
		return 0, fmt.Errorf("unable to retrieve daemonset %s: %s", fullName, res.OutputPrettyPrint())
	}

	d := &appsv1.DaemonSet{}
	err := res.Unmarshal(d)
	if err != nil {
		return 0, fmt.Errorf("unable to unmarshal DaemonSet %s: %s", fullName, err)
	}

	if d.Status.DesiredNumberScheduled == 0 {
		return 0, fmt.Errorf("desired number of pods is zero")
	}

	if d.Status.CurrentNumberScheduled != d.Status.DesiredNumberScheduled {
		return 0, fmt.Errorf("only %d of %d desired pods are scheduled", d.Status.CurrentNumberScheduled, d.Status.DesiredNumberScheduled)
	}

	if d.Status.NumberAvailable != d.Status.DesiredNumberScheduled {
		return 0, fmt.Errorf("only %d of %d desired pods are ready", d.Status.NumberAvailable, d.Status.DesiredNumberScheduled)
	}

	return int(d.Status.DesiredNumberScheduled), nil
}

// AddRegistryCredentials adds a registry credentials secret into the
// cluster
func (kub *Kubectl) AddRegistryCredentials(cred string, registry string) error {
	if len(cred) == 0 || cred == ":" {
		return nil
	}
	if kub.ExecShort(fmt.Sprintf("%s get secret regcred", KubectlCmd)).WasSuccessful() {
		return nil
	}
	up := strings.SplitN(cred, ":", 2)
	if len(up) != 2 {
		return fmt.Errorf("registry credentials had an invalid format")
	}

	cmd := fmt.Sprintf("%s secret docker-registry regcred --docker-server=%s --docker-username=%s --docker-password=%s", KubectlCmd, registry, up[0], up[1])
	if !kub.ExecShort(cmd).WasSuccessful() {
		return fmt.Errorf("unable to create registry credentials")
	}
	return nil
}

// WaitForCiliumReadiness waits for the Cilium DaemonSet to become ready.
// Readiness is achieved when all Cilium pods which are desired to run on a
// node are in ready state.
func (kub *Kubectl) WaitForCiliumReadiness(offset int, errMsg string) {
	ginkgoext.By("Waiting for Cilium to become ready")
	gomega.EventuallyWithOffset(1+offset, func() error {
		numPods, err := kub.DaemonSetIsReady(CiliumNamespace, "cilium")
		if err != nil {
			ginkgoext.By("Cilium DaemonSet not ready yet: %s", err)
		} else {
			ginkgoext.By("Number of ready Cilium pods: %d", numPods)
		}
		return err
	}, 4*time.Minute, time.Second).Should(gomega.BeNil(), errMsg)
}

// DeleteResourceInAnyNamespace deletes all objects with the provided name of
// the specified resource type in all namespaces.
func (kub *Kubectl) DeleteResourcesInAnyNamespace(resource string, names []string) error {
	cmd := KubectlCmd + " get " + resource + " --all-namespaces -o json | jq -r '[ .items[].metadata | (.namespace + \"/\" + .name) ]'"
	res := kub.ExecShort(cmd)
	if !res.WasSuccessful() {
		return fmt.Errorf("unable to retrieve %s in all namespaces '%s': %s", resource, cmd, res.OutputPrettyPrint())
	}

	var allNames []string
	if err := res.Unmarshal(&allNames); err != nil {
		return fmt.Errorf("unable to unmarshal string slice '%#v': %s", res.OutputPrettyPrint(), err)
	}

	namesMap := map[string]struct{}{}
	for _, name := range names {
		namesMap[name] = struct{}{}
	}

	for _, combinedName := range allNames {
		parts := strings.SplitN(combinedName, "/", 2)
		if len(parts) != 2 {
			return fmt.Errorf("The %s idenfifier '%s' is not in the form <namespace>/<name>", resource, combinedName)
		}
		namespace, name := parts[0], parts[1]
		if _, ok := namesMap[name]; ok {
			ginkgoext.By("Deleting %s %s in namespace %s", resource, name, namespace)
			cmd = KubectlCmd + " -n " + namespace + " delete " + resource + " " + name
			res = kub.ExecShort(cmd)
			if !res.WasSuccessful() {
				return fmt.Errorf("unable to delete %s %s in namespaces %s with command '%s': %s",
					resource, name, namespace, cmd, res.OutputPrettyPrint())
			}
		}
	}

	return nil
}

// ParallelResourceDelete deletes all instances of a resource in a namespace
// based on the list of names provided. Waits until all delete API calls
// return.
func (kub *Kubectl) ParallelResourceDelete(namespace, resource string, names []string) {
	ginkgoext.By("Deleting %s [%s] in namespace %s", resource, strings.Join(names, ","), namespace)
	var wg sync.WaitGroup
	for _, name := range names {
		wg.Add(1)
		go func(name string) {
			cmd := fmt.Sprintf("%s -n %s delete %s %s",
				KubectlCmd, namespace, resource, name)
			res := kub.ExecShort(cmd)
			if !res.WasSuccessful() {
				ginkgoext.By("Unable to delete %s %s with '%s': %s",
					resource, name, cmd, res.OutputPrettyPrint())

			}
			wg.Done()
		}(name)
	}
	ginkgoext.By("Waiting for %d deletes to return (%s)",
		len(names), strings.Join(names, ","))
	wg.Wait()
}

// DeleteAllResourceInNamespace deletes all instances of a resource in a namespace
func (kub *Kubectl) DeleteAllResourceInNamespace(namespace, resource string) {
	cmd := fmt.Sprintf("%s -n %s get %s -o json | jq -r '[ .items[].metadata.name ]'",
		KubectlCmd, namespace, resource)
	res := kub.ExecShort(cmd)
	if !res.WasSuccessful() {
		ginkgoext.By("Unable to retrieve list of resource '%s' with '%s': %s",
			resource, cmd, res.stdout.Bytes())
		return
	}

	if len(res.stdout.Bytes()) > 0 {
		var nameList []string
		if err := res.Unmarshal(&nameList); err != nil {
			ginkgoext.By("Unable to unmarshal string slice '%#v': %s",
				res.OutputPrettyPrint(), err)
			return
		}

		if len(nameList) > 0 {
			kub.ParallelResourceDelete(namespace, resource, nameList)
		}
	}
}

// CleanNamespace removes all artifacts from a namespace
func (kub *Kubectl) CleanNamespace(namespace string) {
	var wg sync.WaitGroup

	for _, resource := range resourcesToClean {
		wg.Add(1)
		go func(resource string) {
			kub.DeleteAllResourceInNamespace(namespace, resource)
			wg.Done()

		}(resource)
	}
	wg.Wait()
}

// DeleteAllInNamespace deletes all namespaces except the ones provided in the
// exception list
func (kub *Kubectl) DeleteAllNamespacesExcept(except []string) error {
	cmd := KubectlCmd + " get namespace -o json | jq -r '[ .items[].metadata.name ]'"
	res := kub.ExecShort(cmd)
	if !res.WasSuccessful() {
		return fmt.Errorf("unable to retrieve all namespaces with '%s': %s", cmd, res.OutputPrettyPrint())
	}

	var namespaceList []string
	if err := res.Unmarshal(&namespaceList); err != nil {
		return fmt.Errorf("unable to unmarshal string slice '%#v': %s", namespaceList, err)
	}

	exceptMap := map[string]struct{}{}
	for _, e := range except {
		exceptMap[e] = struct{}{}
	}

	for _, namespace := range namespaceList {
		if _, ok := exceptMap[namespace]; !ok {
			kub.NamespaceDelete(namespace)
		}
	}

	return nil
}

// PrepareCluster will prepare the cluster to run tests. It will:
// - Delete all existing namespaces
// - Label all nodes so the tests can use them
func (kub *Kubectl) PrepareCluster() {
	ginkgoext.By("Preparing cluster")
	err := kub.DeleteAllNamespacesExcept([]string{
		KubeSystemNamespace,
		CiliumNamespace,
		"default",
		"kube-node-lease",
		"kube-public",
		"container-registry",
		"cilium-ci-lock",
		"prom",
	})
	if err != nil {
		ginkgoext.Failf("Unable to delete non-essential namespaces: %s", err)
	}

	ginkgoext.By("Labelling nodes")
	if err = kub.labelNodes(); err != nil {
		ginkgoext.Failf("unable label nodes: %s", err)
	}
	err = kub.AddRegistryCredentials(config.CiliumTestConfig.RegistryCredentials, config.RegistryDomain)
	if err != nil {
		ginkgoext.Failf("unable to add registry credentials to cluster: %s", err)
	}
}

// labelNodes labels all Kubernetes nodes for use by the CI tests
func (kub *Kubectl) labelNodes() error {
	cmd := KubectlCmd + " get nodes -o json | jq -r '[ .items[] | select(.metadata.labels[\"node-role.kubernetes.io/controlplane\"] == null).metadata.name ]'"
	res := kub.ExecShort(cmd)
	if !res.WasSuccessful() {
		return fmt.Errorf("unable to retrieve all nodes with '%s': %s", cmd, res.OutputPrettyPrint())
	}

	var nodesList []string
	if err := res.Unmarshal(&nodesList); err != nil {
		return fmt.Errorf("unable to unmarshal string slice '%#v': %s", nodesList, err)
	}

	index := 1
	for _, nodeName := range nodesList {
		cmd := fmt.Sprintf("%s label --overwrite node %s cilium.io/ci-node=k8s%d", KubectlCmd, nodeName, index)
		res := kub.ExecShort(cmd)
		if !res.WasSuccessful() {
			return fmt.Errorf("unable to label node with '%s': %s", cmd, res.OutputPrettyPrint())
		}
		index++
	}

	node := GetNodeWithoutCilium()
	if node != "" {
		// Prevent scheduling any pods on the node, as it will be used as an external client
		// to send requests to k8s{1,2}
		cmd := fmt.Sprintf("%s taint --overwrite nodes %s key=value:NoSchedule", KubectlCmd, node)
		res := kub.ExecMiddle(cmd)
		if !res.WasSuccessful() {
			return fmt.Errorf("unable to taint node with '%s': %s", cmd, res.OutputPrettyPrint())
		}
	}

	return nil
}

// GetCiliumEndpoint returns the CiliumEndpoint for the specified pod.
func (kub *Kubectl) GetCiliumEndpoint(namespace string, pod string) (*cnpv2.EndpointStatus, error) {
	fullName := namespace + "/" + pod
	cmd := fmt.Sprintf("%s -n %s get cep %s -o json | jq '.status'", KubectlCmd, namespace, pod)
	res := kub.ExecShort(cmd)
	if !res.WasSuccessful() {
		return nil, fmt.Errorf("unable to run command '%s' to retrieve CiliumEndpoint %s: %s",
			cmd, fullName, res.OutputPrettyPrint())
	}

	if len(res.stdout.Bytes()) == 0 {
		return nil, fmt.Errorf("CiliumEndpoint does not exist")
	}

	var data *cnpv2.EndpointStatus
	err := res.Unmarshal(&data)
	if err != nil {
		return nil, fmt.Errorf("unable to unmarshal CiliumEndpoint %s: %s", fullName, err)
	}

	return data, nil
}

// GetCiliumHostEndpointID returns the ID of the host endpoint on a given node.
func (kub *Kubectl) GetCiliumHostEndpointID(ciliumPod string) (int64, error) {
	cmd := fmt.Sprintf("cilium endpoint list -o jsonpath='{[?(@.status.identity.id==%d)].id}'",
		ReservedIdentityHost)
	res := kub.CiliumExecContext(context.Background(), ciliumPod, cmd)
	if !res.WasSuccessful() {
		return 0, fmt.Errorf("unable to run command '%s' to retrieve ID of host endpoint from %s: %s",
			cmd, ciliumPod, res.OutputPrettyPrint())
	}

	hostEpID, err := strconv.ParseInt(strings.TrimSpace(res.Stdout()), 10, 64)
	if err != nil || hostEpID == 0 {
		return 0, fmt.Errorf("incorrect host endpoint ID %s: %s",
			strings.TrimSpace(res.Stdout()), err)
	}
	return hostEpID, nil
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

// CountMissedTailCalls returns the number of the sum of all drops due to
// missed tail calls that happened on all Cilium-managed nodes.
func (kub *Kubectl) CountMissedTailCalls() (int, error) {
	ciliumPods, err := kub.GetCiliumPods()
	if err != nil {
		return -1, err
	}

	totalMissedTailCalls := 0
	for _, ciliumPod := range ciliumPods {
		cmd := "cilium metrics list -o json | jq '.[] | select( .name == \"cilium_drop_count_total\" and .labels.reason == \"Missed tail call\" ).value'"
		res := kub.CiliumExecContext(context.Background(), ciliumPod, cmd)
		if !res.WasSuccessful() {
			return -1, fmt.Errorf("Failed to run %s in pod %s: %s", cmd, ciliumPod, res.CombineOutput())
		}
		if res.Stdout() == "" {
			return 0, nil
		}

		for _, cnt := range res.ByLines() {
			nbMissedTailCalls, err := strconv.Atoi(cnt)
			if err != nil {
				return -1, err
			}
			totalMissedTailCalls += nbMissedTailCalls
		}
	}

	return totalMissedTailCalls, nil
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
	command := fmt.Sprintf("%s exec -n %s %s -- %s", KubectlCmd, namespace, pod, arg)
	res := kub.Exec(command)
	if !res.WasSuccessful() {
		return fmt.Errorf("ExecKafkaPodCmd: command '%s' failed %s",
			res.GetCmd(), res.OutputPrettyPrint())
	}

	if strings.Contains(res.Stderr(), "ERROR") {
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
		return len(regex.FindAllString(res.Stdout(), -1)) == count
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

// GetPodOnNodeLabeledWithOffset retrieves name and ip of a pod matching filter and residing on a node with label cilium.io/ci-node=<label>
func (kub *Kubectl) GetPodOnNodeLabeledWithOffset(label string, podFilter string, callOffset int) (string, string) {
	callOffset++

	nodeName, err := kub.GetNodeNameByLabel(label)
	gomega.ExpectWithOffset(callOffset, err).Should(gomega.BeNil())
	gomega.ExpectWithOffset(callOffset, nodeName).ShouldNot(gomega.BeEmpty(), "Cannot retrieve node name with label cilium.io/ci-node=%s", label)

	var podName string

	podsNodes, err := kub.GetPodsNodes(DefaultNamespace, fmt.Sprintf("-l %s", podFilter))
	gomega.ExpectWithOffset(callOffset, err).Should(gomega.BeNil(), "Cannot retrieve pods nodes with filter %q", podFilter)
	gomega.Expect(podsNodes).ShouldNot(gomega.BeEmpty(), "No pod found in namespace %s with filter %q", DefaultNamespace, podFilter)
	for pod, node := range podsNodes {
		if node == nodeName {
			podName = pod
			break
		}
	}
	gomega.ExpectWithOffset(callOffset, podName).ShouldNot(gomega.BeEmpty(), "Cannot retrieve pod on node %s with filter %q", nodeName, podFilter)
	podsIPs, err := kub.GetPodsIPs(DefaultNamespace, podFilter)
	gomega.ExpectWithOffset(callOffset, err).Should(gomega.BeNil(), "Cannot retrieve pods IPs with filter %q", podFilter)
	gomega.Expect(podsIPs).ShouldNot(gomega.BeEmpty(), "No pod IP found in namespace %s with filter %q", DefaultNamespace, podFilter)
	podIP := podsIPs[podName]
	return podName, podIP
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

// GetPodsHostIPs returns a map with pod name as a key and host IP name as value. It
// only gets pods in the given namespace that match the provided filter. It
// returns an error if pods cannot be retrieved correctly
func (kub *Kubectl) GetPodsHostIPs(namespace string, label string) (map[string]string, error) {
	jsonFilter := `{range .items[*]}{@.metadata.name}{"="}{@.status.hostIP}{"\n"}{end}`
	res := kub.ExecShort(fmt.Sprintf("%s -n %s get pods -l %s -o jsonpath='%s'",
		KubectlCmd, namespace, label, jsonFilter))
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

	getPodsCtx, cancel := context.WithTimeout(ctx, MidCommandTimeout)
	defer cancel()

	var podsList v1.List
	res := kub.ExecContext(getPodsCtx,
		fmt.Sprintf("%s get pods --all-namespaces -o json", KubectlCmd),
		ExecOptions{SkipLog: ops.SkipLog})

	if !res.WasSuccessful() {
		return nil, res.GetError()
	}

	err := res.Unmarshal(&podsList)
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

	out := strings.Trim(res.Stdout(), "\n")

	if len(out) == 0 {
		return "", fmt.Errorf("no matching node to read name with label '%v'", label)
	}

	return out, nil
}

// GetNodeIPByLabel returns the IP of the node with cilium.io/ci-node=label.
// An error is returned if a node cannot be found.
func (kub *Kubectl) GetNodeIPByLabel(label string, external bool) (string, error) {
	ipType := "InternalIP"
	if external {
		ipType = "ExternalIP"
	}
	filter := `{@.items[*].status.addresses[?(@.type == "` + ipType + `")].address}`
	res := kub.ExecShort(fmt.Sprintf("%s get nodes -l cilium.io/ci-node=%s -o jsonpath='%s'",
		KubectlCmd, label, filter))
	if !res.WasSuccessful() {
		return "", fmt.Errorf("cannot retrieve node to read IP: %s", res.CombineOutput())
	}

	out := strings.Trim(res.Stdout(), "\n")
	if len(out) == 0 {
		return "", fmt.Errorf("no matching node to read IP with label '%v'", label)
	}

	return out, nil
}

func (kub *Kubectl) getIfaceByIPAddr(label string, ipAddr string) (string, error) {
	cmd := fmt.Sprintf(
		`ip -j a s  | jq -r '.[] | select(.addr_info[] | .local == "%s") | .ifname'`,
		ipAddr)
	iface, err := kub.ExecInHostNetNSByLabel(context.TODO(), label, cmd)
	if err != nil {
		return "", fmt.Errorf("Failed to retrieve iface by IP addr: %s", err)
	}

	return strings.Trim(iface, "\n"), nil
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

// MonitorStart runs cilium monitor in the background and returns the command
// result, CmdRes, along with a cancel function. The cancel function is used to
// stop the monitor.
func (kub *Kubectl) MonitorStart(pod string) (res *CmdRes, cancel func()) {
	cmd := fmt.Sprintf("%s exec -n %s %s -- cilium monitor -vv", KubectlCmd, CiliumNamespace, pod)
	ctx, cancel := context.WithCancel(context.Background())

	return kub.ExecInBackground(ctx, cmd, ExecOptions{SkipLog: true}), cancel
}

// MonitorEndpointStart runs cilium monitor only on a specified endpoint. This
// function is the same as MonitorStart.
func (kub *Kubectl) MonitorEndpointStart(pod string, epID int64) (res *CmdRes, cancel func()) {
	cmd := fmt.Sprintf("%s exec -n %s %s -- cilium monitor -vv --related-to %d",
		KubectlCmd, CiliumNamespace, pod, epID)
	ctx, cancel := context.WithCancel(context.Background())

	return kub.ExecInBackground(ctx, cmd, ExecOptions{SkipLog: true}), cancel
}

// BackgroundReport dumps the result of the given commands on cilium pods each
// five seconds.
func (kub *Kubectl) BackgroundReport(commands ...string) (context.CancelFunc, error) {
	backgroundCtx, cancel := context.WithCancel(context.Background())
	retrieveInfo := func() {
		pods, err := kub.GetCiliumPods()
		if err != nil {
			kub.Logger().Infof("failed to retrieve cilium pods: %s", err)
			return
		}
		if len(pods) == 0 {
			kub.Logger().Infof("no cilium pods found")
			return
		}
		for _, pod := range pods {
			for _, cmd := range commands {
				kub.CiliumExecContext(context.TODO(), pod, cmd)
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
		res := kub.ExecPodCmd(CiliumNamespace, pod, "gops pprof-cpu 1")
		if !res.WasSuccessful() {
			log.Errorf("cannot execute pprof: %s", res.OutputPrettyPrint())
			return
		}
		files := kub.ExecPodCmd(CiliumNamespace, pod, `ls -1 /tmp/`)
		for _, file := range files.ByLines() {
			if !strings.Contains(file, "profile") {
				continue
			}

			dest := filepath.Join(
				kub.BasePath(), testPath,
				fmt.Sprintf("%s-profile-%s.pprof", pod, file))
			_ = kub.Exec(fmt.Sprintf("%[1]s cp %[2]s/%[3]s:/tmp/%[4]s %[5]s",
				KubectlCmd, CiliumNamespace, pod, file, dest),
				ExecOptions{SkipLog: true})

			_ = kub.ExecPodCmd(CiliumNamespace, pod, fmt.Sprintf(
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

			pods, err := kub.GetCiliumPods()
			if err != nil {
				log.Errorf("cannot get cilium pods")
			}

			for _, pod := range pods {
				retrievePProf(pod, testPath)
			}

		}
	}
}

// NamespaceCreate creates a new Kubernetes namespace with the given name
func (kub *Kubectl) NamespaceCreate(name string) *CmdRes {
	ginkgoext.By("Creating namespace %s", name)
	kub.ExecShort(fmt.Sprintf("%s delete namespace %s", KubectlCmd, name))
	return kub.ExecShort(fmt.Sprintf("%s create namespace %s", KubectlCmd, name))
}

// NamespaceDelete deletes a given Kubernetes namespace
func (kub *Kubectl) NamespaceDelete(name string) *CmdRes {
	ginkgoext.By("Deleting namespace %s", name)
	if err := kub.DeleteAllInNamespace(name); err != nil {
		kub.Logger().Infof("Error while deleting all objects from %s ns: %s", name, err)
	}
	res := kub.ExecShort(fmt.Sprintf("%s delete namespace %s", KubectlCmd, name))
	if !res.WasSuccessful() {
		kub.Logger().Infof("Error while deleting ns %s: %s", name, res.GetError())
	}
	return kub.ExecShort(fmt.Sprintf(
		"%[1]s get namespace %[2]s -o json | tr -d \"\\n\" | sed \"s/\\\"finalizers\\\": \\[[^]]\\+\\]/\\\"finalizers\\\": []/\" | %[1]s replace --raw /api/v1/namespaces/%[2]s/finalize -f -", KubectlCmd, name))

}

// EnsureNamespaceExists creates a namespace, ignoring the AlreadyExists error.
func (kub *Kubectl) EnsureNamespaceExists(name string) error {
	ginkgoext.By("Ensuring the namespace %s exists", name)
	res := kub.ExecShort(fmt.Sprintf("%s create namespace %s", KubectlCmd, name))
	if !res.success && !strings.Contains(res.Stderr(), "AlreadyExists") {
		return res.err
	}
	return nil
}

// DeleteAllInNamespace deletes all k8s objects in a namespace
func (kub *Kubectl) DeleteAllInNamespace(name string) error {
	// we are getting all namespaced resources from k8s apiserver, and delete all objects of these types in a provided namespace
	cmd := fmt.Sprintf("%s delete $(%s api-resources --namespaced=true --verbs=delete -o name | tr '\n' ',' | sed -e 's/,$//') -n %s --all", KubectlCmd, KubectlCmd, name)
	if res := kub.ExecShort(cmd); !res.WasSuccessful() {
		return fmt.Errorf("unable to run '%s': %s", cmd, res.OutputPrettyPrint())
	}

	return nil
}

// NamespaceLabel sets a label in a Kubernetes namespace
func (kub *Kubectl) NamespaceLabel(namespace string, label string) *CmdRes {
	ginkgoext.By("Setting label %s in namespace %s", label, namespace)
	return kub.ExecShort(fmt.Sprintf("%s label --overwrite namespace %s %s", KubectlCmd, namespace, label))
}

// WaitforPods waits up until timeout seconds have elapsed for all pods in the
// specified namespace that match the provided JSONPath filter to have their
// containterStatuses equal to "ready". Returns true if all pods achieve
// the aforementioned desired state within timeout seconds. Returns false and
// an error if the command failed or the timeout was exceeded.
func (kub *Kubectl) WaitforPods(namespace string, filter string, timeout time.Duration) error {
	ginkgoext.By("WaitforPods(namespace=%q, filter=%q)", namespace, filter)
	err := kub.waitForNPods(checkReady, namespace, filter, 0, timeout)
	ginkgoext.By("WaitforPods(namespace=%q, filter=%q) => %v", namespace, filter, err)
	if err != nil {
		desc := kub.ExecShort(fmt.Sprintf("%s describe pods -n %s %s", KubectlCmd, namespace, filter))
		ginkgoext.By(desc.GetDebugMessage())
	}
	return err
}

// WaitForSinglePod waits up until timeout seconds have elapsed for all pods in the
// specified namespace that match the provided JSONPath filter to have their
// containterStatuses equal to "ready". Returns true if all pods achieve
// the aforementioned desired state within timeout seconds. Returns false and
// an error if the command failed or the timeout was exceeded.
func (kub *Kubectl) WaitForSinglePod(namespace, filter string, timeout time.Duration) error {
	ginkgoext.By("WaitforPods(namespace=%q, filter=%q)", namespace, filter)
	err := kub.waitForSinglePod(checkReady, namespace, filter, timeout)
	ginkgoext.By("WaitforPods(namespace=%q, filter=%q) => %v", namespace, filter, err)
	if err != nil {
		desc := kub.ExecShort(fmt.Sprintf("%s describe pods -n %s %s", KubectlCmd, namespace, filter))
		ginkgoext.By(desc.GetDebugMessage())
	}
	return err
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
	ginkgoext.By("WaitforNPodsRunning(namespace=%q, filter=%q)", namespace, filter)
	err := kub.waitForNPods(checkRunning, namespace, filter, minRequired, timeout)
	ginkgoext.By("WaitforNPods(namespace=%q, filter=%q) => %v", namespace, filter, err)
	if err != nil {
		desc := kub.ExecShort(fmt.Sprintf("%s describe pods -n %s %s", KubectlCmd, namespace, filter))
		ginkgoext.By(desc.GetDebugMessage())
	}
	return err
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
	ginkgoext.By("WaitforNPods(namespace=%q, filter=%q)", namespace, filter)
	err := kub.waitForNPods(checkReady, namespace, filter, minRequired, timeout)
	ginkgoext.By("WaitforNPods(namespace=%q, filter=%q) => %v", namespace, filter, err)
	if err != nil {
		desc := kub.ExecShort(fmt.Sprintf("%s describe pods -n %s %s", KubectlCmd, namespace, filter))
		ginkgoext.By(desc.GetDebugMessage())
	}
	return err
}

func (kub *Kubectl) waitForNPods(checkStatus checkPodStatusFunc, namespace string, filter string, minRequired int, timeout time.Duration) error {
	body := func() bool {
		podList := &v1.PodList{}
		err := kub.GetPods(namespace, filter).Unmarshal(podList)
		if err != nil {
			kub.Logger().Infof("Error while getting PodList: %s", err)
			return false
		}

		if len(podList.Items) == 0 {
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

func (kub *Kubectl) waitForSinglePod(checkStatus checkPodStatusFunc, namespace string, filter string, timeout time.Duration) error {
	body := func() bool {
		pod := v1.Pod{}
		err := kub.GetPods(namespace, filter).Unmarshal(&pod)
		if err != nil {
			kub.Logger().Infof("Error while getting Pod: %s", err)
			return false
		}

		// Count the pod as running when all conditions are true:
		//  - It is scheduled via Phase == v1.PodRunning
		//  - It is not scheduled for deletion when DeletionTimestamp is set
		//  - All containers in the pod have passed the liveness check via
		//  containerStatuses.Ready
		return checkReady(pod)
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

	ctx, cancel := context.WithTimeout(context.Background(), MidCommandTimeout*2)
	defer cancel()
	return kub.ExecContext(ctx, cmd)
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

// DeleteInNamespace deletes the Kubernetes manifest at path filepath in a
// particular namespace
func (kub *Kubectl) DeleteInNamespace(namespace, filePath string) *CmdRes {
	kub.Logger().Debugf("deleting %s in namespace %s", filePath, namespace)
	return kub.ExecShort(
		fmt.Sprintf("%s -n %s delete -f  %s", KubectlCmd, namespace, filePath))
}

// Delete deletes the Kubernetes manifest at path filepath.
func (kub *Kubectl) Delete(filePath string) *CmdRes {
	kub.Logger().Debugf("deleting %s", filePath)
	return kub.ExecShort(
		fmt.Sprintf("%s delete -f  %s", KubectlCmd, filePath))
}

// DeleteAndWait deletes the Kubernetes manifest at path filePath and wait
// for the associated resources to be gone.
// If ignoreNotFound parameter is true we don't error if the resource to be
// deleted is not found in the cluster.
func (kub *Kubectl) DeleteAndWait(filePath string, ignoreNotFound bool) *CmdRes {
	kub.Logger().Debugf("waiting for resources in %q to be deleted", filePath)
	var ignoreOpt string
	if ignoreNotFound {
		ignoreOpt = "--ignore-not-found"
	}
	return kub.ExecMiddle(
		fmt.Sprintf("%s delete -f  %s --wait %s", KubectlCmd, filePath, ignoreOpt))
}

// DeleteLong deletes the Kubernetes manifest at path filepath with longer timeout.
func (kub *Kubectl) DeleteLong(filePath string) *CmdRes {
	kub.Logger().Debugf("deleting %s", filePath)
	return kub.Exec(
		fmt.Sprintf("%s delete -f  %s", KubectlCmd, filePath))
}

// PodsHaveCiliumIdentity validates that all pods matching th podSelector have
// a CiliumEndpoint resource mirroring it and an identity is assigned to it. If
// any pods do not match this criteria, an error is returned.
func (kub *Kubectl) PodsHaveCiliumIdentity(namespace, podSelector string) error {
	res := kub.ExecShort(fmt.Sprintf("%s -n %s get pods -l %s -o json", KubectlCmd, namespace, podSelector))
	if !res.WasSuccessful() {
		return fmt.Errorf("unable to retrieve pods for selector %s:  %s", podSelector, res.OutputPrettyPrint())
	}

	podList := &v1.PodList{}
	err := res.Unmarshal(podList)
	if err != nil {
		return fmt.Errorf("unable to unmarshal pods for selector %s: %s", podSelector, err)
	}

	for _, pod := range podList.Items {
		ep, err := kub.GetCiliumEndpoint(namespace, pod.Name)
		if err != nil {
			return err
		}

		if ep == nil {
			return fmt.Errorf("pod %s/%s has no CiliumEndpoint", namespace, pod.Name)
		}

		if ep.Identity == nil || ep.Identity.ID == 0 {
			return fmt.Errorf("pod %s/%s has no CiliumIdentity", namespace, pod.Name)
		}
	}

	return nil
}

// DeploymentIsReady validate that a deployment has at least one replica and
// that all replicas are:
// - up-to-date
// - ready
//
// If the above condition is not met, an error is returned. If all replicas are
// ready, then the number of replicas is returned.
func (kub *Kubectl) DeploymentIsReady(namespace, deployment string) (int, error) {
	fullName := namespace + "/" + deployment

	res := kub.ExecShort(fmt.Sprintf("%s -n %s get deployment %s -o json", KubectlCmd, namespace, deployment))
	if !res.WasSuccessful() {
		return 0, fmt.Errorf("unable to retrieve deployment %s: %s", fullName, res.OutputPrettyPrint())
	}

	d := &appsv1.Deployment{}
	err := res.Unmarshal(d)
	if err != nil {
		return 0, fmt.Errorf("unable to unmarshal deployment %s: %s", fullName, err)
	}

	if d.Status.Replicas == 0 {
		return 0, fmt.Errorf("replicas count is zero")
	}

	if d.Status.AvailableReplicas != d.Status.Replicas {
		return 0, fmt.Errorf("only %d of %d replicas are available", d.Status.AvailableReplicas, d.Status.Replicas)
	}

	if d.Status.ReadyReplicas != d.Status.Replicas {
		return 0, fmt.Errorf("only %d of %d replicas are ready", d.Status.ReadyReplicas, d.Status.Replicas)
	}

	if d.Status.UpdatedReplicas != d.Status.Replicas {
		return 0, fmt.Errorf("only %d of %d replicas are up-to-date", d.Status.UpdatedReplicas, d.Status.Replicas)
	}

	return int(d.Status.Replicas), nil
}

func (kub *Kubectl) GetService(namespace, service string) (*v1.Service, error) {
	fullName := namespace + "/" + service
	res := kub.Get(namespace, "service "+service)
	if !res.WasSuccessful() {
		return nil, fmt.Errorf("unable to retrieve service %s: %s", fullName, res.OutputPrettyPrint())
	}

	var serviceObj v1.Service
	err := res.Unmarshal(&serviceObj)
	if err != nil {
		return nil, fmt.Errorf("unable to unmarshal service %s: %s", fullName, err)
	}

	return &serviceObj, nil
}

func absoluteServiceName(namespace, service string) string {
	fullServiceName := service + "." + namespace

	if !strings.HasSuffix(fullServiceName, ServiceSuffix) {
		fullServiceName = fullServiceName + "." + ServiceSuffix
	}

	return fullServiceName
}

func (kub *Kubectl) KubernetesDNSCanResolve(namespace, service string) error {
	serviceToResolve := absoluteServiceName(namespace, service)

	kubeDnsService, err := kub.GetService(KubeSystemNamespace, "kube-dns")
	if err != nil {
		return err
	}

	if len(kubeDnsService.Spec.Ports) == 0 {
		return fmt.Errorf("kube-dns service has no ports defined")
	}

	ctx, cancel := context.WithTimeout(context.Background(), MidCommandTimeout)
	defer cancel()

	cmd := fmt.Sprintf("dig +short %s @%s", serviceToResolve, kubeDnsService.Spec.ClusterIP)
	res := kub.ExecInFirstPod(ctx, LogGathererNamespace, logGathererSelector(false), cmd)
	if res.err != nil {
		return fmt.Errorf("unable to resolve service name %s with DNS server %s by running '%s' Cilium pod: %s",
			serviceToResolve, kubeDnsService.Spec.ClusterIP, cmd, res.OutputPrettyPrint())
	}
	foundIP, ipFromDNS := hasIPAddress(res.ByLines())
	if !foundIP {
		return fmt.Errorf("dig did not return an IP: %s", res.SingleOut())
	}

	destinationService, err := kub.GetService(namespace, service)
	if err != nil {
		return err
	}

	// If the destination service is headless, there is no ClusterIP, the
	// IP returned by the dig is the IP of one of the pods.
	if destinationService.Spec.ClusterIP == v1.ClusterIPNone {
		cmd := fmt.Sprintf("dig +tcp %s @%s", serviceToResolve, kubeDnsService.Spec.ClusterIP)
		res = kub.ExecInFirstPod(ctx, LogGathererNamespace, logGathererSelector(false), cmd)
		if !res.WasSuccessful() {
			return fmt.Errorf("unable to resolve service name %s by running '%s': %s",
				serviceToResolve, cmd, res.OutputPrettyPrint())
		}

		return nil
	}

	if !strings.Contains(ipFromDNS, destinationService.Spec.ClusterIP) {
		return fmt.Errorf("IP returned '%s' does not match the ClusterIP '%s' of the destination service",
			res.SingleOut(), destinationService.Spec.ClusterIP)
	}

	return nil
}

func (kub *Kubectl) validateServicePlumbingInCiliumPod(fullName, ciliumPod string, serviceObj *v1.Service, endpointsObj v1.Endpoints) error {
	jq := "jq -r '[ .[].status.realized | select(.\"frontend-address\".ip==\"" + serviceObj.Spec.ClusterIP + "\") | . ] '"
	cmd := "cilium service list -o json | " + jq
	res := kub.CiliumExecContext(context.Background(), ciliumPod, cmd)
	if !res.WasSuccessful() {
		return fmt.Errorf("unable to validate cilium service by running '%s': %s", cmd, res.OutputPrettyPrint())
	}

	if len(res.stdout.Bytes()) == 0 {
		return fmt.Errorf("ClusterIP %s not found in service list of cilium pod %s",
			serviceObj.Spec.ClusterIP, ciliumPod)
	}

	var realizedServices []models.ServiceSpec
	err := res.Unmarshal(&realizedServices)
	if err != nil {
		return fmt.Errorf("unable to unmarshal service spec '%s': %s", res.OutputPrettyPrint(), err)
	}

	cmd = "cilium bpf lb list -o json"
	res = kub.CiliumExecContext(context.Background(), ciliumPod, cmd)
	if !res.WasSuccessful() {
		return fmt.Errorf("unable to validate cilium service by running '%s': %s", cmd, res.OutputPrettyPrint())
	}

	var lbMap map[string][]string
	err = res.Unmarshal(&lbMap)
	if err != nil {
		return fmt.Errorf("unable to unmarshal cilium bpf lb list output: %s", err)
	}

	for _, port := range serviceObj.Spec.Ports {
		var foundPort *v1.ServicePort
		for _, realizedService := range realizedServices {
			if port.Port == int32(realizedService.FrontendAddress.Port) {
				foundPort = &port
				break
			}
		}
		if foundPort == nil {
			return fmt.Errorf("port %d of service %s (%s) not found in cilium pod %s",
				port.Port, fullName, serviceObj.Spec.ClusterIP, ciliumPod)
		}

		if _, ok := lbMap[net.JoinHostPort(serviceObj.Spec.ClusterIP, fmt.Sprintf("%d", port.Port))]; !ok {
			return fmt.Errorf("port %d of service %s (%s) not found in cilium bpf lb list of pod %s",
				port.Port, fullName, serviceObj.Spec.ClusterIP, ciliumPod)
		}
	}

	for _, subset := range endpointsObj.Subsets {
		for _, addr := range subset.Addresses {
			for _, port := range subset.Ports {
				foundBackend, foundBackendLB := false, false
				for _, realizedService := range realizedServices {
					frontEnd := realizedService.FrontendAddress
					lb := lbMap[net.JoinHostPort(frontEnd.IP, fmt.Sprintf("%d", frontEnd.Port))]

					for _, backAddr := range realizedService.BackendAddresses {
						if addr.IP == *backAddr.IP && uint16(port.Port) == backAddr.Port {
							foundBackend = true
							for _, backend := range lb {
								if strings.Contains(backend, net.JoinHostPort(*backAddr.IP, fmt.Sprintf("%d", port.Port))) {
									foundBackendLB = true
								}
							}
						}
					}
				}
				if !foundBackend {
					return fmt.Errorf("unable to find service backend %s in cilium pod %s",
						net.JoinHostPort(addr.IP, fmt.Sprintf("%d", port.Port)), ciliumPod)
				}

				if !foundBackendLB {
					return fmt.Errorf("unable to find service backend %s in datapath of cilium pod %s",
						net.JoinHostPort(addr.IP, fmt.Sprintf("%d", port.Port)), ciliumPod)
				}
			}
		}
	}

	return nil
}

// ValidateServicePlumbing ensures that a service in a namespace successfully
// plumbed by all Cilium pods in the cluster:
// - The service and endpoints are found in `cilium service list`
// - The service and endpoints are found in `cilium bpf lb list`
func (kub *Kubectl) ValidateServicePlumbing(namespace, service string) error {
	fullName := namespace + "/" + service

	serviceObj, err := kub.GetService(namespace, service)
	if err != nil {
		return err
	}

	if serviceObj == nil {
		return fmt.Errorf("%s service not found", fullName)
	}

	res := kub.Get(namespace, "endpoints "+service)
	if !res.WasSuccessful() {
		return fmt.Errorf("unable to retrieve endpoints %s: %s", fullName, res.OutputPrettyPrint())
	}

	if serviceObj.Spec.ClusterIP == v1.ClusterIPNone {
		return nil
	}

	var endpointsObj v1.Endpoints
	err = res.Unmarshal(&endpointsObj)
	if err != nil {
		return fmt.Errorf("unable to unmarshal endpoints %s: %s", fullName, err)
	}

	ciliumPods, err := kub.GetCiliumPods()
	if err != nil {
		return err
	}

	g, _ := errgroup.WithContext(context.TODO())
	for _, ciliumPod := range ciliumPods {
		ciliumPod := ciliumPod
		g.Go(func() error {
			var err error
			// The plumbing of Kubernetes services typically lags
			// behind a little bit if Cilium was just restarted.
			// Give this a thight timeout to avoid always failing.
			timeoutErr := RepeatUntilTrue(func() bool {
				err = kub.validateServicePlumbingInCiliumPod(fullName, ciliumPod, serviceObj, endpointsObj)
				if err != nil {
					ginkgoext.By("Checking service %s plumbing in cilium pod %s: %s", fullName, ciliumPod, err)
				}
				return err == nil
			}, &TimeoutConfig{Timeout: 5 * time.Second, Ticker: 1 * time.Second})
			if err != nil {
				return err
			} else if timeoutErr != nil {
				return timeoutErr
			}
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return err
	}

	return nil
}

// ValidateKubernetesDNS validates that the Kubernetes DNS server has been
// deployed correctly and can resolve DNS names. The following validations are
// done:
//  - The Kuberentes DNS deployment has at least one replica
//  - All replicas are up-to-date and ready
//  - All pods matching the deployment are represented by a CiliumEndpoint with an identity
//  - The kube-system/kube-dns service is correctly pumbed in all Cilium agents
//  - The service "default/kubernetes" can be resolved via the KubernetesDNS
//    and the IP returned matches the ClusterIP in the service
func (kub *Kubectl) ValidateKubernetesDNS() error {
	// The deployment is always validated first and not in parallel. There
	// is no point in validating correct plumbing if the DNS is not even up
	// and running.
	ginkgoext.By("Checking if deployment is ready")
	_, err := kub.DeploymentIsReady(KubeSystemNamespace, "kube-dns")
	if err != nil {
		_, err = kub.DeploymentIsReady(KubeSystemNamespace, "coredns")
		if err != nil {
			return err
		}
	}

	var (
		wg       sync.WaitGroup
		errQueue = make(chan error, 3)
	)
	wg.Add(3)

	go func() {
		ginkgoext.By("Checking if pods have identity")
		if err := kub.PodsHaveCiliumIdentity(KubeSystemNamespace, kubeDNSLabel); err != nil {
			errQueue <- err
		}
		wg.Done()
	}()

	go func() {
		ginkgoext.By("Checking if DNS can resolve")
		if err := kub.KubernetesDNSCanResolve("default", "kubernetes"); err != nil {
			errQueue <- err
		}
		wg.Done()
	}()

	go func() {
		ginkgoext.By("Checking if kube-dns service is plumbed correctly")
		if err := kub.ValidateServicePlumbing(KubeSystemNamespace, "kube-dns"); err != nil {
			errQueue <- err
		}
		wg.Done()
	}()

	wg.Wait()

	select {
	case err := <-errQueue:
		return err
	default:
	}

	return nil
}

// RestartUnmanagedPodsInNamespace restarts all pods in a namespace which are:
// * not host networking
// * not managed by Cilium already
func (kub *Kubectl) RestartUnmanagedPodsInNamespace(namespace string, excludePodPrefix ...string) {
	podList := &v1.PodList{}
	cmd := KubectlCmd + " -n " + namespace + " get pods -o json"
	res := kub.ExecShort(cmd)
	if !res.WasSuccessful() {
		ginkgoext.Failf("Unable to retrieve all pods to restart unmanaged pods with '%s': %s", cmd, res.OutputPrettyPrint())
	}
	if err := res.Unmarshal(podList); err != nil {
		ginkgoext.Failf("Unable to unmarshal podlist: %s", err)
	}

iteratePods:
	for _, pod := range podList.Items {
		if pod.Spec.HostNetwork || pod.DeletionTimestamp != nil {
			continue
		}

		for _, prefix := range excludePodPrefix {
			if strings.HasPrefix(pod.Name, prefix) {
				continue iteratePods
			}
		}

		ep, err := kub.GetCiliumEndpoint(namespace, pod.Name)
		if err != nil || ep.Identity == nil || ep.Identity.ID == 0 {
			ginkgoext.By("Restarting unmanaged pod %s/%s", namespace, pod.Name)
			cmd = KubectlCmd + " -n " + namespace + " delete pod " + pod.Name
			res = kub.Exec(cmd)
			if !res.WasSuccessful() {
				ginkgoext.Failf("Unable to restart unmanaged pod with '%s': %s", cmd, res.OutputPrettyPrint())
			}
		}
	}
}

// RedeployKubernetesDnsIfNecessary validates if the Kubernetes DNS is
// functional and re-deploys it if it is not and then waits for it to deploy
// successfully and become operational. See ValidateKubernetesDNS() for the
// list of conditions that must be met for Kubernetes DNS to be considered
// operational.
func (kub *Kubectl) RedeployKubernetesDnsIfNecessary() {
	ginkgoext.By("Validating if Kubernetes DNS is deployed")
	err := kub.ValidateKubernetesDNS()
	if err == nil {
		ginkgoext.By("Kubernetes DNS is up and operational")
		return
	} else {
		ginkgoext.By("Kubernetes DNS is not ready: %s", err)
	}

	ginkgoext.By("Restarting Kubernetes DNS (-l %s)", kubeDNSLabel)
	res := kub.DeleteResource("pod", "-n "+KubeSystemNamespace+" -l "+kubeDNSLabel)
	if !res.WasSuccessful() {
		ginkgoext.Failf("Unable to delete DNS pods: %s", res.OutputPrettyPrint())
	}

	ginkgoext.By("Waiting for Kubernetes DNS to become operational")
	err = RepeatUntilTrueDefaultTimeout(func() bool {
		err := kub.ValidateKubernetesDNS()
		if err != nil {
			ginkgoext.By("Kubernetes DNS is not ready yet: %s", err)
		}
		return err == nil
	})
	if err != nil {
		desc := kub.ExecShort(fmt.Sprintf("%s describe pods -n %s -l %s", KubectlCmd, KubeSystemNamespace, kubeDNSLabel))
		ginkgoext.By(desc.GetDebugMessage())

		ginkgoext.Fail("Kubernetes DNS did not become ready in time")
	}
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
	logger := kub.Logger().WithFields(logrus.Fields{"serviceName": serviceName, "serviceNamespace": serviceNamespace})

	serviceNameWithNamespace := fmt.Sprintf("%s.%s", serviceName, serviceNamespace)
	if !strings.HasSuffix(serviceNameWithNamespace, ServiceSuffix) {
		serviceNameWithNamespace = fmt.Sprintf("%s.%s", serviceNameWithNamespace, ServiceSuffix)
	}
	digCMD := "dig +short %s @%s"

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
			res := kub.ExecInFirstPod(ctx, LogGathererNamespace, logGathererSelector(false), fmt.Sprintf(digCMD, serviceNameWithNamespace, dnsClusterIP))
			if res.err != nil {
				logger.Debugf("failed to run dig in log-gatherer pod")
				kub.ExecInFirstPod(ctx, LogGathererNamespace, logGathererSelector(false), fmt.Sprintf(digCMDFallback, serviceNameWithNamespace, dnsClusterIP))
				return false
			}

			// check whether there is a IP line in dig output
			ipPresent, _ := hasIPAddress(res.ByLines())
			return ipPresent
		}
		log.Debugf("service is not headless; checking whether IP retrieved from DNS matches the IP for the service stored in Kubernetes")

		res := kub.ExecInFirstPod(ctx, LogGathererNamespace, logGathererSelector(false), fmt.Sprintf(digCMD, serviceNameWithNamespace, dnsClusterIP))
		if res.err != nil {
			logger.Debugf("failed to run dig in log-gatherer pod")
			return false
		}
		ipPresent, serviceIPFromDNS := hasIPAddress(res.ByLines())

		if !ipPresent {
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

// WaitTerminatingPods waits until all nodes that are in `Terminating`
// state are deleted correctly in the platform. In case of excedding the
// given timeout (in seconds) it returns an error.

func (kub *Kubectl) WaitTerminatingPods(timeout time.Duration) error {
	return kub.WaitTerminatingPodsInNsWithFilter("", "", timeout)
}

// WaitTerminatingPodsInNs waits until all nodes that are in `Terminating`
// state are deleted correctly in the platform. In case of excedding the
// given timeout (in seconds) it returns an error.
func (kub *Kubectl) WaitTerminatingPodsInNs(ns string, timeout time.Duration) error {
	return kub.WaitTerminatingPodsInNsWithFilter(ns, "", timeout)
}

// WaitTerminatingPodsInNs waits until all nodes that are in `Terminating`
// state are deleted correctly in the platform. In case of excedding the
// given timeout (in seconds) it returns an error.
func (kub *Kubectl) WaitTerminatingPodsInNsWithFilter(ns, filter string, timeout time.Duration) error {
	body := func() bool {
		where := ns
		if where == "" {
			where = "--all-namespaces"
		} else {
			where = "-n " + where
		}
		res := kub.ExecShort(fmt.Sprintf(
			"%s get pods %s %s -o jsonpath='{.items[*].metadata.deletionTimestamp}'",
			KubectlCmd, filter, where))
		if !res.WasSuccessful() {
			return false
		}

		if res.Stdout() == "" {
			// Output is empty so no terminating containers
			return true
		}

		podsTerminating := len(strings.Split(res.Stdout(), " "))
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
		_ = kub.ExecShort(fmt.Sprintf(
			`%s patch --filename='%s' --patch %s --local --dry-run -o yaml`,
			KubectlCmd, original, patch))
	}

	// validation 1st
	res := kub.ExecShort(fmt.Sprintf(
		`%s patch --filename='%s' --patch %s --local --dry-run`,
		KubectlCmd, original, patch))
	if !res.WasSuccessful() {
		debugYaml(original, patch)
		return res.GetErr("Cilium patch validation failed")
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
		_ = kub.ExecShort(fmt.Sprintf(
			`%s patch --filename='%s' --patch "$(cat '%s')" --local -o yaml`,
			KubectlCmd, original, patch))
	}

	// validation 1st
	res := kub.ExecShort(fmt.Sprintf(
		`%s patch --filename='%s' --patch "$(cat '%s')" --local --dry-run`,
		KubectlCmd, original, patchFileName))
	if !res.WasSuccessful() {
		debugYaml(original, patchFileName)
		return res.GetErr("Cilium patch validation failed")
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

// Patch patches the given object with the given patch (string).
func (kub *Kubectl) Patch(namespace, objType, objName, patch string) *CmdRes {
	ginkgoext.By("Patching %s %s in namespace %s", objType, objName, namespace)
	return kub.ExecShort(fmt.Sprintf("%s -n %s patch %s %s --patch %q",
		KubectlCmd, namespace, objType, objName, patch))
}

func addIfNotOverwritten(options map[string]string, field, value string) map[string]string {
	if _, ok := options[field]; !ok {
		options[field] = value
	}
	return options
}

func (kub *Kubectl) overwriteHelmOptions(options map[string]string) error {
	if integration := GetCurrentIntegration(); integration != "" {
		overrides := helmOverrides[integration]
		for key, value := range overrides {
			options = addIfNotOverwritten(options, key, value)
		}

	}
	for key, value := range defaultHelmOptions {
		options = addIfNotOverwritten(options, key, value)
	}

	// Do not schedule cilium-agent on the NO_CILIUM_ON_NODE node
	if node := GetNodeWithoutCilium(); node != "" {
		opts := map[string]string{
			"affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[0].matchExpressions[0].key":       "cilium.io/ci-node",
			"affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[0].matchExpressions[0].operator":  "NotIn",
			"affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[0].matchExpressions[0].values[0]": node,
		}
		for key, value := range opts {
			options = addIfNotOverwritten(options, key, value)
		}
	}

	if !RunsWithKubeProxy() {
		opts := map[string]string{
			"kubeProxyReplacement": "strict",
		}

		if DoesNotRunOnGKE() {
			nodeIP, err := kub.GetNodeIPByLabel(K8s1, false)
			if err != nil {
				return fmt.Errorf("Cannot retrieve Node IP for k8s1: %s", err)
			}
			opts["k8sServiceHost"] = nodeIP
			opts["k8sServicePort"] = "6443"
		}

		if RunsOnNetNextOr419Kernel() {
			opts["bpf.masquerade"] = "true"
		}

		for key, value := range opts {
			options = addIfNotOverwritten(options, key, value)
		}
	}

	if RunsWithHostFirewall() {
		addIfNotOverwritten(options, "hostFirewall", "true")
	}

	if !RunsWithKubeProxy() || options["hostFirewall"] == "true" {
		// Set devices
		privateIface, err := kub.GetPrivateIface()
		if err != nil {
			return err
		}
		defaultIface, err := kub.GetDefaultIface()
		if err != nil {
			return err
		}
		devices := fmt.Sprintf(`'{%s,%s}'`, privateIface, defaultIface)
		addIfNotOverwritten(options, "devices", devices)
	}

	if len(config.CiliumTestConfig.RegistryCredentials) > 0 {
		options["imagePullSecrets[0].name"] = config.RegistrySecretName
	}

	return nil
}

func (kub *Kubectl) generateCiliumYaml(options map[string]string, filename string) error {
	err := kub.overwriteHelmOptions(options)
	if err != nil {
		return err
	}
	// TODO GH-8753: Use helm rendering library instead of shelling out to
	// helm template
	helmTemplate := kub.GetFilePath(HelmTemplate)
	res := kub.HelmTemplate(helmTemplate, CiliumNamespace, filename, options)
	if !res.WasSuccessful() {
		// If the helm template generation is not successful remove the empty
		// manifest file.
		_ = os.Remove(filename)
		return res.GetErr("Unable to generate YAML")
	}

	return nil
}

// GetPrivateIface returns an interface name of a netdev which has InternalIP
// addr.
// Assumes that all nodes have identical interfaces.
func (kub *Kubectl) GetPrivateIface() (string, error) {
	ipAddr, err := kub.GetNodeIPByLabel(K8s1, false)
	if err != nil {
		return "", err
	} else if ipAddr == "" {
		return "", fmt.Errorf("%s does not have InternalIP", K8s1)
	}

	return kub.getIfaceByIPAddr(K8s1, ipAddr)
}

// GetPublicIface returns an interface name of a netdev which has ExternalIP
// addr.
// Assumes that all nodes have identical interfaces.
func (kub *Kubectl) GetPublicIface() (string, error) {
	ipAddr, err := kub.GetNodeIPByLabel(K8s1, true)
	if err != nil {
		return "", err
	} else if ipAddr == "" {
		return "", fmt.Errorf("%s does not have ExternalIP", K8s1)
	}

	return kub.getIfaceByIPAddr(K8s1, ipAddr)
}

func (kub *Kubectl) waitToDelete(name, label string) error {
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
			return fmt.Errorf("timed out waiting to delete %s: pods still remaining: %s", name, pods)
		default:
		}

		pods, err = kub.GetPodNamesContext(ctx, CiliumNamespace, label)
		if err != nil {
			return err
		}
		status = len(pods)
		kub.Logger().Infof("%s pods terminating '%d' err='%v' pods='%v'", name, status, err, pods)
		if status == 0 {
			return nil
		}
		time.Sleep(1 * time.Second)
	}
	return nil
}

// GetDefaultIface returns an interface name which is used by a default route.
// Assumes that all nodes have identical interfaces.
func (kub *Kubectl) GetDefaultIface() (string, error) {
	cmd := `ip -o r | grep default | grep -o 'dev [a-zA-Z0-9]*' | cut -d' ' -f2 | head -n1`
	iface, err := kub.ExecInHostNetNSByLabel(context.TODO(), K8s1, cmd)
	if err != nil {
		return "", fmt.Errorf("Failed to retrieve default iface: %s", err)
	}

	return strings.Trim(iface, "\n"), nil
}

func (kub *Kubectl) DeleteCiliumDS() error {
	// Do not assert on success in AfterEach intentionally to avoid
	// incomplete teardown.
	ginkgoext.By("DeleteCiliumDS(namespace=%q)", CiliumNamespace)
	_ = kub.DeleteResource("ds", fmt.Sprintf("-n %s cilium", CiliumNamespace))
	return kub.waitToDelete("Cilium", CiliumAgentLabel)
}

func (kub *Kubectl) DeleteHubbleRelay(ns string) error {
	ginkgoext.By("DeleteHubbleRelay(namespace=%q)", ns)
	_ = kub.DeleteResource("deployment", fmt.Sprintf("-n %s hubble-relay", ns))
	_ = kub.DeleteResource("service", fmt.Sprintf("-n %s hubble-relay", ns))
	return kub.waitToDelete("HubbleRelay", HubbleRelayLabel)
}

// CiliumInstall installs Cilium with the provided Helm options.
func (kub *Kubectl) CiliumInstall(filename string, options map[string]string) error {
	// If the file does not exist, create it so that the command `kubectl delete -f <filename>`
	// does not fail because there is no file.
	_ = kub.ExecContextShort(context.TODO(), fmt.Sprintf("[[ ! -f %s ]] && echo '---' >> %s", filename, filename))

	// First try to remove any existing cilium install. This is done by removing resources
	// from the file we generate cilium install manifest to.
	res := kub.DeleteAndWait(filename, true)
	if !res.WasSuccessful() {
		return res.GetErr("Unable to delete existing cilium YAML")
	}

	if err := kub.generateCiliumYaml(options, filename); err != nil {
		return err
	}

	res = kub.Apply(ApplyOptions{FilePath: filename, Force: true, Namespace: CiliumNamespace})
	if !res.WasSuccessful() {
		return res.GetErr("Unable to apply YAML")
	}

	return nil
}

// convertOptionsToLegacyOptions maps current helm values to old helm Values
// TODO: When Cilium 1.10 branch is created, remove this function
func (kub *Kubectl) convertOptionsToLegacyOptions(options map[string]string) map[string]string {

	result := make(map[string]string)

	legacyMappings := map[string]string{
		"affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[0].matchExpressions[0].key":       "global.affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[0].matchExpressions[0].key",
		"affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[0].matchExpressions[0].operator":  "global.affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[0].matchExpressions[0].operator",
		"affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[0].matchExpressions[0].values[0]": "global.affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[0].matchExpressions[0].values[0]",
		"bpf.preallocateMaps":           "global.bpf.preallocateMaps",
		"bpf.masquerade":                "config.bpfMasquerade",
		"cleanState":                    "global.cleanState",
		"cni.binPath":                   "global.cni.binPath",
		"cni.chainingMode":              "global.cni.chainingMode",
		"cni.confPath":                  "global.cni.confPath",
		"cni.customConf":                "global.cni.customConf",
		"daemon.runPath":                "global.daemon.runPath",
		"debug.enabled":                 "global.debug.enabled",
		"devices":                       "global.devices", // Override "eth0 eth0\neth0"
		"enableCnpStatusUpdates":        "config.enableCnpStatusUpdates",
		"etcd.leaseTTL":                 "global.etcd.leaseTTL",
		"externalIPs.enabled":           "global.externalIPs.enabled",
		"flannel.enabled":               "global.flannel.enabled",
		"gke.enabled":                   "global.gke.enabled",
		"hostFirewall":                  "global.hostFirewall",
		"hostPort.enabled":              "global.hostPort.enabled",
		"hostServices.enabled":          "global.hostServices.enabled",
		"hubble.enabled":                "global.hubble.enabled",
		"hubble.listenAddress":          "global.hubble.listenAddress",
		"hubble.relay.image.repository": "hubble-relay.image.repository",
		"hubble.relay.image.tag":        "hubble-relay.image.tag",
		"image.tag":                     "global.tag",
		"ipam.mode":                     "config.ipam",
		"ipv4.enabled":                  "global.ipv4.enabled",
		"ipv6.enabled":                  "global.ipv6.enabled",
		"k8s.requireIPv4PodCIDR":        "global.k8s.requireIPv4PodCIDR",
		"k8sServiceHost":                "global.k8sServiceHost",
		"k8sServicePort":                "global.k8sServicePort",
		"kubeProxyReplacement":          "global.kubeProxyReplacement",
		"loadBalancer.mode":             "global.nodePort.mode",
		"logSystemLoad":                 "global.logSystemLoad",
		"masquerade":                    "global.masquerade",
		"nativeRoutingCIDR":             "global.nativeRoutingCIDR",
		"nodeinit.enabled":              "global.nodeinit.enabled",
		"nodeinit.reconfigureKubelet":   "global.nodeinit.reconfigureKubelet",
		"nodeinit.removeCbrBridge":      "global.nodeinit.removeCbrBridge",
		"nodeinit.restartPods":          "globalnodeinit.restartPods",
		"nodePort.enabled":              "global.nodePort.enabled",
		"operator.enabled":              "operator.enabled",
		"pprof.enabled":                 "global.pprof.enabled",
		"sessionAffinity":               "config.sessionAffinity",
		"sleepAfterInit":                "agent.sleepAfterInit",
		"tunnel":                        "global.tunnel",
	}

	for newKey, v := range options {
		if oldKey, ok := legacyMappings[newKey]; ok {
			result[oldKey] = v
		} else if !ok {
			if newKey == "image.repository" {
				result["agent.image"] = v + ":" + options["image.tag"]
			} else if newKey == "operator.image.repository" {
				if options["eni"] == "true" {
					result["operator.image"] = v + "-aws:" + options["image.tag"]
				} else if options["azure.enabled"] == "true" {
					result["operator.image"] = v + "-azure:" + options["image.tag"]
				} else {
					result["operator.image"] = v + "-generic:" + options["image.tag"]
				}
			} else if newKey == "preflight.image.repository" {
				result["preflight.image"] = v + ":" + options["image.tag"]
			} else if strings.HasSuffix(newKey, ".tag") {
				// Already handled in the if statement above
				continue
			} else {
				log.Warningf("Skipping option %s", newKey)
			}
		}
	}
	result["ci.kubeCacheMutationDetector"] = "true"
	return result
}

// RunHelm runs the helm command with the given options.
func (kub *Kubectl) RunHelm(action, repo, helmName, version, namespace string, options map[string]string) (*CmdRes, error) {
	err := kub.overwriteHelmOptions(options)
	if err != nil {
		return nil, err
	}
	optionsString := ""

	//TODO: In 1.10 dev cycle, remove this
	if version == "1.8-dev" {
		options = kub.convertOptionsToLegacyOptions(options)
	}

	for k, v := range options {
		optionsString += fmt.Sprintf(" --set %s=%s ", k, v)
	}

	return kub.ExecMiddle(fmt.Sprintf("helm %s %s %s "+
		"--version=%s "+
		"--namespace=%s "+
		"%s", action, helmName, repo, version, namespace, optionsString)), nil
}

// GetCiliumPods returns a list of all Cilium pods in the specified namespace,
// and an error if the Cilium pods were not able to be retrieved.
func (kub *Kubectl) GetCiliumPods() ([]string, error) {
	return kub.GetPodNames(CiliumNamespace, "k8s-app=cilium")
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

// CiliumEndpointIPv6 returns the IPv6 address of each endpoint which matches
// the given endpoint selector.
func (kub *Kubectl) CiliumEndpointIPv6(pod string, endpoint string) map[string]string {
	filter := `{range [*]}{@.status.external-identifiers.pod-name}{"="}{@.status.networking.addressing[*].ipv6}{"\n"}{end}`
	ctx, cancel := context.WithTimeout(context.Background(), ShortCommandTimeout)
	defer cancel()
	return kub.CiliumExecContext(ctx, pod, fmt.Sprintf(
		"cilium endpoint get %s -o jsonpath='%s'", endpoint, filter)).KVOutput()
}

// CiliumEndpointWaitReady waits until all endpoints managed by all Cilium pod
// are ready. Returns an error if the Cilium pods cannot be retrieved via
// Kubernetes, or endpoints are not ready after a specified timeout
func (kub *Kubectl) CiliumEndpointWaitReady() error {
	ciliumPods, err := kub.GetCiliumPods()
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
		ep, err := kub.GetCiliumEndpoint(ns, podName)
		if err != nil || ep == nil {
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
		command := fmt.Sprintf("%s exec -n %s %s -- %s", KubectlCmd, CiliumNamespace, pod, cmd)
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

// CiliumExecMustSucceed runs cmd in the specified Cilium pod.
// it causes a test failure if the command was not successful.
func (kub *Kubectl) CiliumExecMustSucceed(ctx context.Context, pod, cmd string, optionalDescription ...interface{}) *CmdRes {
	res := kub.CiliumExecContext(ctx, pod, cmd)
	if !res.WasSuccessful() {
		res.SendToLog(false)
	}
	gomega.ExpectWithOffset(1, res).Should(
		CMDSuccess(), optionalDescription...)
	return res
}

// CiliumExecUntilMatch executes the specified command repeatedly for the
// specified Cilium pod until the given substring is present in stdout.
// If the timeout is reached it will return an error.
func (kub *Kubectl) CiliumExecUntilMatch(pod, cmd, substr string) error {
	body := func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), ShortCommandTimeout)
		defer cancel()
		res := kub.CiliumExecContext(ctx, pod, cmd)
		return strings.Contains(res.Stdout(), substr)
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

// LoadedPolicyInFirstAgent returns the policy as loaded in the first cilium
// agent that is found in the cluster
func (kub *Kubectl) LoadedPolicyInFirstAgent() (string, error) {
	pods, err := kub.GetCiliumPods()
	if err != nil {
		return "", fmt.Errorf("cannot retrieve cilium pods: %s", err)
	}
	for _, pod := range pods {
		ctx, cancel := context.WithTimeout(context.Background(), ShortCommandTimeout)
		defer cancel()
		res := kub.CiliumExecContext(ctx, pod, "cilium policy get")
		if !res.WasSuccessful() {
			return "", fmt.Errorf("cannot execute cilium policy get: %s", res.Stdout())
		} else {
			return res.CombineOutput().String(), nil
		}
	}
	return "", fmt.Errorf("no running cilium pods")
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
		return -1, fmt.Errorf("cannot get the revision %s", res.Stdout())
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

func (kub *Kubectl) getPodRevisions() (map[string]int, error) {
	pods, err := kub.GetCiliumPods()
	if err != nil {
		kub.Logger().WithError(err).Error("cannot retrieve cilium pods")
		return nil, fmt.Errorf("Cannot get cilium pods: %s", err)
	}

	revisions := make(map[string]int)
	for _, pod := range pods {
		revision, err := kub.CiliumPolicyRevision(pod)
		if err != nil {
			kub.Logger().WithError(err).Error("cannot retrieve cilium pod policy revision")
			return nil, fmt.Errorf("Cannot retrieve cilium pod %s policy revision: %s", pod, err)
		}
		revisions[pod] = revision
	}
	return revisions, nil
}

func (kub *Kubectl) waitNextPolicyRevisions(podRevisions map[string]int, mustHavePolicy bool, timeout time.Duration) error {
	npFilter := fmt.Sprintf(
		`{range .items[*]}{"%s="}{.metadata.name}{" %s="}{.metadata.namespace}{"\n"}{end}`,
		KubectlPolicyNameLabel, KubectlPolicyNameSpaceLabel)

	knpBody := func() bool {
		knp := kub.ExecShort(fmt.Sprintf("%s get --all-namespaces netpol -o jsonpath='%s'",
			KubectlCmd, npFilter))
		result := knp.ByLines()
		if len(result) == 0 {
			return true
		}

		for _, item := range result {
			for ciliumPod, revision := range podRevisions {
				if mustHavePolicy {
					if !kub.CiliumIsPolicyLoaded(ciliumPod, item) {
						kub.Logger().Infof("Policy '%s' is not ready on Cilium pod '%s'", item, ciliumPod)
						return false
					}
				}

				ctx, cancel := context.WithTimeout(context.Background(), ShortCommandTimeout)
				defer cancel()
				desiredRevision := revision + 1
				res := kub.CiliumExecContext(ctx, ciliumPod, fmt.Sprintf("cilium policy wait %d --max-wait-time %d", desiredRevision, int(ShortCommandTimeout.Seconds())))
				if res.GetExitCode() != 0 {
					kub.Logger().Infof("Failed to wait for policy revision %d on pod %s", desiredRevision, ciliumPod)
					return false
				}
			}
		}
		return true
	}

	err := WithTimeout(
		knpBody,
		"Timed out while waiting for CNP to be applied on all PODs",
		&TimeoutConfig{Timeout: timeout})
	return err
}

func getPolicyEnforcingJqFilter(numNodes int) string {
	// Test filter: https://jqplay.org/s/EgNzc06Cgn
	return fmt.Sprintf(
		`[.items[]|{name:.metadata.name, enforcing: (.status|if has("nodes") then .nodes |to_entries|map_values(.value.enforcing) + [(.|length >= %d)]|all else true end)|tostring, status: has("status")|tostring}]`,
		numNodes)
}

// CiliumPolicyAction performs the specified action in Kubernetes for the policy
// stored in path filepath and waits up  until timeout seconds for the policy
// to be applied in all Cilium endpoints. Returns an error if the policy is not
// imported before the timeout is
// exceeded.
func (kub *Kubectl) CiliumPolicyAction(namespace, filepath string, action ResourceLifeCycleAction, timeout time.Duration) (string, error) {
	podRevisions, err := kub.getPodRevisions()
	if err != nil {
		return "", err
	}
	numNodes := len(podRevisions)

	kub.Logger().Infof("Performing %s action on resource '%s'", action, filepath)

	status := kub.Action(action, filepath, namespace)
	if !status.WasSuccessful() {
		return "", status.GetErr(fmt.Sprintf("Cannot perform '%s' on resource '%s'", action, filepath))
	}
	unchanged := action == KubectlApply && strings.HasSuffix(status.Stdout(), " unchanged\n")

	// If policy is uninstalled we can't require a policy being enforced.
	if action != KubectlDelete {
		jqFilter := getPolicyEnforcingJqFilter(numNodes)
		body := func() bool {
			cmds := map[string]string{
				"CNP":  fmt.Sprintf("%s get cnp --all-namespaces -o json | jq '%s'", KubectlCmd, jqFilter),
				"CCNP": fmt.Sprintf("%s get ccnp -o json | jq '%s'", KubectlCmd, jqFilter),
			}

			for ctx, cmd := range cmds {
				var data []map[string]string

				res := kub.ExecShort(cmd)
				if !res.WasSuccessful() {
					kub.Logger().WithError(res.GetErr("")).Errorf("cannot get %s status", ctx)
					return false
				}

				err := res.Unmarshal(&data)
				if err != nil {
					kub.Logger().WithError(err).Errorf("Cannot unmarshal json for %s status", ctx)
					return false
				}

				for _, item := range data {
					if item["enforcing"] != "true" || item["status"] != "true" {
						kub.Logger().Errorf("%s policy '%s' is not enforcing yet", ctx, item["name"])
						return false
					}
				}
			}

			return true
		}

		err = WithTimeout(
			body,
			"Timed out while waiting for policies to be enforced",
			&TimeoutConfig{Timeout: timeout})

		if err != nil {
			return "", err
		}
	}

	// If the applied policy was unchanged, we don't need to wait for the next policy revision.
	if unchanged {
		return "", nil
	}

	return "", kub.waitNextPolicyRevisions(podRevisions, action != KubectlDelete, timeout)
}

// CiliumClusterwidePolicyAction applies a clusterwide policy action as described in action argument. It
// then wait till timeout Duration for the policy to be applied to all the cilium endpoints.
func (kub *Kubectl) CiliumClusterwidePolicyAction(filepath string, action ResourceLifeCycleAction, timeout time.Duration) (string, error) {
	podRevisions, err := kub.getPodRevisions()
	if err != nil {
		return "", err
	}
	numNodes := len(podRevisions)

	kub.Logger().Infof("Performing %s action on resource '%s'", action, filepath)

	status := kub.Action(action, filepath)
	if !status.WasSuccessful() {
		return "", status.GetErr(fmt.Sprintf("Cannot perform '%s' on resource '%s'", action, filepath))
	}
	unchanged := action == KubectlApply && strings.HasSuffix(status.Stdout(), " unchanged\n")

	// If policy is uninstalled we can't require a policy being enforced.
	if action != KubectlDelete {
		jqFilter := getPolicyEnforcingJqFilter(numNodes)
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
			"Timed out while waiting CCNP to be enforced",
			&TimeoutConfig{Timeout: timeout})

		if err != nil {
			return "", err
		}
	}

	// If the applied policy was unchanged, we don't need to wait for the next policy revision.
	if unchanged {
		return "", nil
	}

	return "", kub.waitNextPolicyRevisions(podRevisions, action != KubectlDelete, timeout)
}

// CiliumReport report the cilium pod to the log and appends the logs for the
// given commands.
func (kub *Kubectl) CiliumReport(commands ...string) {
	if config.CiliumTestConfig.SkipLogGathering {
		ginkgoext.GinkgoPrint("Skipped gathering logs (-cilium.skipLogs=true)\n")
		return
	}

	if kub == nil {
		ginkgoext.GinkgoPrint("Skipped gathering logs due to kubectl not being initialized")
		return
	}

	// Log gathering for Cilium should take at most 10 minutes. This ensures that
	// the CiliumReport stage doesn't cause the entire CI to hang.

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		kub.GatherLogs(ctx)
	}()

	go func() {
		defer wg.Done()
		kub.DumpCiliumCommandOutput(ctx, CiliumNamespace)
	}()

	kub.CiliumCheckReport(ctx)

	pods, err := kub.GetCiliumPodsContext(ctx, CiliumNamespace)
	if err != nil {
		kub.Logger().WithError(err).Error("cannot retrieve cilium pods on ReportDump")
	}
	res := kub.ExecContextShort(ctx, fmt.Sprintf("%s get pods -o wide --all-namespaces", KubectlCmd))
	ginkgoext.GinkgoPrint(res.GetDebugMessage())

	results := make([]*CmdRes, 0, len(pods)*len(commands))
	ginkgoext.GinkgoPrint("Fetching command output from pods %s", pods)
	for _, pod := range pods {
		for _, cmd := range commands {
			res = kub.ExecPodCmdBackground(ctx, CiliumNamespace, pod, cmd, ExecOptions{SkipLog: true})
			results = append(results, res)
		}
	}

	wg.Wait()

	for _, res := range results {
		res.WaitUntilFinish()
		ginkgoext.GinkgoPrint(res.GetDebugMessage())
	}
}

// CiliumCheckReport prints a few checks on the Junit output to provide more
// context to users. The list of checks that prints are the following:
// - Number of Kubernetes and Cilium policies installed.
// - Policy enforcement status by endpoint.
// - Controller, health, kvstore status.
func (kub *Kubectl) CiliumCheckReport(ctx context.Context) {
	pods, _ := kub.GetCiliumPods()
	fmt.Fprintf(CheckLogs, "Cilium pods: %v\n", pods)

	var policiesFilter = `{range .items[*]}{.metadata.namespace}{"::"}{.metadata.name}{" "}{end}`
	netpols := kub.ExecContextShort(ctx, fmt.Sprintf(
		"%s get netpol -o jsonpath='%s' --all-namespaces",
		KubectlCmd, policiesFilter))
	fmt.Fprintf(CheckLogs, "Netpols loaded: %v\n", netpols.GetStdOut())

	cnp := kub.ExecContextShort(ctx, fmt.Sprintf(
		"%s get cnp -o jsonpath='%s' --all-namespaces",
		KubectlCmd, policiesFilter))
	fmt.Fprintf(CheckLogs, "CiliumNetworkPolicies loaded: %v\n", cnp.GetStdOut())

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

// ValidateNoErrorsInLogs checks that cilium logs since the given duration (By
// default `CurrentGinkgoTestDescription().Duration`) do not contain any of the
// known-bad messages (e.g., `deadlocks` or `segmentation faults`). In case of
// any of these messages, it'll mark the test as failed.
func (kub *Kubectl) ValidateNoErrorsInLogs(duration time.Duration) {
	blacklist := GetBadLogMessages()
	kub.ValidateListOfErrorsInLogs(duration, blacklist)
}

// ValidateListOfErrorsInLogs is similar to ValidateNoErrorsInLogs, but
// takes a blacklist of bad log messages instead of using the default list.
func (kub *Kubectl) ValidateListOfErrorsInLogs(duration time.Duration, blacklist map[string][]string) {
	if kub == nil {
		// if `kub` is nil, this is run after the test failed while setting up `kub` and we are unable to gather logs
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	apps := map[string]string{
		"k8s-app=cilium":         CiliumTestLog,
		"k8s-app=hubble-relay":   HubbleRelayTestLog,
		"io.cilium/app=operator": CiliumOperatorTestLog,
	}

	wg := sync.WaitGroup{}
	wg.Add(len(apps))
	for app, file := range apps {
		go func(app, file string) {
			var logs string
			cmd := fmt.Sprintf("%s -n %s logs --tail=-1 --timestamps=true -l %s --since=%vs",
				KubectlCmd, CiliumNamespace, app, duration.Seconds())
			res := kub.ExecContext(ctx, fmt.Sprintf("%s --previous", cmd), ExecOptions{SkipLog: true})
			if res.WasSuccessful() {
				logs += res.Stdout()
			}
			res = kub.ExecContext(ctx, cmd, ExecOptions{SkipLog: true})
			if res.WasSuccessful() {
				logs += res.Stdout()
			}
			defer func() {
				defer wg.Done()
				// Keep the cilium logs for the given test in a separate file.
				testPath, err := CreateReportDirectory()
				if err != nil {
					kub.Logger().WithError(err).Error("Cannot create report directory")
					return
				}
				err = ioutil.WriteFile(
					fmt.Sprintf("%s/%s", testPath, file),
					[]byte(logs), LogPerm)

				if err != nil {
					kub.Logger().WithError(err).Errorf("Cannot create %s", CiliumTestLog)
				}
			}()

			failIfContainsBadLogMsg(logs, app, blacklist)

			fmt.Fprint(CheckLogs, logutils.LogErrorsSummary(logs))
		}(app, file)
	}

	wg.Wait()
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
			KubectlCmd, CiliumNamespace,
			ciliumPod, src, dst)
		res := kub.ExecContext(ctx, cmd, ExecOptions{SkipLog: true})
		if !res.WasSuccessful() {
			log.WithField("output", res.CombineOutput()).Error("Cannot get core from pod")
		}
	}
}

// ExecInFirstPod runs given command in one pod that matches given selector and namespace
// An error is returned if no pods can be found
func (kub *Kubectl) ExecInFirstPod(ctx context.Context, namespace, selector, cmd string, options ...ExecOptions) *CmdRes {
	names, err := kub.GetPodNamesContext(ctx, namespace, selector)
	if err != nil {
		return &CmdRes{err: err}
	}
	if len(names) == 0 {
		return &CmdRes{err: fmt.Errorf("Cannot find pods matching %s to execute %s", selector, cmd)}
	}

	name := names[0]
	command := fmt.Sprintf("%s exec -n %s %s -- %s", KubectlCmd, namespace, name, cmd)
	return kub.ExecContext(ctx, command)
}

// ExecInPods runs given command on all pods in given namespace that match selector and returns map pod-name->CmdRes
func (kub *Kubectl) ExecInPods(ctx context.Context, namespace, selector, cmd string, options ...ExecOptions) (results map[string]*CmdRes, err error) {
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
func (kub *Kubectl) ExecInHostNetNS(ctx context.Context, node, cmd string) *CmdRes {
	// This is a hack, as we execute the given cmd in the log-gathering pod
	// which runs in the host netns. Also, the log-gathering pods lack some
	// packages, e.g. iproute2.
	selector := fmt.Sprintf("%s --field-selector spec.nodeName=%s",
		logGathererSelector(true), node)

	return kub.ExecInFirstPod(ctx, LogGathererNamespace, selector, cmd)
}

// ExecInHostNetNSByLabel runs given command in a pod running in a host network namespace.
// The pod's node is identified by the given label.
func (kub *Kubectl) ExecInHostNetNSByLabel(ctx context.Context, label, cmd string) (string, error) {
	nodeName, err := kub.GetNodeNameByLabel(label)
	if err != nil {
		return "", fmt.Errorf("Cannot get node by label %s", label)
	}

	res := kub.ExecInHostNetNS(ctx, nodeName, cmd)
	if !res.WasSuccessful() {
		return "", fmt.Errorf("Failed to exec %q cmd on %q node: %s", cmd, nodeName, res.GetErr(""))
	}

	return res.Stdout(), nil
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
			res = kub.ExecContext(ctx, fmt.Sprintf("mkdir -p %q", archiveName))
			if !res.WasSuccessful() {
				logger.WithField("cmd", res.GetCmd()).Errorf(
					"cannot create bugtool archive folder: %s", res.CombineOutput())
				continue
			}

			cmd := fmt.Sprintf("tar -xf /tmp/%s -C %q --strip-components=1", line, archiveName)
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
		"kubectl get pods --all-namespaces -o json":                          "pods.txt",
		"kubectl get services --all-namespaces -o json":                      "svc.txt",
		"kubectl get nodes -o json":                                          "nodes.txt",
		"kubectl get ds --all-namespaces -o json":                            "ds.txt",
		"kubectl get cnp --all-namespaces -o json":                           "cnp.txt",
		"kubectl get cep --all-namespaces -o json":                           "cep.txt",
		"kubectl get netpol --all-namespaces -o json":                        "netpol.txt",
		"kubectl describe pods --all-namespaces":                             "pods_status.txt",
		"kubectl get replicationcontroller --all-namespaces -o json":         "replicationcontroller.txt",
		"kubectl get deployment --all-namespaces -o json":                    "deployment.txt",
		"kubectl get crd ciliumnetworkpolicies.cilium.io -o json":            "cilium-network-policies-crd.json",
		"kubectl get crd ciliumclusterwidenetworkpolicies.cilium.io -o json": "cilium-clusterwide-network-policies-crd.json",
		"kubectl get serviceaccount --all-namespaces -o json":                "serviceaccounts.txt",
		"kubectl get clusterrole -o json":                                    "clusterroles.txt",
		"kubectl get clusterrolebinding -o json":                             "clusterrolebindings.txt",

		fmt.Sprintf("kubectl get cm cilium-config -n %s -o json", CiliumNamespace):                                                   "cilium-config.json",
		fmt.Sprintf("kubectl logs -l k8s-app=cilium -n %s --timestamps -c clean-cilium-state --tail -1", CiliumNamespace):            "cilium-init-container-logs.txt",
		fmt.Sprintf("kubectl logs -l k8s-app=cilium -n %s --timestamps -c clean-cilium-state --previous --tail -1", CiliumNamespace): "cilium-init-container-logs-previous.txt",
		fmt.Sprintf("kubectl logs -l k8s-app=cilium -n %s --timestamps --all-containers --tail -1", CiliumNamespace):                 "cilium-combined-logs.txt",
		fmt.Sprintf("kubectl logs -l k8s-app=cilium -n %s --timestamps --all-containers --previous --tail -1", CiliumNamespace):      "cilium-combined-logs-previous.txt",
	}

	kub.GeneratePodLogGatheringCommands(ctx, reportCmds)

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
func (kub *Kubectl) GetCiliumPodOnNode(node string) (string, error) {
	filter := fmt.Sprintf(
		"-o jsonpath='{.items[?(@.spec.nodeName == \"%s\")].metadata.name}'", node)

	res := kub.ExecShort(fmt.Sprintf(
		"%s -n %s get pods -l k8s-app=cilium %s", KubectlCmd, CiliumNamespace, filter))
	if !res.WasSuccessful() {
		return "", fmt.Errorf("Cilium pod not found on node '%s'", node)
	}

	return res.Stdout(), nil
}

// GetNodeInfo provides the node name and IP address based on the label
// (eg helpers.K8s1 or helpers.K8s2)
func (kub *Kubectl) GetNodeInfo(label string) (nodeName, nodeIP string) {
	nodeName, err := kub.GetNodeNameByLabel(label)
	gomega.ExpectWithOffset(1, err).To(gomega.BeNil(), "Cannot get node by label "+label)
	nodeIP, err = kub.GetNodeIPByLabel(label, false)
	gomega.ExpectWithOffset(1, err).Should(gomega.BeNil(), "Can not retrieve Node IP for "+label)
	return nodeName, nodeIP
}

// GetCiliumPodOnNodeWithLabel returns the name of the Cilium pod that is running on node with cilium.io/ci-node label
func (kub *Kubectl) GetCiliumPodOnNodeWithLabel(label string) (string, error) {
	node, err := kub.GetNodeNameByLabel(label)
	if err != nil {
		return "", fmt.Errorf("Unable to get nodes with label '%s': %s", label, err)
	}

	return kub.GetCiliumPodOnNode(node)
}

func (kub *Kubectl) validateCilium() error {
	var g errgroup.Group

	g.Go(func() error {
		if err := kub.ciliumStatusPreFlightCheck(); err != nil {
			return fmt.Errorf("status is unhealthy: %s", err)
		}
		return nil
	})

	g.Go(func() error {
		if err := kub.ciliumControllersPreFlightCheck(); err != nil {
			return fmt.Errorf("controllers are failing: %s", err)
		}
		return nil
	})

	if GetCurrentIntegration() != CIIntegrationFlannel {
		g.Go(func() error {
			if err := kub.ciliumHealthPreFlightCheck(); err != nil {
				return fmt.Errorf("connectivity health is failing: %s", err)
			}
			return nil
		})
	}

	g.Go(func() error {
		err := kub.fillServiceCache()
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
	})

	return g.Wait()
}

// CiliumPreFlightCheck specify that it checks that various subsystems within
// Cilium are in a good state. If one of the multiple preflight fails it'll
// return an error.
func (kub *Kubectl) CiliumPreFlightCheck() error {
	ginkgoext.By("Validating Cilium Installation")
	// Doing this withTimeout because the Status can be ready, but the other
	// nodes cannot be show up yet, and the cilium-health can fail as a false positive.
	var (
		lastError           string
		consecutiveFailures int
	)

	body := func() bool {
		if err := kub.validateCilium(); err != nil {
			if lastError != err.Error() || consecutiveFailures >= 5 {
				ginkgoext.By("Cilium is not ready yet: %s", err)
				lastError = err.Error()
				consecutiveFailures = 0
			} else {
				consecutiveFailures++
			}
			return false
		}
		return true

	}
	if err := RepeatUntilTrue(body, &TimeoutConfig{Timeout: HelperTimeout}); err != nil {
		return fmt.Errorf("Cilium validation failed: %s: Last polled error: %s", err, lastError)
	}
	return nil
}

func (kub *Kubectl) ciliumStatusPreFlightCheck() error {
	ginkgoext.By("Performing Cilium status preflight check")
	ciliumPods, err := kub.GetCiliumPods()
	if err != nil {
		return fmt.Errorf("cannot retrieve cilium pods: %s", err)
	}
	reNoQuorum := regexp.MustCompile(`^.*KVStore:.*has-quorum=false.*$`)
	for _, pod := range ciliumPods {
		status := kub.CiliumExecContext(context.TODO(), pod, "cilium status --all-health --all-nodes")
		if !status.WasSuccessful() {
			return fmt.Errorf("cilium-agent '%s' is unhealthy: %s", pod, status.OutputPrettyPrint())
		}
		if reNoQuorum.Match(status.GetStdOut().Bytes()) {
			return fmt.Errorf("KVStore doesn't have quorum: %s", status.OutputPrettyPrint())
		}
	}

	return nil
}

func (kub *Kubectl) ciliumControllersPreFlightCheck() error {
	ginkgoext.By("Performing Cilium controllers preflight check")
	var controllersFilter = `{range .controllers[*]}{.name}{"="}{.status.consecutive-failure-count}{"\n"}{end}`
	ciliumPods, err := kub.GetCiliumPods()
	if err != nil {
		return fmt.Errorf("cannot retrieve cilium pods: %s", err)
	}
	for _, pod := range ciliumPods {
		status := kub.CiliumExecContext(context.TODO(), pod, fmt.Sprintf(
			"cilium status --all-controllers -o jsonpath='%s'", controllersFilter))
		if !status.WasSuccessful() {
			return fmt.Errorf("cilium-agent '%s': Cannot run cilium status: %s",
				pod, status.OutputPrettyPrint())
		}
		for controller, status := range status.KVOutput() {
			if status != "0" {
				failmsg := kub.CiliumExecContext(context.TODO(), pod, "cilium status --all-controllers")
				return fmt.Errorf("cilium-agent '%s': controller %s is failing: %s",
					pod, controller, failmsg.OutputPrettyPrint())
			}
		}
	}

	return nil
}

func (kub *Kubectl) ciliumHealthPreFlightCheck() error {
	ginkgoext.By("Performing Cilium health check")
	var nodesFilter = `{.nodes[*].name}`
	var statusFilter = `{range .nodes[*]}{.name}{"="}{.host.primary-address.http.status}{"\n"}{end}`

	ciliumPods, err := kub.GetCiliumPods()
	if err != nil {
		return fmt.Errorf("cannot retrieve cilium pods: %s", err)
	}
	for _, pod := range ciliumPods {
		status := kub.CiliumExecContext(context.TODO(), pod, "cilium-health status -o json --probe")
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
				pod, len(ciliumPods), len(nodeCount), nodeCount)
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

	ciliumPods, err := kub.GetCiliumPods()
	if err != nil {
		return fmt.Errorf("cannot retrieve cilium pods: %s", err)
	}
	ciliumSvcCmd := "cilium service list -o json"
	ciliumBpfLbCmd := "cilium bpf lb list -o json"

	cache.pods = make([]ciliumPodServiceCache, 0, len(ciliumPods))
	for _, pod := range ciliumPods {
		podCache := ciliumPodServiceCache{name: pod}

		ciliumServicesRes := kub.CiliumExecContext(context.TODO(), pod, ciliumSvcCmd)
		err := ciliumServicesRes.GetErr(
			fmt.Sprintf("Unable to retrieve Cilium services on %s", pod))
		if err != nil {
			return err
		}

		err = ciliumServicesRes.Unmarshal(&podCache.services)
		if err != nil {
			return fmt.Errorf("Unable to unmarshal Cilium services: %s", err.Error())
		}

		ciliumLbRes := kub.CiliumExecContext(context.TODO(), pod, ciliumBpfLbCmd)
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
	var dnsErr error
	body := func() bool {
		dnsErr = kub.fillServiceCache()
		if dnsErr != nil {
			return false
		}
		dnsErr = kub.servicePreFlightCheck("kube-dns", KubeSystemNamespace)
		return dnsErr == nil
	}

	err := WithTimeout(body, "DNS not ready within timeout", &TimeoutConfig{Timeout: HelperTimeout})
	if err != nil {
		return fmt.Errorf("kube-dns service not ready: %s", dnsErr)
	}
	return nil
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

// CiliumServiceAdd adds the given service on a 'pod' running Cilium
func (kub *Kubectl) CiliumServiceAdd(pod string, id int64, frontend string, backends []string, svcType, trafficPolicy string) error {
	var opts []string
	switch strings.ToLower(svcType) {
	case "nodeport":
		opts = append(opts, "--k8s-node-port")
	case "externalip":
		opts = append(opts, "--k8s-external")
	case "localredirect":
		opts = append(opts, "--local-redirect")
	case "clusterip":
		// this is the default
	default:
		return fmt.Errorf("invalid service type: %q", svcType)
	}

	trafficPolicy = strings.Title(strings.ToLower(trafficPolicy))
	switch trafficPolicy {
	case "Cluster", "Local":
		opts = append(opts, "--k8s-traffic-policy "+trafficPolicy)
	default:
		return fmt.Errorf("invalid traffic policy: %q", svcType)
	}

	optsStr := strings.Join(opts, " ")
	backendsStr := strings.Join(backends, ",")
	ctx, cancel := context.WithTimeout(context.Background(), ShortCommandTimeout)
	defer cancel()
	return kub.CiliumExecContext(ctx, pod, fmt.Sprintf("cilium service update --id %d --frontend %q --backends %q %s",
		id, frontend, backendsStr, optsStr)).GetErr("cilium service update")
}

// CiliumServiceDel deletes the service with 'id' on a 'pod' running Cilium
func (kub *Kubectl) CiliumServiceDel(pod string, id int64) error {
	ctx, cancel := context.WithTimeout(context.Background(), ShortCommandTimeout)
	defer cancel()
	return kub.CiliumExecContext(ctx, pod, fmt.Sprintf("cilium service delete %d", id)).GetErr("cilium service delete")
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

// reportMapContext saves the output of the given commands to the specified filename.
// Function needs a directory path where the files are going to be written
// commands are run on all pods matching selector
func (kub *Kubectl) reportMapContext(ctx context.Context, path string, reportCmds map[string]string, ns, selector string) {
	for cmd, logfile := range reportCmds {
		results, err := kub.ExecInPods(ctx, ns, selector, cmd, ExecOptions{SkipLog: true})
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
	wg := sync.WaitGroup{}
	for cmd, logfile := range reportCmds {
		wg.Add(1)
		go func(cmd, logfile string) {
			defer wg.Done()
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
		}(cmd, logfile)
	}
	wg.Wait()
}

// HelmAddCiliumRepo installs the repository that contain Cilium helm charts.
func (kub *Kubectl) HelmAddCiliumRepo() *CmdRes {
	return kub.ExecMiddle("helm repo add cilium https://helm.cilium.io")
}

// HelmTemplate renders given helm template. TODO: use go helm library for that
// We use --validate with `helm template` to properly populate the built-in objects like
// .Capabilities.KubeVersion with the values from associated cluster.
// This comes with a caveat that the command might fail if helm is not able to validate the
// chart install on the cluster, like if a previous cilium install is not cleaned up properly
// from the cluster. For this the caller has to make sure that there are no leftover cilium
// components in the cluster.
func (kub *Kubectl) HelmTemplate(chartDir, namespace, filename string, options map[string]string) *CmdRes {
	optionsString := ""

	for k, v := range options {
		optionsString += fmt.Sprintf(" --set %s=%s ", k, v)
	}

	return kub.ExecMiddle("helm template --validate " +
		chartDir + " " +
		fmt.Sprintf("--namespace=%s %s > %s", namespace, optionsString, filename))
}

// HubbleObserve runs `hubble observe --output=json <args>` on 'ns/pod' and
// waits for its completion.
func (kub *Kubectl) HubbleObserve(pod string, args string) *CmdRes {
	ctx, cancel := context.WithTimeout(context.Background(), ShortCommandTimeout)
	defer cancel()
	return kub.ExecPodCmdContext(ctx, CiliumNamespace, pod, fmt.Sprintf("hubble observe --output=json %s", args))
}

// HubbleObserveFollow runs `hubble observe --follow --output=json <args>` on
// 'ns/pod' in the background. The process is stopped when ctx is cancelled.
func (kub *Kubectl) HubbleObserveFollow(ctx context.Context, pod string, args string) *CmdRes {
	return kub.ExecPodCmdBackground(ctx, CiliumNamespace, pod, fmt.Sprintf("hubble observe --follow --output=json %s", args))
}

// WaitForIPCacheEntry waits until the given ipAddr appears in "cilium bpf ipcache list"
// on the given node.
func (kub *Kubectl) WaitForIPCacheEntry(node, ipAddr string) error {
	ciliumPod, err := kub.GetCiliumPodOnNode(node)
	if err != nil {
		return err
	}

	body := func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), ShortCommandTimeout)
		defer cancel()
		cmd := fmt.Sprintf(`cilium bpf ipcache list | grep -q %s`, ipAddr)
		return kub.CiliumExecContext(ctx, ciliumPod, cmd).WasSuccessful()
	}

	return WithTimeout(body,
		fmt.Sprintf("ipcache entry for %s was not found in time", ipAddr),
		&TimeoutConfig{Timeout: HelperTimeout})
}

// RepeatCommandInBackground runs command on repeat in goroutine until quit channel
// is closed and closes run channel when command is first run
func (kub *Kubectl) RepeatCommandInBackground(cmd string) (quit, run chan struct{}) {
	quit = make(chan struct{})
	run = make(chan struct{})
	go func() {
		firstRun := true
		for {
			select {
			case <-quit:
				return
			default:
				res := kub.Exec(cmd)
				if !res.WasSuccessful() {
					kub.Logger().WithFields(logrus.Fields{
						"cmd": cmd,
					}).Warning("Command failed running in the background")
				}
				if firstRun {
					close(run)
				}
				firstRun = false
			}
		}
	}()
	return
}

func serviceKey(s v1.Service) string {
	return s.Namespace + "/" + s.Name
}

// validateCiliumSvc checks if given Cilium service has corresponding k8s services and endpoints in given slices
func validateCiliumSvc(cSvc models.Service, k8sSvcs []v1.Service, k8sEps []v1.Endpoints, k8sServicesFound map[string]bool) error {
	var k8sService *v1.Service

	// TODO(brb) validate NodePort, LoadBalancer and HostPort services
	if cSvc.Status.Realized.Flags != nil {
		switch cSvc.Status.Realized.Flags.Type {
		case models.ServiceSpecFlagsTypeNodePort,
			models.ServiceSpecFlagsTypeHostPort,
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
	scope := ""
	if cSvc.Status.Realized.FrontendAddress.Scope == models.FrontendAddressScopeInternal {
		scope = "/i"
	}

	frontendAddress := net.JoinHostPort(
		cSvc.Status.Realized.FrontendAddress.IP,
		strconv.Itoa(int(cSvc.Status.Realized.FrontendAddress.Port))) + scope
	bpfBackends, ok := lbMap[frontendAddress]
	if !ok {
		return fmt.Errorf("%s bpf lb map entry not found", frontendAddress)
	}

BACKENDS:
	for _, addr := range cSvc.Status.Realized.BackendAddresses {
		backend := net.JoinHostPort(*addr.IP, strconv.Itoa(int(addr.Port)))
		for _, bpfAddr := range bpfBackends {
			if strings.Contains(bpfAddr, backend) {
				continue BACKENDS
			}
		}
		return fmt.Errorf("%s not found in bpf map for frontend %s", backend, frontendAddress)
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
// prefixing with timestamp
func GenerateNamespaceForTest(seed string) string {
	lowered := strings.ToLower(ginkgoext.CurrentGinkgoTestDescription().FullTestText)
	// K8s namespaces cannot have spaces, underscores or slashes.
	replaced := strings.Replace(lowered, " ", "", -1)
	replaced = strings.Replace(replaced, "_", "", -1)
	replaced = strings.Replace(replaced, "/", "", -1)

	timestamped := time.Now().Format("200601021504") + seed + replaced

	if len(timestamped) <= 63 {
		return timestamped
	}

	return timestamped[:63]
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

// GetDNSProxyPort returns the port the Cilium DNS proxy is listening on
func (kub *Kubectl) GetDNSProxyPort(ciliumPod string) int {
	// We could fetch this from Cilium as per the below if an endpoint is
	// configured with policy prior to calling this function:
	// # cilium status -o jsonpath='{.proxy.redirects[?(@.proxy=="cilium-dns-egress")].proxy-port}'
	//
	// However, the callees don't reliably do this. So revert back to 'ss':
	// #  ss -uap | grep cilium-agent
	// UNCONN 0 0 *:33647 *:* users:(("cilium-agent",pid=9745,fd=28))
	const pickDNSProxyPort = `ss -uap | grep cilium-agent | awk '{ print $4 }' | awk -F':' '{ print $2 }'`

	// Find out the DNS proxy ports in use
	res := kub.CiliumExecContext(context.TODO(), ciliumPod, pickDNSProxyPort)
	if !res.WasSuccessful() {
		ginkgoext.Failf("Cannot find DNS proxy port on %s", ciliumPod)
	}
	portStr := res.GetStdOut().String()
	gomega.ExpectWithOffset(1, portStr).ShouldNot(gomega.BeEmpty(), "No DNS proxy port found on %s", ciliumPod)
	port, err := strconv.Atoi(strings.TrimSpace(portStr))
	if err != nil || port == 0 {
		ginkgoext.Failf("Invalid DNS proxy port on %s: %s", ciliumPod, portStr)
	}
	return port
}

// AddIPRoute adds a route to a given subnet address and a gateway on a given
// node via the iproute2 utility suite. The function takes in a flag called
// replace which will convert the action to replace the  route being added if
// another route exists and matches. This allows for idempotency as the "replace"
// action will not fail if another matching route exists, whereas "add" will fail.
func (kub *Kubectl) AddIPRoute(nodeName, subnet, gw string, replace bool) *CmdRes {
	action := "add"
	if replace {
		action = "replace"
	}
	cmd := fmt.Sprintf("ip route %s %s via %s", action, subnet, gw)

	return kub.ExecInHostNetNS(context.TODO(), nodeName, cmd)
}

// DelIPRoute deletes a route to a given IP address and a gateway on a given
// node via the iproute2 utility suite.
func (kub *Kubectl) DelIPRoute(nodeName, subnet, gw string) *CmdRes {
	cmd := fmt.Sprintf("ip route del %s via %s", subnet, gw)

	return kub.ExecInHostNetNS(context.TODO(), nodeName, cmd)
}

// CleanupCiliumComponents removes all the cilium related components from the cluster.
// This is best effort, any error occurring when deleting resources is ignored.
func (kub *Kubectl) CleanupCiliumComponents() {
	ginkgoext.By("Cleaning up Cilium components")

	var (
		wg sync.WaitGroup

		resourcesToDelete = map[string]string{
			"configmap":          "cilium-config hubble-ca-cert hubble-relay-config",
			"daemonset":          "cilium cilium-node-init",
			"deployment":         "cilium-operator hubble-relay",
			"clusterrolebinding": "cilium cilium-operator hubble-relay",
			"clusterrole":        "cilium cilium-operator hubble-relay",
			"serviceaccount":     "cilium cilium-operator hubble-relay",
			"service":            "cilium-agent hubble-metrics hubble-relay",
			"secret":             "hubble-relay-client-certs hubble-server-certs",
			"resourcequota":      "cilium-resource-quota cilium-operator-resource-quota",
		}

		crdsToDelete = synced.AllCRDResourceNames
	)

	wg.Add(len(resourcesToDelete))
	for resourceType, resource := range resourcesToDelete {
		go func(resource, resourceType string) {
			_ = kub.DeleteResource(resourceType, "-n "+CiliumNamespace+" "+resource)
			wg.Done()
		}(resource, resourceType)
	}

	wg.Add(len(crdsToDelete))
	for _, crd := range crdsToDelete {
		// crd is of format `type:name`, e.g. "crd:ciliumnodes.cilium.io"
		parts := strings.SplitN(crd, ":", 2)
		go func(resource, resourceType string) {
			_ = kub.DeleteResource(resourceType, resource)
			wg.Done()
		}(parts[1], parts[0])
	}

	wg.Wait()
}

// checks dig output for ip address
func hasIPAddress(output []string) (bool, string) {
	for _, line := range output {
		ip := net.ParseIP(line)
		if ip != nil {
			return true, line
		}
	}
	return false, ""
}
