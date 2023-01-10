// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/cilium/cilium/test/config"
	ginkgoext "github.com/cilium/cilium/test/ginkgo-ext"
)

// NamespaceName represents a Kubernetes namespace name
type NamespaceName string

// IsRandom returns true if the namespace name has been generated with
// GenerateNamespaceForTest
func (n NamespaceName) IsRandom() bool { return strings.HasPrefix(string(n), "202") }
func (n NamespaceName) String() string { return string(n) }

// Manifest represents a deployment manifest that can consist of an any number
// of Deployments, DaemonSets, Pods, etc.
type Manifest struct {
	// Filename is the file (not path) of the manifest. This must point to
	// a file that contains any number of Deployments, DaemonSets, ...
	Filename string

	// Alternate is an alternative file (not path) of the manifest that
	// takes the place of 'Filename' for single-node testing. It is
	// otherwise equivalent and must point to a file containing resources
	// to deploy.
	Alternate string

	// DaemonSetNames is the list of all daemonset names in the manifest
	DaemonSetNames []string

	// DeploymentNames is the list of all deployment names in the manifest
	DeploymentNames []string

	// NumPods is the number of pods expected in the manifest, not counting
	// any DaemonSets
	NumPods int

	// LabelSelector is the selector required to select *ALL* pods created
	// from this manifest
	LabelSelector string

	// Singleton marks a manifest as singleton. A singleton manifest can be
	// deployed exactly once into the cluster, regardless of the namespace
	// the manifest is deployed into. Singletons are required if the
	// deployment is using HostPorts, NodePorts or other resources which
	// may conflict if the deployment is scheduled multiple times onto the
	// same node.
	Singleton bool
}

// GetFilename resolves the filename for the manifest depending on whether the
// alternate filename is used (ie, single node testing YAMLs)
func (m Manifest) GetFilename() string {
	if config.CiliumTestConfig.Multinode {
		return m.Filename
	}
	return m.Alternate
}

// Deploy deploys the manifest. It will call ginkgoext.Fail() if any aspect of
// that fails.
func (m Manifest) Deploy(kubectl *Kubectl, namespace string) *Deployment {
	deploy, err := m.deploy(kubectl, namespace)
	if err != nil {
		ginkgoext.Failf("Unable to deploy manifest %s: %s", m.GetFilename(), err)
	}

	return deploy
}

// deleteInAnyNamespace is used to delete all resources of the manifest in all
// namespaces. This is required to implement singleton manifests. For the most
// part, this will have no effect as PrepareCluster() will delete any leftover
// temporary namespaces before starting the tests. This deletion is a safety
// net for any deployment leaks between tests and in case a test deploys into a
// non-random namespace.
func (m Manifest) deleteInAnyNamespace(kubectl *Kubectl) {
	if len(m.DaemonSetNames) > 0 {
		if err := kubectl.DeleteResourcesInAnyNamespace("daemonset", m.DaemonSetNames); err != nil {
			ginkgoext.Failf("Unable to delete existing daemonsets [%s] while deploying singleton manifest: %s",
				m.DaemonSetNames, err)
		}
	}

	if len(m.DeploymentNames) > 0 {
		if err := kubectl.DeleteResourcesInAnyNamespace("deployment", m.DeploymentNames); err != nil {
			ginkgoext.Failf("Unable to delete existing deployments [%s] while deploying singleton manifest: %s",
				m.DeploymentNames, err)
		}
	}
}

func (m Manifest) deploy(kubectl *Kubectl, namespace string) (*Deployment, error) {
	ginkgoext.By("Deploying %s in namespace %s", m.GetFilename(), namespace)

	if m.Singleton {
		m.deleteInAnyNamespace(kubectl)
	}

	numNodes := kubectl.GetNumCiliumNodes()
	if numNodes == 0 {
		return nil, fmt.Errorf("No available nodes to deploy")
	}

	path := ManifestGet(kubectl.BasePath(), m.GetFilename())
	res := kubectl.Apply(ApplyOptions{Namespace: namespace, FilePath: path})
	if !res.WasSuccessful() {
		return nil, fmt.Errorf("Unable to deploy manifest %s: %s", path, res.CombineOutput().String())
	}

	d := &Deployment{
		manifest:  m,
		kubectl:   kubectl,
		numNodes:  numNodes,
		namespace: NamespaceName(namespace),
		path:      path,
	}

	return d, nil
}

// Deployment is a deployed manifest. The deployment binds the manifest to a
// particular namespace and records the number of nodes the deployment is
// spread over.
type Deployment struct {
	kubectl   *Kubectl
	manifest  Manifest
	numNodes  int
	namespace NamespaceName
	path      string
}

// numExpectedPods returns the number of expected pods the deployment resulted
// in
func (d *Deployment) numExpectedPods() int {
	return (d.numNodes * len(d.manifest.DaemonSetNames)) + d.manifest.NumPods
}

// WaitUntilReady waits until all pods of the deployment are up and in ready
// state
func (d *Deployment) WaitUntilReady() {
	expectedPods := d.numExpectedPods()
	if expectedPods == 0 {
		return
	}

	ginkgoext.By("Waiting for %s for %d pods of deployment %s to become ready",
		HelperTimeout, expectedPods, d.manifest.GetFilename())

	if err := d.kubectl.WaitforNPods(string(d.namespace), "", expectedPods, HelperTimeout); err != nil {
		ginkgoext.Failf("Pods are not ready in time: %s", err)
	}
}

// Delete deletes the deployment
func (d *Deployment) Delete() {
	ginkgoext.By("Deleting deployment %s", d.manifest.GetFilename())
	d.kubectl.DeleteInNamespace(string(d.namespace), d.path)
}

// DeploymentManager manages a set of deployments
type DeploymentManager struct {
	kubectl        *Kubectl
	deployments    map[string]*Deployment
	ciliumDeployed bool
	ciliumFilename string
}

// NewDeploymentManager returns a new deployment manager
func NewDeploymentManager() *DeploymentManager {
	return &DeploymentManager{
		deployments:    map[string]*Deployment{},
		ciliumFilename: TimestampFilename("cilium.yaml"),
	}
}

// SetKubectl sets the kubectl client to use
func (m *DeploymentManager) SetKubectl(kubectl *Kubectl) {
	m.kubectl = kubectl
}

// DeployRandomNamespaceShared is like DeployRandomNamespace but will check if
// the Manifest has already been deployed in any namespace. If so, returns the
// namespace the existing deployment is running in. If not, the manifest is
// deployed using DeployRandomNamespace.
func (m *DeploymentManager) DeployRandomNamespaceShared(manifest Manifest) string {
	if d, ok := m.deployments[manifest.GetFilename()]; ok {
		return string(d.namespace)
	}

	return m.DeployRandomNamespace(manifest)
}

// DeployRandomNamespace deploys a manifest into a random namespace using the
// deployment manager and stores the deployment in the manager
func (m *DeploymentManager) DeployRandomNamespace(manifest Manifest) string {
	namespace := GenerateNamespaceForTest("")

	res := m.kubectl.NamespaceCreate(namespace)
	if !res.WasSuccessful() {
		ginkgoext.Failf("Unable to create namespace %s: %s",
			namespace, res.OutputPrettyPrint())
	}

	d, err := manifest.deploy(m.kubectl, namespace)
	if err != nil {
		m.kubectl.NamespaceDelete(namespace)

		ginkgoext.Failf("Unable to deploy manifest %s: %s", manifest.GetFilename(), err)
	}

	m.deployments[manifest.GetFilename()] = d

	return namespace
}

// Deploy deploys a manifest using the deployment manager and stores the
// deployment in the manager
func (m *DeploymentManager) Deploy(namespace string, manifest Manifest) {
	d, err := manifest.deploy(m.kubectl, namespace)
	if err != nil {
		ginkgoext.Failf("Unable to deploy manifest %s: %s", manifest.Filename, err)
	}

	m.deployments[manifest.Filename] = d
}

// DeleteAll deletes all deployments which have previously been deployed using
// this deployment manager
func (m *DeploymentManager) DeleteAll() {
	var (
		deleted = 0
		wg      sync.WaitGroup
	)

	wg.Add(len(m.deployments))
	for _, d := range m.deployments {
		// Issue all delete triggers in parallel
		go func(d *Deployment) {
			d.Delete()
			wg.Done()
		}(d)
		deleted++
	}

	namespaces := map[NamespaceName]struct{}{}
	for _, d := range m.deployments {
		if d.namespace.IsRandom() {
			namespaces[d.namespace] = struct{}{}
		}
	}

	wg.Wait()
	m.deployments = map[string]*Deployment{}

	wg.Add(len(namespaces))
	for namespace := range namespaces {
		go func(namespace NamespaceName) {
			m.kubectl.NamespaceDelete(string(namespace))
			wg.Done()
		}(namespace)
	}

	if deleted > 0 {
		m.kubectl.WaitTerminatingPods(2 * time.Minute)
	}
	wg.Wait()
}

// DeleteCilium deletes a Cilium deployment that was previously deployed with
// DeployCilium()
func (m *DeploymentManager) DeleteCilium() {
	if m.ciliumDeployed {
		// Ensure any Cilium-managed pods are terminated first
		m.kubectl.WaitTerminatingPods(2 * time.Minute)
		ginkgoext.By("Deleting Cilium")
		m.kubectl.DeleteAndWait(m.ciliumFilename, true)
		m.kubectl.WaitTerminatingPods(2 * time.Minute)
	}
}

// WaitUntilReady waits until all deployments managed by this manager are up
// and ready
func (m *DeploymentManager) WaitUntilReady() {
	for _, d := range m.deployments {
		d.WaitUntilReady()
	}
}

// CiliumDeployFunc is the function to use for deploying cilium.
type CiliumDeployFunc func(kubectl *Kubectl, ciliumFilename string, options map[string]string)

// DeployCilium deploys Cilium using the provided options and waits for it to
// become ready
func (m *DeploymentManager) DeployCilium(options map[string]string, deploy CiliumDeployFunc) {
	deploy(m.kubectl, m.ciliumFilename, options)

	_, err := m.kubectl.CiliumNodesWait()
	if err != nil {
		ginkgoext.Failf("Kubernetes nodes were not annotated by Cilium")
	}

	ginkgoext.By("Making sure all endpoints are in ready state")
	if err = m.kubectl.CiliumEndpointWaitReady(); err != nil {
		Fail(fmt.Sprintf("Failure while waiting for all cilium endpoints to reach ready state: %s", err))
	}

	m.ciliumDeployed = true
}
