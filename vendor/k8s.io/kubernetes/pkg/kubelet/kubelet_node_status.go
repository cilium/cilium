/*
Copyright 2016 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package kubelet

import (
	"fmt"
	"math"
	"net"
	goruntime "runtime"
	"sort"
	"strings"
	"time"

	"github.com/golang/glog"
	"k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/conversion"
	"k8s.io/apimachinery/pkg/types"
	utilnet "k8s.io/apimachinery/pkg/util/net"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	k8s_api_v1 "k8s.io/kubernetes/pkg/api/v1"
	v1helper "k8s.io/kubernetes/pkg/api/v1/helper"
	"k8s.io/kubernetes/pkg/cloudprovider"
	"k8s.io/kubernetes/pkg/features"
	kubeletapis "k8s.io/kubernetes/pkg/kubelet/apis"
	"k8s.io/kubernetes/pkg/kubelet/cadvisor"
	"k8s.io/kubernetes/pkg/kubelet/events"
	"k8s.io/kubernetes/pkg/kubelet/util"
	"k8s.io/kubernetes/pkg/kubelet/util/sliceutils"
	nodeutil "k8s.io/kubernetes/pkg/util/node"
	"k8s.io/kubernetes/pkg/version"
	"k8s.io/kubernetes/pkg/volume/util/volumehelper"
	"k8s.io/kubernetes/plugin/pkg/scheduler/algorithm"
)

const (
	// maxImagesInNodeStatus is the number of max images we store in image status.
	maxImagesInNodeStatus = 50

	// maxNamesPerImageInNodeStatus is max number of names per image stored in
	// the node status.
	maxNamesPerImageInNodeStatus = 5
)

// registerWithAPIServer registers the node with the cluster master. It is safe
// to call multiple times, but not concurrently (kl.registrationCompleted is
// not locked).
func (kl *Kubelet) registerWithAPIServer() {
	if kl.registrationCompleted {
		return
	}
	step := 100 * time.Millisecond

	for {
		time.Sleep(step)
		step = step * 2
		if step >= 7*time.Second {
			step = 7 * time.Second
		}

		node, err := kl.initialNode()
		if err != nil {
			glog.Errorf("Unable to construct v1.Node object for kubelet: %v", err)
			continue
		}

		glog.Infof("Attempting to register node %s", node.Name)
		registered := kl.tryRegisterWithAPIServer(node)
		if registered {
			glog.Infof("Successfully registered node %s", node.Name)
			kl.registrationCompleted = true
			return
		}
	}
}

// tryRegisterWithAPIServer makes an attempt to register the given node with
// the API server, returning a boolean indicating whether the attempt was
// successful.  If a node with the same name already exists, it reconciles the
// value of the annotation for controller-managed attach-detach of attachable
// persistent volumes for the node.  If a node of the same name exists but has
// a different externalID value, it attempts to delete that node so that a
// later attempt can recreate it.
func (kl *Kubelet) tryRegisterWithAPIServer(node *v1.Node) bool {
	_, err := kl.kubeClient.Core().Nodes().Create(node)
	if err == nil {
		return true
	}

	if !apierrors.IsAlreadyExists(err) {
		glog.Errorf("Unable to register node %q with API server: %v", kl.nodeName, err)
		return false
	}

	existingNode, err := kl.kubeClient.Core().Nodes().Get(string(kl.nodeName), metav1.GetOptions{})
	if err != nil {
		glog.Errorf("Unable to register node %q with API server: error getting existing node: %v", kl.nodeName, err)
		return false
	}
	if existingNode == nil {
		glog.Errorf("Unable to register node %q with API server: no node instance returned", kl.nodeName)
		return false
	}

	clonedNode, err := conversion.NewCloner().DeepCopy(existingNode)
	if err != nil {
		glog.Errorf("Unable to clone %q node object %#v: %v", kl.nodeName, existingNode, err)
		return false
	}

	originalNode, ok := clonedNode.(*v1.Node)
	if !ok || originalNode == nil {
		glog.Errorf("Unable to cast %q node object %#v to v1.Node", kl.nodeName, clonedNode)
		return false
	}

	if existingNode.Spec.ExternalID == node.Spec.ExternalID {
		glog.Infof("Node %s was previously registered", kl.nodeName)

		// Edge case: the node was previously registered; reconcile
		// the value of the controller-managed attach-detach
		// annotation.
		requiresUpdate := kl.reconcileCMADAnnotationWithExistingNode(node, existingNode)
		requiresUpdate = kl.updateDefaultLabels(node, existingNode) || requiresUpdate
		if requiresUpdate {
			if _, err := nodeutil.PatchNodeStatus(kl.kubeClient, types.NodeName(kl.nodeName),
				originalNode, existingNode); err != nil {
				glog.Errorf("Unable to reconcile node %q with API server: error updating node: %v", kl.nodeName, err)
				return false
			}
		}

		return true
	}

	glog.Errorf(
		"Previously node %q had externalID %q; now it is %q; will delete and recreate.",
		kl.nodeName, node.Spec.ExternalID, existingNode.Spec.ExternalID,
	)
	if err := kl.kubeClient.Core().Nodes().Delete(node.Name, nil); err != nil {
		glog.Errorf("Unable to register node %q with API server: error deleting old node: %v", kl.nodeName, err)
	} else {
		glog.Infof("Deleted old node object %q", kl.nodeName)
	}

	return false
}

// updateDefaultLabels will set the default labels on the node
func (kl *Kubelet) updateDefaultLabels(initialNode, existingNode *v1.Node) bool {
	defaultLabels := []string{
		kubeletapis.LabelHostname,
		kubeletapis.LabelZoneFailureDomain,
		kubeletapis.LabelZoneRegion,
		kubeletapis.LabelInstanceType,
		kubeletapis.LabelOS,
		kubeletapis.LabelArch,
	}

	var needsUpdate bool = false
	//Set default labels but make sure to not set labels with empty values
	for _, label := range defaultLabels {
		if existingNode.Labels[label] != initialNode.Labels[label] {
			existingNode.Labels[label] = initialNode.Labels[label]
			needsUpdate = true
		}

		if existingNode.Labels[label] == "" {
			delete(existingNode.Labels, label)
		}
	}

	return needsUpdate
}

// reconcileCMADAnnotationWithExistingNode reconciles the controller-managed
// attach-detach annotation on a new node and the existing node, returning
// whether the existing node must be updated.
func (kl *Kubelet) reconcileCMADAnnotationWithExistingNode(node, existingNode *v1.Node) bool {
	var (
		existingCMAAnnotation    = existingNode.Annotations[volumehelper.ControllerManagedAttachAnnotation]
		newCMAAnnotation, newSet = node.Annotations[volumehelper.ControllerManagedAttachAnnotation]
	)

	if newCMAAnnotation == existingCMAAnnotation {
		return false
	}

	// If the just-constructed node and the existing node do
	// not have the same value, update the existing node with
	// the correct value of the annotation.
	if !newSet {
		glog.Info("Controller attach-detach setting changed to false; updating existing Node")
		delete(existingNode.Annotations, volumehelper.ControllerManagedAttachAnnotation)
	} else {
		glog.Info("Controller attach-detach setting changed to true; updating existing Node")
		if existingNode.Annotations == nil {
			existingNode.Annotations = make(map[string]string)
		}
		existingNode.Annotations[volumehelper.ControllerManagedAttachAnnotation] = newCMAAnnotation
	}

	return true
}

// initialNode constructs the initial v1.Node for this Kubelet, incorporating node
// labels, information from the cloud provider, and Kubelet configuration.
func (kl *Kubelet) initialNode() (*v1.Node, error) {
	node := &v1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: string(kl.nodeName),
			Labels: map[string]string{
				kubeletapis.LabelHostname: kl.hostname,
				kubeletapis.LabelOS:       goruntime.GOOS,
				kubeletapis.LabelArch:     goruntime.GOARCH,
			},
		},
		Spec: v1.NodeSpec{
			Unschedulable: !kl.registerSchedulable,
		},
	}
	nodeTaints := make([]v1.Taint, 0)
	if len(kl.kubeletConfiguration.RegisterWithTaints) > 0 {
		taints := make([]v1.Taint, len(kl.kubeletConfiguration.RegisterWithTaints))
		for i := range kl.kubeletConfiguration.RegisterWithTaints {
			if err := k8s_api_v1.Convert_api_Taint_To_v1_Taint(&kl.kubeletConfiguration.RegisterWithTaints[i], &taints[i], nil); err != nil {
				return nil, err
			}
		}
		nodeTaints = append(nodeTaints, taints...)
	}
	if kl.externalCloudProvider {
		taint := v1.Taint{
			Key:    algorithm.TaintExternalCloudProvider,
			Value:  "true",
			Effect: v1.TaintEffectNoSchedule,
		}

		nodeTaints = append(nodeTaints, taint)
	}
	if len(nodeTaints) > 0 {
		node.Spec.Taints = nodeTaints
	}
	// Initially, set NodeNetworkUnavailable to true.
	if kl.providerRequiresNetworkingConfiguration() {
		node.Status.Conditions = append(node.Status.Conditions, v1.NodeCondition{
			Type:               v1.NodeNetworkUnavailable,
			Status:             v1.ConditionTrue,
			Reason:             "NoRouteCreated",
			Message:            "Node created without a route",
			LastTransitionTime: metav1.NewTime(kl.clock.Now()),
		})
	}

	if kl.enableControllerAttachDetach {
		if node.Annotations == nil {
			node.Annotations = make(map[string]string)
		}

		glog.Infof("Setting node annotation to enable volume controller attach/detach")
		node.Annotations[volumehelper.ControllerManagedAttachAnnotation] = "true"
	} else {
		glog.Infof("Controller attach/detach is disabled for this node; Kubelet will attach and detach volumes")
	}

	if kl.kubeletConfiguration.KeepTerminatedPodVolumes {
		if node.Annotations == nil {
			node.Annotations = make(map[string]string)
		}
		glog.Infof("Setting node annotation to keep pod volumes of terminated pods attached to the node")
		node.Annotations[volumehelper.KeepTerminatedPodVolumesAnnotation] = "true"
	}

	// @question: should this be place after the call to the cloud provider? which also applies labels
	for k, v := range kl.nodeLabels {
		if cv, found := node.ObjectMeta.Labels[k]; found {
			glog.Warningf("the node label %s=%s will overwrite default setting %s", k, v, cv)
		}
		node.ObjectMeta.Labels[k] = v
	}

	if kl.providerID != "" {
		node.Spec.ProviderID = kl.providerID
	}

	if kl.cloud != nil {
		instances, ok := kl.cloud.Instances()
		if !ok {
			return nil, fmt.Errorf("failed to get instances from cloud provider")
		}

		// TODO(roberthbailey): Can we do this without having credentials to talk
		// to the cloud provider?
		// TODO: ExternalID is deprecated, we'll have to drop this code
		externalID, err := instances.ExternalID(kl.nodeName)
		if err != nil {
			return nil, fmt.Errorf("failed to get external ID from cloud provider: %v", err)
		}
		node.Spec.ExternalID = externalID

		// TODO: We can't assume that the node has credentials to talk to the
		// cloudprovider from arbitrary nodes. At most, we should talk to a
		// local metadata server here.
		if node.Spec.ProviderID == "" {
			node.Spec.ProviderID, err = cloudprovider.GetInstanceProviderID(kl.cloud, kl.nodeName)
			if err != nil {
				return nil, err
			}
		}

		instanceType, err := instances.InstanceType(kl.nodeName)
		if err != nil {
			return nil, err
		}
		if instanceType != "" {
			glog.Infof("Adding node label from cloud provider: %s=%s", kubeletapis.LabelInstanceType, instanceType)
			node.ObjectMeta.Labels[kubeletapis.LabelInstanceType] = instanceType
		}
		// If the cloud has zone information, label the node with the zone information
		zones, ok := kl.cloud.Zones()
		if ok {
			zone, err := zones.GetZone()
			if err != nil {
				return nil, fmt.Errorf("failed to get zone from cloud provider: %v", err)
			}
			if zone.FailureDomain != "" {
				glog.Infof("Adding node label from cloud provider: %s=%s", kubeletapis.LabelZoneFailureDomain, zone.FailureDomain)
				node.ObjectMeta.Labels[kubeletapis.LabelZoneFailureDomain] = zone.FailureDomain
			}
			if zone.Region != "" {
				glog.Infof("Adding node label from cloud provider: %s=%s", kubeletapis.LabelZoneRegion, zone.Region)
				node.ObjectMeta.Labels[kubeletapis.LabelZoneRegion] = zone.Region
			}
		}
	} else {
		node.Spec.ExternalID = kl.hostname
		if kl.autoDetectCloudProvider {
			// If no cloud provider is defined - use the one detected by cadvisor
			info, err := kl.GetCachedMachineInfo()
			if err == nil {
				kl.updateCloudProviderFromMachineInfo(node, info)
			}
		}
	}
	kl.setNodeStatus(node)

	return node, nil
}

// syncNodeStatus should be called periodically from a goroutine.
// It synchronizes node status to master, registering the kubelet first if
// necessary.
func (kl *Kubelet) syncNodeStatus() {
	if kl.kubeClient == nil {
		return
	}
	if kl.registerNode {
		// This will exit immediately if it doesn't need to do anything.
		kl.registerWithAPIServer()
	}
	if err := kl.updateNodeStatus(); err != nil {
		glog.Errorf("Unable to update node status: %v", err)
	}
}

// updateNodeStatus updates node status to master with retries.
func (kl *Kubelet) updateNodeStatus() error {
	for i := 0; i < nodeStatusUpdateRetry; i++ {
		if err := kl.tryUpdateNodeStatus(i); err != nil {
			glog.Errorf("Error updating node status, will retry: %v", err)
		} else {
			return nil
		}
	}
	return fmt.Errorf("update node status exceeds retry count")
}

// tryUpdateNodeStatus tries to update node status to master. If ReconcileCBR0
// is set, this function will also confirm that cbr0 is configured correctly.
func (kl *Kubelet) tryUpdateNodeStatus(tryNumber int) error {
	// In large clusters, GET and PUT operations on Node objects coming
	// from here are the majority of load on apiserver and etcd.
	// To reduce the load on etcd, we are serving GET operations from
	// apiserver cache (the data might be slightly delayed but it doesn't
	// seem to cause more conflict - the delays are pretty small).
	// If it result in a conflict, all retries are served directly from etcd.
	opts := metav1.GetOptions{}
	if tryNumber == 0 {
		util.FromApiserverCache(&opts)
	}
	node, err := kl.kubeClient.Core().Nodes().Get(string(kl.nodeName), opts)
	if err != nil {
		return fmt.Errorf("error getting node %q: %v", kl.nodeName, err)
	}

	clonedNode, err := conversion.NewCloner().DeepCopy(node)
	if err != nil {
		return fmt.Errorf("error clone node %q: %v", kl.nodeName, err)
	}

	originalNode, ok := clonedNode.(*v1.Node)
	if !ok || originalNode == nil {
		return fmt.Errorf("failed to cast %q node object %#v to v1.Node", kl.nodeName, clonedNode)
	}

	kl.updatePodCIDR(node.Spec.PodCIDR)

	kl.setNodeStatus(node)
	// Patch the current status on the API server
	updatedNode, err := nodeutil.PatchNodeStatus(kl.kubeClient, types.NodeName(kl.nodeName), originalNode, node)
	if err != nil {
		return err
	}
	// If update finishes successfully, mark the volumeInUse as reportedInUse to indicate
	// those volumes are already updated in the node's status
	kl.volumeManager.MarkVolumesAsReportedInUse(updatedNode.Status.VolumesInUse)
	return nil
}

// recordNodeStatusEvent records an event of the given type with the given
// message for the node.
func (kl *Kubelet) recordNodeStatusEvent(eventType, event string) {
	glog.V(2).Infof("Recording %s event message for node %s", event, kl.nodeName)
	// TODO: This requires a transaction, either both node status is updated
	// and event is recorded or neither should happen, see issue #6055.
	kl.recorder.Eventf(kl.nodeRef, eventType, event, "Node %s status is now: %s", kl.nodeName, event)
}

// Set IP and hostname addresses for the node.
func (kl *Kubelet) setNodeAddress(node *v1.Node) error {
	if kl.nodeIP != nil {
		if err := kl.validateNodeIP(); err != nil {
			return fmt.Errorf("failed to validate nodeIP: %v", err)
		}
		glog.V(2).Infof("Using node IP: %q", kl.nodeIP.String())
	}

	if kl.externalCloudProvider {
		// We rely on the external cloud provider to supply the addresses.
		return nil
	}
	if kl.cloud != nil {
		instances, ok := kl.cloud.Instances()
		if !ok {
			return fmt.Errorf("failed to get instances from cloud provider")
		}
		// TODO(roberthbailey): Can we do this without having credentials to talk
		// to the cloud provider?
		// TODO(justinsb): We can if CurrentNodeName() was actually CurrentNode() and returned an interface
		// TODO: If IP addresses couldn't be fetched from the cloud provider, should kubelet fallback on the other methods for getting the IP below?
		nodeAddresses, err := instances.NodeAddresses(kl.nodeName)
		if err != nil {
			return fmt.Errorf("failed to get node address from cloud provider: %v", err)
		}
		if kl.nodeIP != nil {
			enforcedNodeAddresses := []v1.NodeAddress{}
			for _, nodeAddress := range nodeAddresses {
				if nodeAddress.Address == kl.nodeIP.String() {
					enforcedNodeAddresses = append(enforcedNodeAddresses, v1.NodeAddress{Type: nodeAddress.Type, Address: nodeAddress.Address})
				}
			}
			if len(enforcedNodeAddresses) > 0 {
				enforcedNodeAddresses = append(enforcedNodeAddresses, v1.NodeAddress{Type: v1.NodeHostName, Address: kl.GetHostname()})
				node.Status.Addresses = enforcedNodeAddresses
				return nil
			}
			return fmt.Errorf("failed to get node address from cloud provider that matches ip: %v", kl.nodeIP)
		}

		// Only add a NodeHostName address if the cloudprovider did not specify one
		// (we assume the cloudprovider knows best)
		var addressNodeHostName *v1.NodeAddress
		for i := range nodeAddresses {
			if nodeAddresses[i].Type == v1.NodeHostName {
				addressNodeHostName = &nodeAddresses[i]
				break
			}
		}
		if addressNodeHostName == nil {
			hostnameAddress := v1.NodeAddress{Type: v1.NodeHostName, Address: kl.GetHostname()}
			nodeAddresses = append(nodeAddresses, hostnameAddress)
		} else {
			glog.V(2).Infof("Using Node Hostname from cloudprovider: %q", addressNodeHostName.Address)
		}
		node.Status.Addresses = nodeAddresses
	} else {
		var ipAddr net.IP
		var err error

		// 1) Use nodeIP if set
		// 2) If the user has specified an IP to HostnameOverride, use it
		// 3) Lookup the IP from node name by DNS and use the first non-loopback ipv4 address
		// 4) Try to get the IP from the network interface used as default gateway
		if kl.nodeIP != nil {
			ipAddr = kl.nodeIP
			node.ObjectMeta.Annotations[kubeletapis.AnnotationProvidedIPAddr] = kl.nodeIP.String()
		} else if addr := net.ParseIP(kl.hostname); addr != nil {
			ipAddr = addr
		} else {
			var addrs []net.IP
			addrs, err = net.LookupIP(node.Name)
			for _, addr := range addrs {
				if !addr.IsLoopback() && addr.To4() != nil {
					ipAddr = addr
					break
				}
			}

			if ipAddr == nil {
				ipAddr, err = utilnet.ChooseHostInterface()
			}
		}

		if ipAddr == nil {
			// We tried everything we could, but the IP address wasn't fetchable; error out
			return fmt.Errorf("can't get ip address of node %s. error: %v", node.Name, err)
		}
		node.Status.Addresses = []v1.NodeAddress{
			{Type: v1.NodeInternalIP, Address: ipAddr.String()},
			{Type: v1.NodeHostName, Address: kl.GetHostname()},
		}
	}
	return nil
}

func (kl *Kubelet) setNodeStatusMachineInfo(node *v1.Node) {
	// Note: avoid blindly overwriting the capacity in case opaque
	//       resources are being advertised.
	if node.Status.Capacity == nil {
		node.Status.Capacity = v1.ResourceList{}
	}

	// populate GPU capacity.
	gpuCapacity := kl.gpuManager.Capacity()
	if gpuCapacity != nil {
		for k, v := range gpuCapacity {
			node.Status.Capacity[k] = v
		}
	}

	// TODO: Post NotReady if we cannot get MachineInfo from cAdvisor. This needs to start
	// cAdvisor locally, e.g. for test-cmd.sh, and in integration test.
	info, err := kl.GetCachedMachineInfo()
	if err != nil {
		// TODO(roberthbailey): This is required for test-cmd.sh to pass.
		// See if the test should be updated instead.
		node.Status.Capacity[v1.ResourceCPU] = *resource.NewMilliQuantity(0, resource.DecimalSI)
		node.Status.Capacity[v1.ResourceMemory] = resource.MustParse("0Gi")
		node.Status.Capacity[v1.ResourcePods] = *resource.NewQuantity(int64(kl.maxPods), resource.DecimalSI)
		glog.Errorf("Error getting machine info: %v", err)
	} else {
		node.Status.NodeInfo.MachineID = info.MachineID
		node.Status.NodeInfo.SystemUUID = info.SystemUUID

		for rName, rCap := range cadvisor.CapacityFromMachineInfo(info) {
			node.Status.Capacity[rName] = rCap
		}

		if kl.podsPerCore > 0 {
			node.Status.Capacity[v1.ResourcePods] = *resource.NewQuantity(
				int64(math.Min(float64(info.NumCores*kl.podsPerCore), float64(kl.maxPods))), resource.DecimalSI)
		} else {
			node.Status.Capacity[v1.ResourcePods] = *resource.NewQuantity(
				int64(kl.maxPods), resource.DecimalSI)
		}

		if node.Status.NodeInfo.BootID != "" &&
			node.Status.NodeInfo.BootID != info.BootID {
			// TODO: This requires a transaction, either both node status is updated
			// and event is recorded or neither should happen, see issue #6055.
			kl.recorder.Eventf(kl.nodeRef, v1.EventTypeWarning, events.NodeRebooted,
				"Node %s has been rebooted, boot id: %s", kl.nodeName, info.BootID)
		}
		node.Status.NodeInfo.BootID = info.BootID

		if utilfeature.DefaultFeatureGate.Enabled(features.LocalStorageCapacityIsolation) {
			// TODO: all the node resources should use GetCapacity instead of deriving the
			// capacity for every node status request
			initialCapacity := kl.containerManager.GetCapacity()
			if initialCapacity != nil {
				node.Status.Capacity[v1.ResourceEphemeralStorage] = initialCapacity[v1.ResourceEphemeralStorage]
			}
		}

		initialCapacity := kl.containerManager.GetCapacity()
		if initialCapacity != nil {
			for k, v := range initialCapacity {
				if v1helper.IsExtendedResourceName(k) {
					node.Status.Capacity[k] = v
				}
			}
		}
	}

	// Set Allocatable.
	if node.Status.Allocatable == nil {
		node.Status.Allocatable = make(v1.ResourceList)
	}
	// Remove extended resources from allocatable that are no longer
	// present in capacity.
	for k := range node.Status.Allocatable {
		_, found := node.Status.Capacity[k]
		if !found && v1helper.IsExtendedResourceName(k) {
			delete(node.Status.Allocatable, k)
		}
	}
	allocatableReservation := kl.containerManager.GetNodeAllocatableReservation()
	for k, v := range node.Status.Capacity {
		value := *(v.Copy())
		if res, exists := allocatableReservation[k]; exists {
			value.Sub(res)
		}
		if value.Sign() < 0 {
			// Negative Allocatable resources don't make sense.
			value.Set(0)
		}
		node.Status.Allocatable[k] = value
	}
	// for every huge page reservation, we need to remove it from allocatable memory
	for k, v := range node.Status.Capacity {
		if v1helper.IsHugePageResourceName(k) {
			allocatableMemory := node.Status.Allocatable[v1.ResourceMemory]
			value := *(v.Copy())
			allocatableMemory.Sub(value)
			if allocatableMemory.Sign() < 0 {
				// Negative Allocatable resources don't make sense.
				allocatableMemory.Set(0)
			}
			node.Status.Allocatable[v1.ResourceMemory] = allocatableMemory
		}
	}
}

// Set versioninfo for the node.
func (kl *Kubelet) setNodeStatusVersionInfo(node *v1.Node) {
	verinfo, err := kl.cadvisor.VersionInfo()
	if err != nil {
		glog.Errorf("Error getting version info: %v", err)
		return
	}

	node.Status.NodeInfo.KernelVersion = verinfo.KernelVersion
	node.Status.NodeInfo.OSImage = verinfo.ContainerOsVersion

	runtimeVersion := "Unknown"
	if runtimeVer, err := kl.containerRuntime.Version(); err == nil {
		runtimeVersion = runtimeVer.String()
	}
	node.Status.NodeInfo.ContainerRuntimeVersion = fmt.Sprintf("%s://%s", kl.containerRuntime.Type(), runtimeVersion)

	node.Status.NodeInfo.KubeletVersion = version.Get().String()
	// TODO: kube-proxy might be different version from kubelet in the future
	node.Status.NodeInfo.KubeProxyVersion = version.Get().String()
}

// Set daemonEndpoints for the node.
func (kl *Kubelet) setNodeStatusDaemonEndpoints(node *v1.Node) {
	node.Status.DaemonEndpoints = *kl.daemonEndpoints
}

// Set images list for the node
func (kl *Kubelet) setNodeStatusImages(node *v1.Node) {
	// Update image list of this node
	var imagesOnNode []v1.ContainerImage
	containerImages, err := kl.imageManager.GetImageList()
	if err != nil {
		glog.Errorf("Error getting image list: %v", err)
		node.Status.Images = imagesOnNode
		return
	}
	// sort the images from max to min, and only set top N images into the node status.
	sort.Sort(sliceutils.ByImageSize(containerImages))
	if maxImagesInNodeStatus < len(containerImages) {
		containerImages = containerImages[0:maxImagesInNodeStatus]
	}

	for _, image := range containerImages {
		names := append(image.RepoDigests, image.RepoTags...)
		// Report up to maxNamesPerImageInNodeStatus names per image.
		if len(names) > maxNamesPerImageInNodeStatus {
			names = names[0:maxNamesPerImageInNodeStatus]
		}
		imagesOnNode = append(imagesOnNode, v1.ContainerImage{
			Names:     names,
			SizeBytes: image.Size,
		})
	}

	node.Status.Images = imagesOnNode
}

// Set the GOOS and GOARCH for this node
func (kl *Kubelet) setNodeStatusGoRuntime(node *v1.Node) {
	node.Status.NodeInfo.OperatingSystem = goruntime.GOOS
	node.Status.NodeInfo.Architecture = goruntime.GOARCH
}

// Set status for the node.
func (kl *Kubelet) setNodeStatusInfo(node *v1.Node) {
	kl.setNodeStatusMachineInfo(node)
	kl.setNodeStatusVersionInfo(node)
	kl.setNodeStatusDaemonEndpoints(node)
	kl.setNodeStatusImages(node)
	kl.setNodeStatusGoRuntime(node)
}

// Set Ready condition for the node.
func (kl *Kubelet) setNodeReadyCondition(node *v1.Node) {
	// NOTE(aaronlevy): NodeReady condition needs to be the last in the list of node conditions.
	// This is due to an issue with version skewed kubelet and master components.
	// ref: https://github.com/kubernetes/kubernetes/issues/16961
	currentTime := metav1.NewTime(kl.clock.Now())
	var newNodeReadyCondition v1.NodeCondition
	rs := append(kl.runtimeState.runtimeErrors(), kl.runtimeState.networkErrors()...)
	if len(rs) == 0 {
		newNodeReadyCondition = v1.NodeCondition{
			Type:              v1.NodeReady,
			Status:            v1.ConditionTrue,
			Reason:            "KubeletReady",
			Message:           "kubelet is posting ready status",
			LastHeartbeatTime: currentTime,
		}
	} else {
		newNodeReadyCondition = v1.NodeCondition{
			Type:              v1.NodeReady,
			Status:            v1.ConditionFalse,
			Reason:            "KubeletNotReady",
			Message:           strings.Join(rs, ","),
			LastHeartbeatTime: currentTime,
		}
	}

	// Append AppArmor status if it's enabled.
	// TODO(tallclair): This is a temporary message until node feature reporting is added.
	if newNodeReadyCondition.Status == v1.ConditionTrue &&
		kl.appArmorValidator != nil && kl.appArmorValidator.ValidateHost() == nil {
		newNodeReadyCondition.Message = fmt.Sprintf("%s. AppArmor enabled", newNodeReadyCondition.Message)
	}

	// Record any soft requirements that were not met in the container manager.
	status := kl.containerManager.Status()
	if status.SoftRequirements != nil {
		newNodeReadyCondition.Message = fmt.Sprintf("%s. WARNING: %s", newNodeReadyCondition.Message, status.SoftRequirements.Error())
	}

	readyConditionUpdated := false
	needToRecordEvent := false
	for i := range node.Status.Conditions {
		if node.Status.Conditions[i].Type == v1.NodeReady {
			if node.Status.Conditions[i].Status == newNodeReadyCondition.Status {
				newNodeReadyCondition.LastTransitionTime = node.Status.Conditions[i].LastTransitionTime
			} else {
				newNodeReadyCondition.LastTransitionTime = currentTime
				needToRecordEvent = true
			}
			node.Status.Conditions[i] = newNodeReadyCondition
			readyConditionUpdated = true
			break
		}
	}
	if !readyConditionUpdated {
		newNodeReadyCondition.LastTransitionTime = currentTime
		node.Status.Conditions = append(node.Status.Conditions, newNodeReadyCondition)
	}
	if needToRecordEvent {
		if newNodeReadyCondition.Status == v1.ConditionTrue {
			kl.recordNodeStatusEvent(v1.EventTypeNormal, events.NodeReady)
		} else {
			kl.recordNodeStatusEvent(v1.EventTypeNormal, events.NodeNotReady)
			glog.Infof("Node became not ready: %+v", newNodeReadyCondition)
		}
	}
}

// setNodeMemoryPressureCondition for the node.
// TODO: this needs to move somewhere centralized...
func (kl *Kubelet) setNodeMemoryPressureCondition(node *v1.Node) {
	currentTime := metav1.NewTime(kl.clock.Now())
	var condition *v1.NodeCondition

	// Check if NodeMemoryPressure condition already exists and if it does, just pick it up for update.
	for i := range node.Status.Conditions {
		if node.Status.Conditions[i].Type == v1.NodeMemoryPressure {
			condition = &node.Status.Conditions[i]
		}
	}

	newCondition := false
	// If the NodeMemoryPressure condition doesn't exist, create one
	if condition == nil {
		condition = &v1.NodeCondition{
			Type:   v1.NodeMemoryPressure,
			Status: v1.ConditionUnknown,
		}
		// cannot be appended to node.Status.Conditions here because it gets
		// copied to the slice. So if we append to the slice here none of the
		// updates we make below are reflected in the slice.
		newCondition = true
	}

	// Update the heartbeat time
	condition.LastHeartbeatTime = currentTime

	// Note: The conditions below take care of the case when a new NodeMemoryPressure condition is
	// created and as well as the case when the condition already exists. When a new condition
	// is created its status is set to v1.ConditionUnknown which matches either
	// condition.Status != v1.ConditionTrue or
	// condition.Status != v1.ConditionFalse in the conditions below depending on whether
	// the kubelet is under memory pressure or not.
	if kl.evictionManager.IsUnderMemoryPressure() {
		if condition.Status != v1.ConditionTrue {
			condition.Status = v1.ConditionTrue
			condition.Reason = "KubeletHasInsufficientMemory"
			condition.Message = "kubelet has insufficient memory available"
			condition.LastTransitionTime = currentTime
			kl.recordNodeStatusEvent(v1.EventTypeNormal, "NodeHasInsufficientMemory")
		}
	} else if condition.Status != v1.ConditionFalse {
		condition.Status = v1.ConditionFalse
		condition.Reason = "KubeletHasSufficientMemory"
		condition.Message = "kubelet has sufficient memory available"
		condition.LastTransitionTime = currentTime
		kl.recordNodeStatusEvent(v1.EventTypeNormal, "NodeHasSufficientMemory")
	}

	if newCondition {
		node.Status.Conditions = append(node.Status.Conditions, *condition)
	}
}

// setNodeDiskPressureCondition for the node.
// TODO: this needs to move somewhere centralized...
func (kl *Kubelet) setNodeDiskPressureCondition(node *v1.Node) {
	currentTime := metav1.NewTime(kl.clock.Now())
	var condition *v1.NodeCondition

	// Check if NodeDiskPressure condition already exists and if it does, just pick it up for update.
	for i := range node.Status.Conditions {
		if node.Status.Conditions[i].Type == v1.NodeDiskPressure {
			condition = &node.Status.Conditions[i]
		}
	}

	newCondition := false
	// If the NodeDiskPressure condition doesn't exist, create one
	if condition == nil {
		condition = &v1.NodeCondition{
			Type:   v1.NodeDiskPressure,
			Status: v1.ConditionUnknown,
		}
		// cannot be appended to node.Status.Conditions here because it gets
		// copied to the slice. So if we append to the slice here none of the
		// updates we make below are reflected in the slice.
		newCondition = true
	}

	// Update the heartbeat time
	condition.LastHeartbeatTime = currentTime

	// Note: The conditions below take care of the case when a new NodeDiskPressure condition is
	// created and as well as the case when the condition already exists. When a new condition
	// is created its status is set to v1.ConditionUnknown which matches either
	// condition.Status != v1.ConditionTrue or
	// condition.Status != v1.ConditionFalse in the conditions below depending on whether
	// the kubelet is under disk pressure or not.
	if kl.evictionManager.IsUnderDiskPressure() {
		if condition.Status != v1.ConditionTrue {
			condition.Status = v1.ConditionTrue
			condition.Reason = "KubeletHasDiskPressure"
			condition.Message = "kubelet has disk pressure"
			condition.LastTransitionTime = currentTime
			kl.recordNodeStatusEvent(v1.EventTypeNormal, "NodeHasDiskPressure")
		}
	} else if condition.Status != v1.ConditionFalse {
		condition.Status = v1.ConditionFalse
		condition.Reason = "KubeletHasNoDiskPressure"
		condition.Message = "kubelet has no disk pressure"
		condition.LastTransitionTime = currentTime
		kl.recordNodeStatusEvent(v1.EventTypeNormal, "NodeHasNoDiskPressure")
	}

	if newCondition {
		node.Status.Conditions = append(node.Status.Conditions, *condition)
	}
}

// Set OODCondition for the node.
func (kl *Kubelet) setNodeOODCondition(node *v1.Node) {
	currentTime := metav1.NewTime(kl.clock.Now())
	var nodeOODCondition *v1.NodeCondition

	// Check if NodeOutOfDisk condition already exists and if it does, just pick it up for update.
	for i := range node.Status.Conditions {
		if node.Status.Conditions[i].Type == v1.NodeOutOfDisk {
			nodeOODCondition = &node.Status.Conditions[i]
		}
	}

	newOODCondition := nodeOODCondition == nil
	if newOODCondition {
		nodeOODCondition = &v1.NodeCondition{}
	}
	if nodeOODCondition.Status != v1.ConditionFalse {
		nodeOODCondition.Type = v1.NodeOutOfDisk
		nodeOODCondition.Status = v1.ConditionFalse
		nodeOODCondition.Reason = "KubeletHasSufficientDisk"
		nodeOODCondition.Message = "kubelet has sufficient disk space available"
		nodeOODCondition.LastTransitionTime = currentTime
		kl.recordNodeStatusEvent(v1.EventTypeNormal, "NodeHasSufficientDisk")
	}

	// Update the heartbeat time irrespective of all the conditions.
	nodeOODCondition.LastHeartbeatTime = currentTime

	if newOODCondition {
		node.Status.Conditions = append(node.Status.Conditions, *nodeOODCondition)
	}
}

// Maintains Node.Spec.Unschedulable value from previous run of tryUpdateNodeStatus()
// TODO: why is this a package var?
var oldNodeUnschedulable bool

// record if node schedulable change.
func (kl *Kubelet) recordNodeSchedulableEvent(node *v1.Node) {
	if oldNodeUnschedulable != node.Spec.Unschedulable {
		if node.Spec.Unschedulable {
			kl.recordNodeStatusEvent(v1.EventTypeNormal, events.NodeNotSchedulable)
		} else {
			kl.recordNodeStatusEvent(v1.EventTypeNormal, events.NodeSchedulable)
		}
		oldNodeUnschedulable = node.Spec.Unschedulable
	}
}

// Update VolumesInUse field in Node Status only after states are synced up at least once
// in volume reconciler.
func (kl *Kubelet) setNodeVolumesInUseStatus(node *v1.Node) {
	// Make sure to only update node status after reconciler starts syncing up states
	if kl.volumeManager.ReconcilerStatesHasBeenSynced() {
		node.Status.VolumesInUse = kl.volumeManager.GetVolumesInUse()
	}
}

// setNodeStatus fills in the Status fields of the given Node, overwriting
// any fields that are currently set.
// TODO(madhusudancs): Simplify the logic for setting node conditions and
// refactor the node status condition code out to a different file.
func (kl *Kubelet) setNodeStatus(node *v1.Node) {
	for _, f := range kl.setNodeStatusFuncs {
		if err := f(node); err != nil {
			glog.Warningf("Failed to set some node status fields: %s", err)
		}
	}
}

// defaultNodeStatusFuncs is a factory that generates the default set of
// setNodeStatus funcs
func (kl *Kubelet) defaultNodeStatusFuncs() []func(*v1.Node) error {
	// initial set of node status update handlers, can be modified by Option's
	withoutError := func(f func(*v1.Node)) func(*v1.Node) error {
		return func(n *v1.Node) error {
			f(n)
			return nil
		}
	}
	return []func(*v1.Node) error{
		kl.setNodeAddress,
		withoutError(kl.setNodeStatusInfo),
		withoutError(kl.setNodeOODCondition),
		withoutError(kl.setNodeMemoryPressureCondition),
		withoutError(kl.setNodeDiskPressureCondition),
		withoutError(kl.setNodeReadyCondition),
		withoutError(kl.setNodeVolumesInUseStatus),
		withoutError(kl.recordNodeSchedulableEvent),
	}
}

// Validate given node IP belongs to the current host
func (kl *Kubelet) validateNodeIP() error {
	if kl.nodeIP == nil {
		return nil
	}

	// Honor IP limitations set in setNodeStatus()
	if kl.nodeIP.IsLoopback() {
		return fmt.Errorf("nodeIP can't be loopback address")
	}
	if kl.nodeIP.To4() == nil {
		return fmt.Errorf("nodeIP must be IPv4 address")
	}

	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return err
	}
	for _, addr := range addrs {
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip != nil && ip.Equal(kl.nodeIP) {
			return nil
		}
	}
	return fmt.Errorf("Node IP: %q not found in the host's network interfaces", kl.nodeIP.String())
}
