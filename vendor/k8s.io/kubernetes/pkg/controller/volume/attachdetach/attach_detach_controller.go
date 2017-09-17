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

// Package volume implements a controller to manage volume attach and detach
// operations.
package attachdetach

import (
	"fmt"
	"net"
	"time"

	"github.com/golang/glog"
	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/runtime"
	coreinformers "k8s.io/client-go/informers/core/v1"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	v1core "k8s.io/client-go/kubernetes/typed/core/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
	kcache "k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/kubernetes/pkg/cloudprovider"
	"k8s.io/kubernetes/pkg/controller"
	"k8s.io/kubernetes/pkg/controller/volume/attachdetach/cache"
	"k8s.io/kubernetes/pkg/controller/volume/attachdetach/populator"
	"k8s.io/kubernetes/pkg/controller/volume/attachdetach/reconciler"
	"k8s.io/kubernetes/pkg/controller/volume/attachdetach/statusupdater"
	"k8s.io/kubernetes/pkg/controller/volume/attachdetach/util"
	"k8s.io/kubernetes/pkg/util/io"
	"k8s.io/kubernetes/pkg/util/mount"
	"k8s.io/kubernetes/pkg/volume"
	"k8s.io/kubernetes/pkg/volume/util/operationexecutor"
	"k8s.io/kubernetes/pkg/volume/util/volumehelper"
)

// TimerConfig contains configuration of internal attach/detach timers and
// should be used only to speed up tests. DefaultTimerConfig is the suggested
// timer configuration for production.
type TimerConfig struct {
	// ReconcilerLoopPeriod is the amount of time the reconciler loop waits
	// between successive executions
	ReconcilerLoopPeriod time.Duration

	// ReconcilerMaxWaitForUnmountDuration is the maximum amount of time the
	// attach detach controller will wait for a volume to be safely unmounted
	// from its node. Once this time has expired, the controller will assume the
	// node or kubelet are unresponsive and will detach the volume anyway.
	ReconcilerMaxWaitForUnmountDuration time.Duration

	// DesiredStateOfWorldPopulatorLoopSleepPeriod is the amount of time the
	// DesiredStateOfWorldPopulator loop waits between successive executions
	DesiredStateOfWorldPopulatorLoopSleepPeriod time.Duration

	// DesiredStateOfWorldPopulatorListPodsRetryDuration is the amount of
	// time the DesiredStateOfWorldPopulator loop waits between list pods
	// calls.
	DesiredStateOfWorldPopulatorListPodsRetryDuration time.Duration
}

// DefaultTimerConfig is the default configuration of Attach/Detach controller
// timers.
var DefaultTimerConfig TimerConfig = TimerConfig{
	ReconcilerLoopPeriod:                              100 * time.Millisecond,
	ReconcilerMaxWaitForUnmountDuration:               6 * time.Minute,
	DesiredStateOfWorldPopulatorLoopSleepPeriod:       1 * time.Minute,
	DesiredStateOfWorldPopulatorListPodsRetryDuration: 3 * time.Minute,
}

// AttachDetachController defines the operations supported by this controller.
type AttachDetachController interface {
	Run(stopCh <-chan struct{})
	GetDesiredStateOfWorld() cache.DesiredStateOfWorld
}

// NewAttachDetachController returns a new instance of AttachDetachController.
func NewAttachDetachController(
	kubeClient clientset.Interface,
	podInformer coreinformers.PodInformer,
	nodeInformer coreinformers.NodeInformer,
	pvcInformer coreinformers.PersistentVolumeClaimInformer,
	pvInformer coreinformers.PersistentVolumeInformer,
	cloud cloudprovider.Interface,
	plugins []volume.VolumePlugin,
	prober volume.DynamicPluginProber,
	disableReconciliationSync bool,
	reconcilerSyncDuration time.Duration,
	timerConfig TimerConfig) (AttachDetachController, error) {
	// TODO: The default resyncPeriod for shared informers is 12 hours, this is
	// unacceptable for the attach/detach controller. For example, if a pod is
	// skipped because the node it is scheduled to didn't set its annotation in
	// time, we don't want to have to wait 12hrs before processing the pod
	// again.
	// Luckily https://github.com/kubernetes/kubernetes/issues/23394 is being
	// worked on and will split resync in to resync and relist. Once that
	// happens the resync period can be set to something much faster (30
	// seconds).
	// If that issue is not resolved in time, then this controller will have to
	// consider some unappealing alternate options: use a non-shared informer
	// and set a faster resync period even if it causes relist, or requeue
	// dropped pods so they are continuously processed until it is accepted or
	// deleted (probably can't do this with sharedInformer), etc.
	adc := &attachDetachController{
		kubeClient:  kubeClient,
		pvcLister:   pvcInformer.Lister(),
		pvcsSynced:  pvcInformer.Informer().HasSynced,
		pvLister:    pvInformer.Lister(),
		pvsSynced:   pvInformer.Informer().HasSynced,
		podLister:   podInformer.Lister(),
		podsSynced:  podInformer.Informer().HasSynced,
		nodeLister:  nodeInformer.Lister(),
		nodesSynced: nodeInformer.Informer().HasSynced,
		cloud:       cloud,
	}

	if err := adc.volumePluginMgr.InitPlugins(plugins, prober, adc); err != nil {
		return nil, fmt.Errorf("Could not initialize volume plugins for Attach/Detach Controller: %+v", err)
	}

	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartLogging(glog.Infof)
	eventBroadcaster.StartRecordingToSink(&v1core.EventSinkImpl{Interface: v1core.New(kubeClient.Core().RESTClient()).Events("")})
	recorder := eventBroadcaster.NewRecorder(scheme.Scheme, v1.EventSource{Component: "attachdetach"})

	adc.desiredStateOfWorld = cache.NewDesiredStateOfWorld(&adc.volumePluginMgr)
	adc.actualStateOfWorld = cache.NewActualStateOfWorld(&adc.volumePluginMgr)
	adc.attacherDetacher =
		operationexecutor.NewOperationExecutor(operationexecutor.NewOperationGenerator(
			kubeClient,
			&adc.volumePluginMgr,
			recorder,
			false)) // flag for experimental binary check for volume mount
	adc.nodeStatusUpdater = statusupdater.NewNodeStatusUpdater(
		kubeClient, nodeInformer.Lister(), adc.actualStateOfWorld)

	// Default these to values in options
	adc.reconciler = reconciler.NewReconciler(
		timerConfig.ReconcilerLoopPeriod,
		timerConfig.ReconcilerMaxWaitForUnmountDuration,
		reconcilerSyncDuration,
		disableReconciliationSync,
		adc.desiredStateOfWorld,
		adc.actualStateOfWorld,
		adc.attacherDetacher,
		adc.nodeStatusUpdater,
		recorder)

	adc.desiredStateOfWorldPopulator = populator.NewDesiredStateOfWorldPopulator(
		timerConfig.DesiredStateOfWorldPopulatorLoopSleepPeriod,
		timerConfig.DesiredStateOfWorldPopulatorListPodsRetryDuration,
		podInformer.Lister(),
		adc.desiredStateOfWorld,
		&adc.volumePluginMgr,
		pvcInformer.Lister(),
		pvInformer.Lister())

	podInformer.Informer().AddEventHandler(kcache.ResourceEventHandlerFuncs{
		AddFunc:    adc.podAdd,
		UpdateFunc: adc.podUpdate,
		DeleteFunc: adc.podDelete,
	})

	nodeInformer.Informer().AddEventHandler(kcache.ResourceEventHandlerFuncs{
		AddFunc:    adc.nodeAdd,
		UpdateFunc: adc.nodeUpdate,
		DeleteFunc: adc.nodeDelete,
	})

	return adc, nil
}

type attachDetachController struct {
	// kubeClient is the kube API client used by volumehost to communicate with
	// the API server.
	kubeClient clientset.Interface

	// pvcLister is the shared PVC lister used to fetch and store PVC
	// objects from the API server. It is shared with other controllers and
	// therefore the PVC objects in its store should be treated as immutable.
	pvcLister  corelisters.PersistentVolumeClaimLister
	pvcsSynced kcache.InformerSynced

	// pvLister is the shared PV lister used to fetch and store PV objects
	// from the API server. It is shared with other controllers and therefore
	// the PV objects in its store should be treated as immutable.
	pvLister  corelisters.PersistentVolumeLister
	pvsSynced kcache.InformerSynced

	podLister  corelisters.PodLister
	podsSynced kcache.InformerSynced

	nodeLister  corelisters.NodeLister
	nodesSynced kcache.InformerSynced

	// cloud provider used by volume host
	cloud cloudprovider.Interface

	// volumePluginMgr used to initialize and fetch volume plugins
	volumePluginMgr volume.VolumePluginMgr

	// desiredStateOfWorld is a data structure containing the desired state of
	// the world according to this controller: i.e. what nodes the controller
	// is managing, what volumes it wants be attached to these nodes, and which
	// pods are scheduled to those nodes referencing the volumes.
	// The data structure is populated by the controller using a stream of node
	// and pod API server objects fetched by the informers.
	desiredStateOfWorld cache.DesiredStateOfWorld

	// actualStateOfWorld is a data structure containing the actual state of
	// the world according to this controller: i.e. which volumes are attached
	// to which nodes.
	// The data structure is populated upon successful completion of attach and
	// detach actions triggered by the controller and a periodic sync with
	// storage providers for the "true" state of the world.
	actualStateOfWorld cache.ActualStateOfWorld

	// attacherDetacher is used to start asynchronous attach and operations
	attacherDetacher operationexecutor.OperationExecutor

	// reconciler is used to run an asynchronous periodic loop to reconcile the
	// desiredStateOfWorld with the actualStateOfWorld by triggering attach
	// detach operations using the attacherDetacher.
	reconciler reconciler.Reconciler

	// nodeStatusUpdater is used to update node status with the list of attached
	// volumes
	nodeStatusUpdater statusupdater.NodeStatusUpdater

	// desiredStateOfWorldPopulator runs an asynchronous periodic loop to
	// populate the current pods using podInformer.
	desiredStateOfWorldPopulator populator.DesiredStateOfWorldPopulator

	// recorder is used to record events in the API server
	recorder record.EventRecorder
}

func (adc *attachDetachController) Run(stopCh <-chan struct{}) {
	defer runtime.HandleCrash()

	glog.Infof("Starting attach detach controller")
	defer glog.Infof("Shutting down attach detach controller")

	if !controller.WaitForCacheSync("attach detach", stopCh, adc.podsSynced, adc.nodesSynced, adc.pvcsSynced, adc.pvsSynced) {
		return
	}

	err := adc.populateActualStateOfWorld()
	if err != nil {
		glog.Errorf("Error populating the actual state of world: %v", err)
	}
	err = adc.populateDesiredStateOfWorld()
	if err != nil {
		glog.Errorf("Error populating the desired state of world: %v", err)
	}
	go adc.reconciler.Run(stopCh)
	go adc.desiredStateOfWorldPopulator.Run(stopCh)

	<-stopCh
}

func (adc *attachDetachController) populateActualStateOfWorld() error {
	glog.V(5).Infof("Populating ActualStateOfworld")
	nodes, err := adc.nodeLister.List(labels.Everything())
	if err != nil {
		return err
	}

	for _, node := range nodes {
		nodeName := types.NodeName(node.Name)
		for _, attachedVolume := range node.Status.VolumesAttached {
			uniqueName := attachedVolume.Name
			// The nil VolumeSpec is safe only in the case the volume is not in use by any pod.
			// In such a case it should be detached in the first reconciliation cycle and the
			// volume spec is not needed to detach a volume. If the volume is used by a pod, it
			// its spec can be: this would happen during in the populateDesiredStateOfWorld which
			// scans the pods and updates their volumes in the ActualStateOfWorld too.
			err = adc.actualStateOfWorld.MarkVolumeAsAttached(uniqueName, nil /* VolumeSpec */, nodeName, attachedVolume.DevicePath)
			if err != nil {
				glog.Errorf("Failed to mark the volume as attached: %v", err)
				continue
			}
			adc.processVolumesInUse(nodeName, node.Status.VolumesInUse, true /* forceUnmount */)
			adc.addNodeToDswp(node, types.NodeName(node.Name))
		}
	}
	return nil
}

func (adc *attachDetachController) getNodeVolumeDevicePath(
	volumeName v1.UniqueVolumeName, nodeName types.NodeName) (string, error) {
	var devicePath string
	var found bool
	node, err := adc.nodeLister.Get(string(nodeName))
	if err != nil {
		return devicePath, err
	}
	for _, attachedVolume := range node.Status.VolumesAttached {
		if volumeName == attachedVolume.Name {
			devicePath = attachedVolume.DevicePath
			found = true
			break
		}
	}
	if !found {
		err = fmt.Errorf("Volume %s not found on node %s", volumeName, nodeName)
	}

	return devicePath, err
}

func (adc *attachDetachController) populateDesiredStateOfWorld() error {
	glog.V(5).Infof("Populating DesiredStateOfworld")

	pods, err := adc.podLister.List(labels.Everything())
	if err != nil {
		return err
	}
	for _, pod := range pods {
		podToAdd := pod
		adc.podAdd(&podToAdd)
		for _, podVolume := range podToAdd.Spec.Volumes {
			// The volume specs present in the ActualStateOfWorld are nil, let's replace those
			// with the correct ones found on pods. The present in the ASW with no corresponding
			// pod will be detached and the spec is irrelevant.
			volumeSpec, err := util.CreateVolumeSpec(podVolume, podToAdd.Namespace, adc.pvcLister, adc.pvLister)
			if err != nil {
				glog.Errorf(
					"Error creating spec for volume %q, pod %q/%q: %v",
					podVolume.Name,
					podToAdd.Namespace,
					podToAdd.Name,
					err)
				continue
			}
			nodeName := types.NodeName(podToAdd.Spec.NodeName)
			plugin, err := adc.volumePluginMgr.FindAttachablePluginBySpec(volumeSpec)
			if err != nil || plugin == nil {
				glog.V(10).Infof(
					"Skipping volume %q for pod %q/%q: it does not implement attacher interface. err=%v",
					podVolume.Name,
					podToAdd.Namespace,
					podToAdd.Name,
					err)
				continue
			}
			volumeName, err := volumehelper.GetUniqueVolumeNameFromSpec(plugin, volumeSpec)
			if err != nil {
				glog.Errorf(
					"Failed to find unique name for volume %q, pod %q/%q: %v",
					podVolume.Name,
					podToAdd.Namespace,
					podToAdd.Name,
					err)
				continue
			}
			if adc.actualStateOfWorld.VolumeNodeExists(volumeName, nodeName) {
				devicePath, err := adc.getNodeVolumeDevicePath(volumeName, nodeName)
				if err != nil {
					glog.Errorf("Failed to find device path: %v", err)
					continue
				}
				err = adc.actualStateOfWorld.MarkVolumeAsAttached(volumeName, volumeSpec, nodeName, devicePath)
				if err != nil {
					glog.Errorf("Failed to update volume spec for node %s: %v", nodeName, err)
				}
			}
		}
	}

	return nil
}

func (adc *attachDetachController) podAdd(obj interface{}) {
	pod, ok := obj.(*v1.Pod)
	if pod == nil || !ok {
		return
	}
	if pod.Spec.NodeName == "" {
		// Ignore pods without NodeName, indicating they are not scheduled.
		return
	}

	volumeActionFlag := util.DetermineVolumeAction(
		pod,
		adc.desiredStateOfWorld,
		true /* default volume action */)

	util.ProcessPodVolumes(pod, volumeActionFlag, /* addVolumes */
		adc.desiredStateOfWorld, &adc.volumePluginMgr, adc.pvcLister, adc.pvLister)
}

// GetDesiredStateOfWorld returns desired state of world associated with controller
func (adc *attachDetachController) GetDesiredStateOfWorld() cache.DesiredStateOfWorld {
	return adc.desiredStateOfWorld
}

func (adc *attachDetachController) podUpdate(oldObj, newObj interface{}) {
	pod, ok := newObj.(*v1.Pod)
	if pod == nil || !ok {
		return
	}
	if pod.Spec.NodeName == "" {
		// Ignore pods without NodeName, indicating they are not scheduled.
		return
	}

	volumeActionFlag := util.DetermineVolumeAction(
		pod,
		adc.desiredStateOfWorld,
		true /* default volume action */)

	util.ProcessPodVolumes(pod, volumeActionFlag, /* addVolumes */
		adc.desiredStateOfWorld, &adc.volumePluginMgr, adc.pvcLister, adc.pvLister)
}

func (adc *attachDetachController) podDelete(obj interface{}) {
	pod, ok := obj.(*v1.Pod)
	if pod == nil || !ok {
		return
	}

	util.ProcessPodVolumes(pod, false, /* addVolumes */
		adc.desiredStateOfWorld, &adc.volumePluginMgr, adc.pvcLister, adc.pvLister)
}

func (adc *attachDetachController) nodeAdd(obj interface{}) {
	node, ok := obj.(*v1.Node)
	// TODO: investigate if nodeName is empty then if we can return
	// kubernetes/kubernetes/issues/37777
	if node == nil || !ok {
		return
	}
	nodeName := types.NodeName(node.Name)
	adc.nodeUpdate(nil, obj)
	// kubernetes/kubernetes/issues/37586
	// This is to workaround the case when a node add causes to wipe out
	// the attached volumes field. This function ensures that we sync with
	// the actual status.
	adc.actualStateOfWorld.SetNodeStatusUpdateNeeded(nodeName)
}

func (adc *attachDetachController) nodeUpdate(oldObj, newObj interface{}) {
	node, ok := newObj.(*v1.Node)
	// TODO: investigate if nodeName is empty then if we can return
	if node == nil || !ok {
		return
	}

	nodeName := types.NodeName(node.Name)
	adc.addNodeToDswp(node, nodeName)
	adc.processVolumesInUse(nodeName, node.Status.VolumesInUse, false /* forceUnmount */)
}

func (adc *attachDetachController) nodeDelete(obj interface{}) {
	node, ok := obj.(*v1.Node)
	if node == nil || !ok {
		return
	}

	nodeName := types.NodeName(node.Name)
	if err := adc.desiredStateOfWorld.DeleteNode(nodeName); err != nil {
		// This might happen during drain, but we still want it to appear in our logs
		glog.Infof("error removing node %q from desired-state-of-world: %v", nodeName, err)
	}

	adc.processVolumesInUse(nodeName, node.Status.VolumesInUse, false /* forceUnmount */)
}

// processVolumesInUse processes the list of volumes marked as "in-use"
// according to the specified Node's Status.VolumesInUse and updates the
// corresponding volume in the actual state of the world to indicate that it is
// mounted.
func (adc *attachDetachController) processVolumesInUse(
	nodeName types.NodeName, volumesInUse []v1.UniqueVolumeName, forceUnmount bool) {
	glog.V(4).Infof("processVolumesInUse for node %q", nodeName)
	for _, attachedVolume := range adc.actualStateOfWorld.GetAttachedVolumesForNode(nodeName) {
		mounted := false
		for _, volumeInUse := range volumesInUse {
			if attachedVolume.VolumeName == volumeInUse {
				mounted = true
				break
			}
		}
		err := adc.actualStateOfWorld.SetVolumeMountedByNode(
			attachedVolume.VolumeName, nodeName, mounted, forceUnmount)
		if err != nil {
			glog.Warningf(
				"SetVolumeMountedByNode(%q, %q, %q) returned an error: %v",
				attachedVolume.VolumeName, nodeName, mounted, err)
		}
	}
}

// VolumeHost implementation
// This is an unfortunate requirement of the current factoring of volume plugin
// initializing code. It requires kubelet specific methods used by the mounting
// code to be implemented by all initializers even if the initializer does not
// do mounting (like this attach/detach controller).
// Issue kubernetes/kubernetes/issues/14217 to fix this.
func (adc *attachDetachController) GetPluginDir(podUID string) string {
	return ""
}

func (adc *attachDetachController) GetPodVolumeDir(podUID types.UID, pluginName, volumeName string) string {
	return ""
}

func (adc *attachDetachController) GetPodPluginDir(podUID types.UID, pluginName string) string {
	return ""
}

func (adc *attachDetachController) GetKubeClient() clientset.Interface {
	return adc.kubeClient
}

func (adc *attachDetachController) NewWrapperMounter(volName string, spec volume.Spec, pod *v1.Pod, opts volume.VolumeOptions) (volume.Mounter, error) {
	return nil, fmt.Errorf("NewWrapperMounter not supported by Attach/Detach controller's VolumeHost implementation")
}

func (adc *attachDetachController) NewWrapperUnmounter(volName string, spec volume.Spec, podUID types.UID) (volume.Unmounter, error) {
	return nil, fmt.Errorf("NewWrapperUnmounter not supported by Attach/Detach controller's VolumeHost implementation")
}

func (adc *attachDetachController) GetCloudProvider() cloudprovider.Interface {
	return adc.cloud
}

func (adc *attachDetachController) GetMounter(pluginName string) mount.Interface {
	return nil
}

func (adc *attachDetachController) GetWriter() io.Writer {
	return nil
}

func (adc *attachDetachController) GetHostName() string {
	return ""
}

func (adc *attachDetachController) GetHostIP() (net.IP, error) {
	return nil, fmt.Errorf("GetHostIP() not supported by Attach/Detach controller's VolumeHost implementation")
}

func (adc *attachDetachController) GetNodeAllocatable() (v1.ResourceList, error) {
	return v1.ResourceList{}, nil
}

func (adc *attachDetachController) GetSecretFunc() func(namespace, name string) (*v1.Secret, error) {
	return func(_, _ string) (*v1.Secret, error) {
		return nil, fmt.Errorf("GetSecret unsupported in attachDetachController")
	}
}

func (adc *attachDetachController) GetConfigMapFunc() func(namespace, name string) (*v1.ConfigMap, error) {
	return func(_, _ string) (*v1.ConfigMap, error) {
		return nil, fmt.Errorf("GetConfigMap unsupported in attachDetachController")
	}
}

func (adc *attachDetachController) GetExec(pluginName string) mount.Exec {
	return mount.NewOsExec()
}

func (adc *attachDetachController) addNodeToDswp(node *v1.Node, nodeName types.NodeName) {
	if _, exists := node.Annotations[volumehelper.ControllerManagedAttachAnnotation]; exists {
		keepTerminatedPodVolumes := false

		if t, ok := node.Annotations[volumehelper.KeepTerminatedPodVolumesAnnotation]; ok {
			keepTerminatedPodVolumes = (t == "true")
		}

		// Node specifies annotation indicating it should be managed by attach
		// detach controller. Add it to desired state of world.
		adc.desiredStateOfWorld.AddNode(nodeName, keepTerminatedPodVolumes)
	}
}

func (adc *attachDetachController) GetNodeLabels() (map[string]string, error) {
	return nil, fmt.Errorf("GetNodeLabels() unsupported in Attach/Detach controller")
}
