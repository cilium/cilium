// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sTypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/k8s"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/informer"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	k8sUtils "github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/logging/logfields"
	pkgOption "github.com/cilium/cilium/pkg/option"
)

const (
	hostnameIndexer = "hostname-indexer"

	// ciliumNodeConditionReason is the condition name used by Cilium to set
	// when the Network is setup in the node.
	ciliumNodeConditionReason = "CiliumIsUp"
)

var (
	// ciliumPodsStore contains all Cilium pods running in the cluster
	ciliumPodsStore = cache.NewIndexer(cache.DeletionHandlingMetaNamespaceKeyFunc, ciliumIndexers)

	// ciliumIndexers will index Cilium pods by namespace/name and hostname.
	ciliumIndexers = cache.Indexers{
		cache.NamespaceIndex: cache.MetaNamespaceIndexFunc,
		hostnameIndexer:      hostNameIndexFunc,
	}

	errNoPod = errors.New("object is not a *slim_corev1.Pod")

	queueKeyFunc = cache.DeletionHandlingMetaNamespaceKeyFunc

	ctrlMgr = controller.NewManager()

	mno markNodeOptions
)

func checkTaintForNextNodeItem(c kubernetes.Interface, nodeGetter slimNodeGetter, workQueue workqueue.RateLimitingInterface) bool {
	// Get the next 'key' from the queue.
	key, quit := workQueue.Get()
	if quit {
		return false
	}
	// Done marks item as done processing, and if it has been marked as dirty
	// again while it was being processed, it will be re-added to the queue for
	// re-processing.
	defer workQueue.Done(key)

	success := checkAndMarkNode(c, nodeGetter, key.(string), mno)
	if !success {
		workQueue.Forget(key)
		return true
	}

	// If the event was processed correctly then forget it from the queue.
	// If we don't do this, the next ".Get()" will always return this 'key'.
	// It also depends on if the queue has a rate-limiter (not used in this
	// program)
	workQueue.Forget(key)
	return true
}

// checkAndMarkNode checks if the node contains a Cilium pod in running state
// so that it can set the taints / conditions of the node
func checkAndMarkNode(c kubernetes.Interface, nodeGetter slimNodeGetter, nodeName string, options markNodeOptions) bool {
	node, err := nodeGetter.GetK8sSlimNode(nodeName)
	if node == nil || err != nil {
		return false
	}

	// should we remove the taint?
	scheduled, running := nodeHasCiliumPod(node.GetName())
	if running {
		if (options.RemoveNodeTaint && hasAgentNotReadyTaint(node)) ||
			(options.SetCiliumIsUpCondition && !HasCiliumIsUpCondition(node)) {
			log.WithFields(logrus.Fields{
				logfields.NodeName: node.GetName(),
			}).Info("Cilium pod running for node; marking accordingly")

			markNode(c, nodeGetter, node.GetName(), options, true)
		}
	} else if scheduled { // Taint nodes where the pod is scheduled but not running
		if options.SetNodeTaint && !hasAgentNotReadyTaint(node) {
			log.WithFields(logrus.Fields{
				logfields.NodeName: node.GetName(),
			}).Info("Cilium pod scheduled but not running for node; setting taint")
			markNode(c, nodeGetter, node.GetName(), options, false)
		}
	}
	return true
}

// ciliumPodsWatcher starts up a pod watcher to handle pod events.
func ciliumPodsWatcher(wg *sync.WaitGroup, clientset k8sClient.Clientset, stopCh <-chan struct{}) {
	ciliumQueue := workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "cilium-pod-queue")

	ciliumPodInformer := informer.NewInformerWithStore(
		k8sUtils.ListerWatcherWithModifier(
			k8sUtils.ListerWatcherFromTyped[*slim_corev1.PodList](
				clientset.Slim().CoreV1().Pods(option.Config.CiliumK8sNamespace),
			),
			func(options *metav1.ListOptions) {
				options.LabelSelector = option.Config.CiliumPodLabels
			}),
		&slim_corev1.Pod{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				key, _ := queueKeyFunc(obj)
				ciliumQueue.Add(key)
			},
			UpdateFunc: func(_, newObj interface{}) {
				key, _ := queueKeyFunc(newObj)
				ciliumQueue.Add(key)
			},
		},
		convertToCiliumPod,
		ciliumPodsStore,
	)

	nodeGetter := &nodeGetter{}

	wg.Add(1)
	go func() {
		defer wg.Done()
		// Do not use the k8sClient provided by the nodesInit function since we
		// need a k8s client that can update node structures and not simply
		// watch for node events.
		for processNextCiliumPodItem(clientset, nodeGetter, ciliumQueue) {
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer ciliumQueue.ShutDown()

		ciliumPodInformer.Run(stopCh)
	}()
}

func processNextCiliumPodItem(c kubernetes.Interface, nodeGetter slimNodeGetter, workQueue workqueue.RateLimitingInterface) bool {
	// Get the next 'key' from the queue.
	key, quit := workQueue.Get()
	if quit {
		return false
	}
	// Done marks item as done processing, and if it has been marked as dirty
	// again while it was being processed, it will be re-added to the queue for
	// re-processing.
	defer workQueue.Done(key)

	podInterface, exists, err := ciliumPodsStore.GetByKey(key.(string))
	if err != nil && !k8sErrors.IsNotFound(err) {
		return true
	}
	if !exists || podInterface == nil {
		workQueue.Forget(key)
		return true
	}

	pod := podInterface.(*slim_corev1.Pod)
	nodeName := pod.Spec.NodeName

	success := checkAndMarkNode(c, nodeGetter, nodeName, mno)
	if !success {
		workQueue.Forget(key)
		return true
	}

	// If the event was processed correctly then forget it from the queue.
	// If we don't do this, the next ".Get()" will always return this 'key'.
	// It also depends on if the queue has a rate-limiter (not used in this
	// program)
	workQueue.Forget(key)
	return true
}

// nodeHasCiliumPod determines if a the node has a Cilium agent pod scheduled
// on it, and if it is running and ready.
func nodeHasCiliumPod(nodeName string) (scheduled bool, ready bool) {
	ciliumPodsInNode, err := ciliumPodsStore.ByIndex(hostnameIndexer, nodeName)
	if err != nil {
		return false, false
	}
	if len(ciliumPodsInNode) == 0 {
		return false, false
	}
	for _, ciliumPodInterface := range ciliumPodsInNode {
		ciliumPod := ciliumPodInterface.(*slim_corev1.Pod)
		if ciliumPod.DeletionTimestamp != nil { // even if the pod is running, it will be down shortly
			continue
		}
		if k8sUtils.GetLatestPodReadiness(ciliumPod.Status) == slim_corev1.ConditionTrue {
			return true, true
		}
	}
	return true, false
}

// hasAgentNotReadyTaint returns true if the given node has the Cilium Agent
// Not Ready Node Taint.
func hasAgentNotReadyTaint(k8sNode *slim_corev1.Node) bool {
	for _, taint := range k8sNode.Spec.Taints {
		if taint.Key == pkgOption.Config.AgentNotReadyNodeTaintValue() {
			return true
		}
	}
	return false
}

// hostNameIndexFunc index pods by node name.
func hostNameIndexFunc(obj interface{}) ([]string, error) {
	switch t := obj.(type) {
	case *slim_corev1.Pod:
		return []string{t.Spec.NodeName}, nil
	}
	return nil, fmt.Errorf("%w - found %T", errNoPod, obj)
}

func convertToCiliumPod(obj interface{}) interface{} {
	switch concreteObj := obj.(type) {
	case *slim_corev1.Pod:
		p := &slim_corev1.Pod{
			TypeMeta: concreteObj.TypeMeta,
			ObjectMeta: slim_metav1.ObjectMeta{
				Name:            concreteObj.Name,
				Namespace:       concreteObj.Namespace,
				ResourceVersion: concreteObj.ResourceVersion,
			},
			Spec: slim_corev1.PodSpec{
				NodeName: concreteObj.Spec.NodeName,
			},
			Status: slim_corev1.PodStatus{
				Conditions: concreteObj.Status.Conditions,
			},
		}
		*concreteObj = slim_corev1.Pod{}
		return p
	case cache.DeletedFinalStateUnknown:
		pod, ok := concreteObj.Obj.(*slim_corev1.Pod)
		if !ok {
			return obj
		}
		dfsu := cache.DeletedFinalStateUnknown{
			Key: concreteObj.Key,
			Obj: &slim_corev1.Pod{
				TypeMeta: pod.TypeMeta,
				ObjectMeta: slim_metav1.ObjectMeta{
					Name:            pod.Name,
					Namespace:       pod.Namespace,
					ResourceVersion: pod.ResourceVersion,
				},
				Spec: slim_corev1.PodSpec{
					NodeName: pod.Spec.NodeName,
				},
				Status: slim_corev1.PodStatus{
					Conditions: pod.Status.Conditions,
				},
			},
		}
		// Small GC optimization
		*pod = slim_corev1.Pod{}
		return dfsu
	default:
		return obj
	}
}

// setNodeNetworkUnavailableFalse sets Kubernetes NodeNetworkUnavailable to
// false as Cilium is managing the network connectivity.
// https://kubernetes.io/docs/concepts/architecture/nodes/#condition
// This is because some clusters (notably GCP) come up with a NodeNetworkUnavailable condition set
// and the network provider is expected to remove this manually.
func setNodeNetworkUnavailableFalse(ctx context.Context, c kubernetes.Interface, nodeGetter slimNodeGetter, nodeName string) error {
	n, err := nodeGetter.GetK8sSlimNode(nodeName)
	if err != nil {
		return err
	}

	if HasCiliumIsUpCondition(n) {
		return nil
	}

	now := metav1.Now()
	condition := corev1.NodeCondition{
		Type:               corev1.NodeNetworkUnavailable,
		Status:             corev1.ConditionFalse,
		Reason:             ciliumNodeConditionReason,
		Message:            "Cilium is running on this node",
		LastTransitionTime: now,
		LastHeartbeatTime:  now,
	}
	raw, err := json.Marshal(&[]corev1.NodeCondition{condition})
	if err != nil {
		return err
	}
	patch := []byte(fmt.Sprintf(`{"status":{"conditions":%s}}`, raw))
	_, err = c.CoreV1().Nodes().PatchStatus(ctx, nodeName, patch)
	if err != nil {
		log.WithField(logfields.NodeName, nodeName).WithError(err).Info("Failed to patch node while setting condition")
	}
	return err
}

// HasCiliumIsUpCondition returns true if the given k8s node has the cilium node
// condition set.
func HasCiliumIsUpCondition(n *slim_corev1.Node) bool {
	for _, condition := range n.Status.Conditions {
		if condition.Type == slim_corev1.NodeNetworkUnavailable &&
			condition.Status == slim_corev1.ConditionFalse &&
			condition.Reason == ciliumNodeConditionReason {
			return true
		}
	}
	return false
}

// removeNodeTaint removes the AgentNotReadyNodeTaint allowing for pods to be
// scheduled once Cilium is setup. Mostly used in cloud providers to prevent
// existing CNI plugins from managing pods.
func removeNodeTaint(ctx context.Context, c kubernetes.Interface, nodeGetter slimNodeGetter, nodeName string) error {
	k8sNode, err := nodeGetter.GetK8sSlimNode(nodeName)
	if err != nil {
		return err
	}

	var taintFound bool

	var taints []slim_corev1.Taint
	for _, taint := range k8sNode.Spec.Taints {
		if taint.Key != pkgOption.Config.AgentNotReadyNodeTaintValue() {
			taints = append(taints, taint)
		} else {
			taintFound = true
		}
	}

	// No cilium taints found
	if !taintFound {
		log.WithFields(logrus.Fields{
			logfields.NodeName: nodeName,
			"taint":            pkgOption.Config.AgentNotReadyNodeTaintValue(),
		}).Debug("Taint not found in node")
		return nil
	}
	log.WithFields(logrus.Fields{
		logfields.NodeName: nodeName,
		"taint":            pkgOption.Config.AgentNotReadyNodeTaintValue(),
	}).Debug("Removing Node Taint")

	createStatusAndNodePatch := []k8s.JSONPatch{
		{
			OP:    "test",
			Path:  "/spec/taints",
			Value: k8sNode.Spec.Taints,
		},
		{
			OP:    "replace",
			Path:  "/spec/taints",
			Value: taints,
		},
	}

	patch, err := json.Marshal(createStatusAndNodePatch)
	if err != nil {
		return err
	}

	_, err = c.CoreV1().Nodes().Patch(ctx, nodeName, k8sTypes.JSONPatchType, patch, metav1.PatchOptions{})
	if err != nil {
		log.WithField(logfields.NodeName, nodeName).WithError(err).Info("Failed to patch node while removing taint")
	}
	return err
}

// setNodeTaint sets the AgentNotReady taint on a node
func setNodeTaint(ctx context.Context, c kubernetes.Interface, nodeGetter slimNodeGetter, nodeName string) error {
	k8sNode, err := nodeGetter.GetK8sSlimNode(nodeName)
	if err != nil {
		return err
	}

	taintFound := false

	taints := append([]slim_corev1.Taint{}, k8sNode.Spec.Taints...)
	for _, taint := range k8sNode.Spec.Taints {
		if taint.Key == pkgOption.Config.AgentNotReadyNodeTaintValue() {
			taintFound = true
			break
		}
	}

	if taintFound {
		log.WithFields(logrus.Fields{
			logfields.NodeName: nodeName,
			"taint":            pkgOption.Config.AgentNotReadyNodeTaintValue(),
		}).Debug("Taint already set in node; skipping")
		return nil
	}
	log.WithFields(logrus.Fields{
		logfields.NodeName: nodeName,
		"taint":            pkgOption.Config.AgentNotReadyNodeTaintValue(),
	}).Debug("Setting Node Taint")

	taints = append(taints, slim_corev1.Taint{
		Key:    pkgOption.Config.AgentNotReadyNodeTaintValue(), // the function says value, but it's really a key
		Value:  "",
		Effect: slim_corev1.TaintEffectNoSchedule,
	})

	createStatusAndNodePatch := []k8s.JSONPatch{
		{
			OP:    "test",
			Path:  "/spec/taints",
			Value: k8sNode.Spec.Taints,
		},
		{
			OP:    "replace",
			Path:  "/spec/taints",
			Value: taints,
		},
	}

	patch, err := json.Marshal(createStatusAndNodePatch)
	if err != nil {
		return err
	}

	_, err = c.CoreV1().Nodes().Patch(ctx, nodeName, k8sTypes.JSONPatchType, patch, metav1.PatchOptions{})
	if err != nil {
		log.WithField(logfields.NodeName, nodeName).WithError(err).Info("Failed to patch node while adding taint")
	}
	return err
}

type markNodeOptions struct {
	RemoveNodeTaint        bool
	SetNodeTaint           bool
	SetCiliumIsUpCondition bool
}

// markNode marks the Kubernetes node depending on the modes that it is passed
// on.
func markNode(c kubernetes.Interface, nodeGetter slimNodeGetter, nodeName string, options markNodeOptions, running bool) {
	ctrlName := fmt.Sprintf("mark-k8s-node-%s-taints-conditions", nodeName)

	ctrlMgr.UpdateController(ctrlName,
		controller.ControllerParams{
			DoFunc: func(ctx context.Context) error {
				if running && options.RemoveNodeTaint {
					err := removeNodeTaint(ctx, c, nodeGetter, nodeName)
					if err != nil {
						return err
					}
				}
				if running && options.SetCiliumIsUpCondition {
					err := setNodeNetworkUnavailableFalse(ctx, c, nodeGetter, nodeName)
					if err != nil {
						return err
					}
				}
				if !running && options.SetNodeTaint {
					err := setNodeTaint(ctx, c, nodeGetter, nodeName)
					if err != nil {
						return err
					}
				}

				return nil
			},
		})
}

// HandleNodeTolerationAndTaints remove node
func HandleNodeTolerationAndTaints(wg *sync.WaitGroup, clientset k8sClient.Clientset, stopCh <-chan struct{}) {
	mno = markNodeOptions{
		RemoveNodeTaint:        option.Config.RemoveCiliumNodeTaints,
		SetNodeTaint:           option.Config.SetCiliumNodeTaints,
		SetCiliumIsUpCondition: option.Config.SetCiliumIsUpCondition,
	}
	nodesInit(wg, clientset.Slim(), stopCh)

	wg.Add(1)
	go func() {
		defer wg.Done()
		// Do not use the k8sClient provided by the nodesInit function since we
		// need a k8s client that can update node structures and not simply
		// watch for node events.
		for checkTaintForNextNodeItem(clientset, &nodeGetter{}, nodeQueue) {
		}
	}()

	ciliumPodsWatcher(wg, clientset, stopCh)
}
