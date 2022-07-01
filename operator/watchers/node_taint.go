// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/informer"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	k8sUtils "github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/logging/logfields"
	pkgOption "github.com/cilium/cilium/pkg/option"

	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sTypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
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
// so that it can remove the toleration and taints of that node.
func checkAndMarkNode(c kubernetes.Interface, nodeGetter slimNodeGetter, nodeName string, options markNodeOptions) bool {
	node, err := nodeGetter.GetK8sSlimNode(nodeName)
	if err != nil && !k8sErrors.IsNotFound(err) {
		return false
	}
	if node == nil {
		return false
	}

	if (options.RemoveNodeTaint && hasAgentNotReadyTaint(node)) ||
		(options.SetCiliumIsUpCondition && !HasCiliumIsUpCondition(node)) {
		if isCiliumPodRunning(node.GetName()) {
			markNode(c, nodeGetter, node.GetName(), options)
		} else {
			log.WithFields(logrus.Fields{logfields.NodeName: node.GetName()}).Debug("Cilium pod not running for node")
		}
	} else {
		log.WithFields(logrus.Fields{logfields.NodeName: node.GetName()}).Debug("Node without taint and with CiliumIsUp condition")
	}
	return true
}

// ciliumPodsWatcher starts up a pod watcher to handle pod events.
func ciliumPodsWatcher(k8sClient kubernetes.Interface, stopCh <-chan struct{}) {
	ciliumQueue := workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "cilium-pod-queue")

	ciliumPodInformer := informer.NewInformerWithStore(
		cache.NewFilteredListWatchFromClient(k8sClient.CoreV1().RESTClient(),
			"pods", option.Config.CiliumK8sNamespace, func(options *metav1.ListOptions) {
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

	go func() {
		// Do not use the k8sClient provided by the nodesInit function since we
		// need a k8s client that can update node structures and not simply
		// watch for node events.
		for processNextCiliumPodItem(k8s.Client(), nodeGetter, ciliumQueue) {
		}
	}()

	go ciliumPodInformer.Run(stopCh)
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

// isCiliumPodRunning returns true if there is a Cilium pod Ready on the given
// nodeName.
func isCiliumPodRunning(nodeName string) bool {
	ciliumPodsInNode, err := ciliumPodsStore.ByIndex(hostnameIndexer, nodeName)
	if err != nil {
		return false
	}
	if len(ciliumPodsInNode) == 0 {
		return false
	}
	for _, ciliumPodInterface := range ciliumPodsInNode {
		ciliumPod := ciliumPodInterface.(*slim_corev1.Pod)
		if k8sUtils.GetLatestPodReadiness(ciliumPod.Status) == slim_corev1.ConditionTrue {
			return true
		}
	}
	return false
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
	return err
}

type markNodeOptions struct {
	RemoveNodeTaint        bool
	SetCiliumIsUpCondition bool
}

// markNode marks the Kubernetes node depending on the modes that it is passed
// on.
func markNode(c kubernetes.Interface, nodeGetter slimNodeGetter, nodeName string, options markNodeOptions) {
	log.WithField(logfields.NodeName, nodeName).Debug("Setting NetworkUnavailable=false and removing taint of node")

	ctrlName := fmt.Sprintf("mark-k8s-node-%s-as-available", nodeName)

	ctrlMgr.UpdateController(ctrlName,
		controller.ControllerParams{
			DoFunc: func(ctx context.Context) error {
				if options.RemoveNodeTaint {
					err := removeNodeTaint(ctx, c, nodeGetter, nodeName)
					if err != nil {
						return err
					}
				}
				if options.SetCiliumIsUpCondition {
					err := setNodeNetworkUnavailableFalse(ctx, c, nodeGetter, nodeName)
					if err != nil {
						return err
					}
				}
				return nil
			},
		})
}

// HandleNodeTolerationAndTaints remove node
func HandleNodeTolerationAndTaints(stopCh <-chan struct{}) {
	mno = markNodeOptions{
		RemoveNodeTaint:        option.Config.RemoveCiliumNodeTaints,
		SetCiliumIsUpCondition: option.Config.SetCiliumIsUpCondition,
	}
	nodesInit(k8s.WatcherClient(), stopCh)

	go func() {
		// Do not use the k8sClient provided by the nodesInit function since we
		// need a k8s client that can update node structures and not simply
		// watch for node events.
		for checkTaintForNextNodeItem(k8s.Client(), &nodeGetter{}, nodeQueue) {
		}
	}()

	ciliumPodsWatcher(k8s.WatcherClient(), stopCh)
}
