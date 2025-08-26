// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sTypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/pkg/k8s"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/informer"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	slimclientset "github.com/cilium/cilium/pkg/k8s/slim/k8s/client/clientset/versioned"
	k8sUtils "github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/logging/logfields"
	pkgOption "github.com/cilium/cilium/pkg/option"
)

const (
	hostnameIndexer = "hostname-indexer"

	// ciliumNodeConditionReason is the condition name used by Cilium to set
	// when the Network is setup in the node.
	ciliumNodeConditionReason = "CiliumIsUp"

	maxSilentRetries = 6
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

	mno markNodeOptions
)

func checkTaintForNextNodeItem(c kubernetes.Interface, nodeGetter slimNodeGetter, workQueue workqueue.TypedRateLimitingInterface[string], logger *slog.Logger) bool {
	// Get the next 'key' from the queue.
	key, quit := workQueue.Get()
	if quit {
		return false
	}
	// Done marks item as done processing, and if it has been marked as dirty
	// again while it was being processed, it will be re-added to the queue for
	// re-processing.
	defer workQueue.Done(key)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := checkAndMarkNode(ctx, c, nodeGetter, key, mno, logger)
	// Do not requeue on node not found errors
	if err != nil && k8serrors.IsNotFound(err) {
		workQueue.Forget(key)
		return true
	}
	handleErr(err, key, workQueue, logger)
	return true
}

func handleErr(err error, key string, workQueue workqueue.TypedRateLimitingInterface[string], logger *slog.Logger) {
	if err == nil {
		if workQueue.NumRequeues(key) >= maxSilentRetries {
			logger.Info("Successfully updated taints and conditions for the node", logfields.NodeName, key)
		}
		workQueue.Forget(key)
		return
	}

	if workQueue.NumRequeues(key) < maxSilentRetries {
		logger.Debug(
			"Error updating taints and conditions for the node, will retry",
			logfields.NodeName, key,
			logfields.Error, err,
		)
	} else {
		logger.Warn(
			"Multiple consecutive retries of updating taints and conditions for a node failed, will retry",
			logfields.NodeName, key,
			logfields.Error, err,
		)
	}
	workQueue.AddRateLimited(key)
}

// checkAndMarkNode checks if the node contains a Cilium pod in running state
// so that it can set the taints / conditions of the node
func checkAndMarkNode(ctx context.Context, c kubernetes.Interface, nodeGetter slimNodeGetter, nodeName string, options markNodeOptions, logger *slog.Logger) error {
	node, err := nodeGetter.GetK8sSlimNode(nodeName)
	if err != nil {
		return err
	}
	if node == nil {
		return nil
	}

	// should we remove the taint?
	scheduled, running := nodeHasCiliumPod(node.GetName())
	if running {
		if (options.RemoveNodeTaint && hasAgentNotReadyTaint(node)) ||
			(options.SetCiliumIsUpCondition && !HasCiliumIsUpCondition(node)) {
			logger.Info("Cilium pod running for node; marking accordingly", logfields.NodeName, node.GetName())
			return markNode(ctx, c, nodeGetter, node.GetName(), options, true, logger)
		}
	} else if scheduled { // Taint nodes where the pod is scheduled but not running
		if options.SetNodeTaint && !hasAgentNotReadyTaint(node) {
			logger.Info("Cilium pod scheduled but not running for node; setting taint", logfields.NodeName, node.GetName())
			return markNode(ctx, c, nodeGetter, node.GetName(), options, false, logger)
		}
	}
	return nil
}

func ciliumPodHandler(obj any, queue workqueue.TypedRateLimitingInterface[string], logger *slog.Logger) {
	if pod := informer.CastInformerEvent[slim_corev1.Pod](logger, obj); pod != nil {
		nodeName := pod.Spec.NodeName
		// Pod might not yet be scheduled to a node
		if nodeName != "" {
			queue.Add(nodeName)
		}
	}
}

// ciliumPodsWatcher starts up a pod watcher to handle pod events.
func ciliumPodsWatcher(wg *sync.WaitGroup, slimClient slimclientset.Interface, queue workqueue.TypedRateLimitingInterface[string], stopCh <-chan struct{}, logger *slog.Logger) {
	ciliumPodInformer := informer.NewInformerWithStore(
		k8sUtils.ListerWatcherWithModifier(
			k8sUtils.ListerWatcherFromTyped[*slim_corev1.PodList](
				slimClient.CoreV1().Pods(option.Config.CiliumK8sNamespace),
			),
			func(options *metav1.ListOptions) {
				options.LabelSelector = option.Config.CiliumPodLabels
			}),
		&slim_corev1.Pod{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj any) {
				ciliumPodHandler(obj, queue, logger)
			},
			UpdateFunc: func(_, newObj any) {
				ciliumPodHandler(newObj, queue, logger)
			},
		},
		transformToCiliumPod,
		ciliumPodsStore,
	)

	wg.Add(1)
	go func() {
		defer wg.Done()
		ciliumPodInformer.Run(stopCh)
	}()

	cache.WaitForCacheSync(stopCh, ciliumPodInformer.HasSynced)
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
func hostNameIndexFunc(obj any) ([]string, error) {
	switch t := obj.(type) {
	case *slim_corev1.Pod:
		return []string{t.Spec.NodeName}, nil
	}
	return nil, fmt.Errorf("%w - found %T", errNoPod, obj)
}

func transformToCiliumPod(obj any) (any, error) {
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
		return p, nil
	case cache.DeletedFinalStateUnknown:
		pod, ok := concreteObj.Obj.(*slim_corev1.Pod)
		if !ok {
			return nil, fmt.Errorf("unknown object type %T", concreteObj.Obj)
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
		return dfsu, nil
	default:
		return nil, fmt.Errorf("unknown object type %T", concreteObj)
	}
}

// setNodeNetworkUnavailableFalse sets Kubernetes NodeNetworkUnavailable to
// false as Cilium is managing the network connectivity.
// https://kubernetes.io/docs/concepts/architecture/nodes/#condition
// This is because some clusters (notably GCP) come up with a NodeNetworkUnavailable condition set
// and the network provider is expected to remove this manually.
func setNodeNetworkUnavailableFalse(ctx context.Context, c kubernetes.Interface, nodeGetter slimNodeGetter, nodeName string, logger *slog.Logger) error {
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
	patch := fmt.Appendf(nil, `{"status":{"conditions":%s}}`, raw)
	_, err = c.CoreV1().Nodes().PatchStatus(ctx, nodeName, patch)
	if err != nil {
		logger.Info("Failed to patch node while setting condition",
			logfields.NodeName, nodeName,
			logfields.Error, err,
		)
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
func removeNodeTaint(ctx context.Context, c kubernetes.Interface, nodeGetter slimNodeGetter, nodeName string, logger *slog.Logger) error {
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
		logger.Debug("Taint not found in node",
			logfields.NodeName, nodeName,
			logfields.Taint, pkgOption.Config.AgentNotReadyNodeTaintValue(),
		)
		return nil
	}
	logger.Debug("Removing Node Taint",
		logfields.NodeName, nodeName,
		logfields.Taint, pkgOption.Config.AgentNotReadyNodeTaintValue(),
	)

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
		logger.Info("Failed to patch node while removing taint",
			logfields.NodeName, nodeName,
			logfields.Error, err,
		)
	}
	return err
}

// setNodeTaint sets the AgentNotReady taint on a node
func setNodeTaint(ctx context.Context, c kubernetes.Interface, nodeGetter slimNodeGetter, nodeName string, logger *slog.Logger) error {
	k8sNode, err := nodeGetter.GetK8sSlimNode(nodeName)
	if err != nil {
		return err
	}

	taintFound := false

	taints := slices.Clone(k8sNode.Spec.Taints)
	for _, taint := range k8sNode.Spec.Taints {
		if taint.Key == pkgOption.Config.AgentNotReadyNodeTaintValue() {
			taintFound = true
			break
		}
	}

	if taintFound {
		logger.Debug("Taint already set in node; skipping",
			logfields.NodeName, nodeName,
			logfields.Taint, pkgOption.Config.AgentNotReadyNodeTaintValue(),
		)
		return nil
	}
	logger.Debug("Setting Node Taint",
		logfields.NodeName, nodeName,
		logfields.Taint, pkgOption.Config.AgentNotReadyNodeTaintValue(),
	)

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
		logger.Info("Failed to patch node while adding taint",
			logfields.NodeName, nodeName,
			logfields.Error, err,
		)
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
func markNode(ctx context.Context, c kubernetes.Interface, nodeGetter slimNodeGetter, nodeName string, options markNodeOptions, running bool, logger *slog.Logger) error {
	if running && options.RemoveNodeTaint {
		err := removeNodeTaint(ctx, c, nodeGetter, nodeName, logger)
		if err != nil {
			return err
		}
	}
	if running && options.SetCiliumIsUpCondition {
		err := setNodeNetworkUnavailableFalse(ctx, c, nodeGetter, nodeName, logger)
		if err != nil {
			return err
		}
	}
	if !running && options.SetNodeTaint {
		err := setNodeTaint(ctx, c, nodeGetter, nodeName, logger)
		if err != nil {
			return err
		}
	}

	return nil
}

// HandleNodeTolerationAndTaints remove node
func HandleNodeTolerationAndTaints(wg *sync.WaitGroup, clientset k8sClient.Clientset, stopCh <-chan struct{}, logger *slog.Logger) {
	mno = markNodeOptions{
		RemoveNodeTaint:        option.Config.RemoveCiliumNodeTaints,
		SetNodeTaint:           option.Config.SetCiliumNodeTaints,
		SetCiliumIsUpCondition: option.Config.SetCiliumIsUpCondition,
	}

	nodesInit(wg, clientset.Slim(), stopCh, logger)
	// ciliumPodWatcher blocks waiting for cache sync.
	// we need to do it before starting worker threads
	// so checkAndMarkNode has cilium-pod information.
	// Additionally, we pass nodeQueue to ciliumPodWatcher.
	// that was initialized in nodesInit.
	ciliumPodsWatcher(wg, clientset.Slim(), nodeQueue, stopCh, logger)

	for i := 1; i <= option.Config.TaintSyncWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Do not use the k8sClient provided by the nodesInit function since we
			// need a k8s client that can update node structures and not simply
			// watch for node events.
			for checkTaintForNextNodeItem(clientset, &nodeGetter{}, nodeQueue, logger) {
			}
		}()
	}
}
