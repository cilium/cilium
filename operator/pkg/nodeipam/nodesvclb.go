// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nodeipam

import (
	"context"
	"slices"

	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/selection"
	"k8s.io/apimachinery/pkg/util/sets"
	utilsnet "k8s.io/utils/net"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	controllerruntime "github.com/cilium/cilium/operator/pkg/controller-runtime"
	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var (
	nodeSvcLBClass                 = annotation.Prefix + "/node"
	nodeSvcLBMatchLabelsAnnotation = annotation.Prefix + ".nodeipam" + "/match-node-labels"
)

type nodeSvcLBReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	Logger logrus.FieldLogger
}

func newNodeSvcLBReconciler(mgr ctrl.Manager, logger logrus.FieldLogger) *nodeSvcLBReconciler {
	return &nodeSvcLBReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		Logger: logger,
	}
}

// SetupWithManager sets up the controller with the Manager.
func (r *nodeSvcLBReconciler) SetupWithManager(mgr ctrl.Manager) error {
	filterSvc := func(obj client.Object) bool {
		svc, ok := obj.(*corev1.Service)
		return ok && r.isServiceSupported(svc)
	}

	return ctrl.NewControllerManagedBy(mgr).
		// Watch for changes to Services supported by the controller
		For(&corev1.Service{}, builder.WithPredicates(predicate.NewPredicateFuncs(filterSvc))).
		// Watch for changes to EndpointSlices
		Watches(&discoveryv1.EndpointSlice{}, r.enqueueRequestForEndpointSlice()).
		// Watch for changes to Nodes
		Watches(&corev1.Node{}, r.enqueueRequestForNode()).
		Complete(r)
}

// enqueueRequestForEndpointSlice enqueue the service if a corresponding Enndpoint Slice is updated
func (r *nodeSvcLBReconciler) enqueueRequestForEndpointSlice() handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, o client.Object) []reconcile.Request {
		scopedLog := r.Logger.WithFields(logrus.Fields{
			logfields.Controller: "node-service-lb",
			logfields.Resource:   client.ObjectKeyFromObject(o),
		})
		epSlice, ok := o.(*discoveryv1.EndpointSlice)
		if !ok {
			return []ctrl.Request{}
		}
		svcName, ok := epSlice.Labels[discoveryv1.LabelServiceName]
		if !ok {
			return []ctrl.Request{}
		}
		svc := client.ObjectKey{
			Namespace: epSlice.GetNamespace(),
			Name:      svcName,
		}
		scopedLog.WithField("service", svc).Info("Enqueued Service")
		return []ctrl.Request{{NamespacedName: svc}}
	})
}

// enqueueRequestForNode enqueues all Nodes that are candidates to be included
// by nodeipam (see shouldIncludeNode)
func (r *nodeSvcLBReconciler) enqueueRequestForNode() handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, o client.Object) []reconcile.Request {
		scopedLog := r.Logger.WithFields(logrus.Fields{
			logfields.Controller: "node-service-lb",
			logfields.Resource:   client.ObjectKeyFromObject(o),
		})

		node, ok := o.(*corev1.Node)
		if !ok {
			return []ctrl.Request{}
		}
		if !shouldIncludeNode(node) {
			return []ctrl.Request{}
		}

		svcList := &corev1.ServiceList{}
		if err := r.Client.List(ctx, svcList, &client.ListOptions{}); err != nil {
			scopedLog.WithError(err).Error("Failed to get Services")
			return []reconcile.Request{}
		}
		requests := []reconcile.Request{}
		for _, item := range svcList.Items {
			if !r.isServiceSupported(&item) {
				continue
			}
			svc := client.ObjectKey{
				Namespace: item.GetNamespace(),
				Name:      item.GetName(),
			}
			requests = append(requests, reconcile.Request{NamespacedName: svc})
			scopedLog.WithField("service", svc).Info("Enqueued Service")
		}
		return requests
	})
}

func (r *nodeSvcLBReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	scopedLog := r.Logger.WithFields(logrus.Fields{
		logfields.Controller: "node-service-lb",
		logfields.Resource:   req.NamespacedName,
	})
	scopedLog.Info("Reconciling Service")

	svc := corev1.Service{}
	err := r.Get(ctx, req.NamespacedName, &svc)
	if err != nil {
		if k8serrors.IsNotFound(err) {
			return controllerruntime.Success()
		}
		return controllerruntime.Fail(err)
	}

	if !r.isServiceSupported(&svc) {
		return controllerruntime.Success()
	}

	nodes, err := r.getRelevantNodes(ctx, &svc)
	if err != nil {
		return controllerruntime.Fail(err)
	}
	svc.Status.LoadBalancer.Ingress = getNodeLoadBalancerIngresses(nodes, svc.Spec.IPFamilies)
	return controllerruntime.Fail(r.Status().Update(ctx, &svc))
}

// isServiceSupported returns true if the service is supported by the controller
func (r nodeSvcLBReconciler) isServiceSupported(svc *corev1.Service) bool {
	if !svc.DeletionTimestamp.IsZero() {
		return false
	}
	if svc.Spec.Type != corev1.ServiceTypeLoadBalancer {
		return false
	}
	return svc.Spec.LoadBalancerClass != nil &&
		*svc.Spec.LoadBalancerClass == nodeSvcLBClass
}

// getEndpointSliceNodes returns the set of node names if eTP=Local. If eTP=Cluster
// the set returned will be nil.
func (r *nodeSvcLBReconciler) getEndpointSliceNodeNames(ctx context.Context, svc *corev1.Service) (sets.Set[string], error) {
	// If eTP=Cluster we don't filter nodes on EndpointSlice
	if svc.Spec.ExternalTrafficPolicy != corev1.ServiceExternalTrafficPolicyLocal {
		return nil, nil
	}

	selectedNodes := sets.Set[string]{}
	serviceReq, _ := labels.NewRequirement(discoveryv1.LabelServiceName, selection.Equals, []string{svc.Name})

	selector := labels.NewSelector()
	selector = selector.Add(*serviceReq)

	var epSliceList discoveryv1.EndpointSliceList
	if err := r.List(ctx, &epSliceList, &client.ListOptions{Namespace: svc.Namespace, LabelSelector: selector}); err != nil && !k8serrors.IsNotFound(err) {
		return nil, err
	}

	for _, item := range epSliceList.Items {
		for _, endpoint := range item.Endpoints {
			if endpoint.Conditions.Ready != nil && !*endpoint.Conditions.Ready {
				continue
			}
			if endpoint.NodeName == nil {
				continue
			}

			selectedNodes.Insert(*endpoint.NodeName)
		}
	}

	return selectedNodes, nil
}

// getRelevantNodes gets all the nodes candidates for seletion by nodeipam
func (r *nodeSvcLBReconciler) getRelevantNodes(ctx context.Context, svc *corev1.Service) ([]corev1.Node, error) {
	scopedLog := r.Logger.WithFields(logrus.Fields{
		logfields.Controller: "node-service-lb",
		logfields.Resource:   client.ObjectKeyFromObject(svc),
	})

	endpointSliceNames, err := r.getEndpointSliceNodeNames(ctx, svc)
	if err != nil {
		return []corev1.Node{}, err
	}
	nodeListOptions := &client.ListOptions{}
	if val, ok := svc.Annotations[nodeSvcLBMatchLabelsAnnotation]; ok {
		parsedLabels, err := labels.Parse(val)
		if err != nil {
			return []corev1.Node{}, err
		}
		nodeListOptions.LabelSelector = parsedLabels
	}

	var nodes corev1.NodeList
	if err := r.List(ctx, &nodes, nodeListOptions); err != nil {
		return []corev1.Node{}, err
	}
	if len(nodes.Items) == 0 {
		scopedLog.WithFields(logrus.Fields{logfields.Labels: nodeListOptions.LabelSelector}).Warning("No Nodes found with configured label selector")
	}

	relevantNodes := []corev1.Node{}
	for _, node := range nodes.Items {
		if !shouldIncludeNode(&node) {
			continue
		}
		if endpointSliceNames != nil && !endpointSliceNames.Has(node.Name) {
			continue
		}

		relevantNodes = append(relevantNodes, node)
	}
	return relevantNodes, nil
}

// getNodeLoadBalancerIngresses get all the load balancer ingresses with the specified nodes
// and IPFamilies. It will prioritize external IPs of the nodes if it can find some
// or internal IPs otherwise.
func getNodeLoadBalancerIngresses(nodes []corev1.Node, ipFamilies []corev1.IPFamily) []corev1.LoadBalancerIngress {
	hasV4 := slices.Contains(ipFamilies, corev1.IPv4Protocol)
	hasV6 := slices.Contains(ipFamilies, corev1.IPv6Protocol)
	extIPs := sets.Set[string]{}
	intIPs := sets.Set[string]{}
	for _, node := range nodes {
		for _, addr := range node.Status.Addresses {
			var currentIps *sets.Set[string]
			switch addr.Type {
			case corev1.NodeExternalIP:
				currentIps = &extIPs
			case corev1.NodeInternalIP:
				currentIps = &intIPs
			default:
				continue
			}

			switch {
			case hasV4 && utilsnet.IsIPv4String(addr.Address):
				currentIps.Insert(addr.Address)
			case hasV6 && utilsnet.IsIPv6String(addr.Address):
				currentIps.Insert(addr.Address)
			}
		}
	}

	var ips []string
	if extIPs.Len() > 0 {
		ips = extIPs.UnsortedList()
	} else {
		ips = intIPs.UnsortedList()
	}
	slices.Sort(ips)

	ingresses := make([]corev1.LoadBalancerIngress, len(ips))
	for i, ip := range ips {
		ingresses[i] = corev1.LoadBalancerIngress{IP: ip}
	}

	return ingresses
}
