// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mcsapi

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"reflect"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	k8sApiErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	mcsapicontrollers "sigs.k8s.io/mcs-api/controllers"
	mcsapiv1alpha1 "sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"

	controllerruntime "github.com/cilium/cilium/operator/pkg/controller-runtime"
	mcsapitypes "github.com/cilium/cilium/pkg/clustermesh/mcsapi/types"
	"github.com/cilium/cilium/pkg/clustermesh/operator"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// mcsAPIServiceImportReconciler is a controller that automatically creates
// ServiceImport from ServiceExport (and their corresponding Services) from
// remote clusters and the local cluster. It also handles ServiceExport status
// since we have all the info here to do so.
type mcsAPIServiceImportReconciler struct {
	client.Client
	Logger *slog.Logger

	cluster                    string
	globalServiceExports       *operator.GlobalServiceExportCache
	remoteClusterServiceSource *remoteClusterServiceExportSource
}

func newMCSAPIServiceImportReconciler(mgr ctrl.Manager, logger *slog.Logger, cluster string, globalServiceExports *operator.GlobalServiceExportCache, remoteClusterServiceSource *remoteClusterServiceExportSource) *mcsAPIServiceImportReconciler {
	return &mcsAPIServiceImportReconciler{
		Client:                     mgr.GetClient(),
		Logger:                     logger,
		cluster:                    cluster,
		globalServiceExports:       globalServiceExports,
		remoteClusterServiceSource: remoteClusterServiceSource,
	}
}

func (r *mcsAPIServiceImportReconciler) getSvcExport(ctx context.Context, req ctrl.Request) (*mcsapiv1alpha1.ServiceExport, error) {
	var svcExport mcsapiv1alpha1.ServiceExport
	if err := r.Client.Get(ctx, req.NamespacedName, &svcExport); err != nil {
		return nil, client.IgnoreNotFound(err)
	}
	return &svcExport, nil
}

func (r *mcsAPIServiceImportReconciler) getSvcImportBase(ctx context.Context, req ctrl.Request) (*mcsapiv1alpha1.ServiceImport, bool, error) {
	var svcImport mcsapiv1alpha1.ServiceImport
	if err := r.Client.Get(ctx, req.NamespacedName, &svcImport); err != nil {
		if k8sApiErrors.IsNotFound(err) {
			return &mcsapiv1alpha1.ServiceImport{
				ObjectMeta: metav1.ObjectMeta{
					Name:      req.Name,
					Namespace: req.Namespace,
				},
			}, false, nil
		}
		return nil, false, err
	}
	return &svcImport, true, nil
}

func (r *mcsAPIServiceImportReconciler) getLocalService(ctx context.Context, req ctrl.Request) (*corev1.Service, error) {
	var svc corev1.Service
	if err := r.Client.Get(ctx, req.NamespacedName, &svc); err != nil {
		return nil, client.IgnoreNotFound(err)
	}
	return &svc, nil
}

func (r *mcsAPIServiceImportReconciler) doesNamespaceExist(ctx context.Context, req ctrl.Request) (bool, error) {
	var ns corev1.Namespace
	key := types.NamespacedName{Name: req.Namespace}

	if err := r.Client.Get(ctx, key, &ns); err != nil {
		return false, client.IgnoreNotFound(err)
	}
	return true, nil
}

func fromServiceToMCSAPIServiceSpec(svc *corev1.Service, cluster string, svcExport *mcsapiv1alpha1.ServiceExport) *mcsapitypes.MCSAPIServiceSpec {
	ports := make([]mcsapiv1alpha1.ServicePort, 0, len(svc.Spec.Ports))
	for _, port := range svc.Spec.Ports {
		ports = append(ports, mcsapiv1alpha1.ServicePort{
			Name:        port.Name,
			Protocol:    port.Protocol,
			AppProtocol: port.AppProtocol,
			Port:        port.Port,
		})
	}
	mcsAPISvcType := mcsapiv1alpha1.ClusterSetIP
	if svc.Spec.ClusterIP == corev1.ClusterIPNone {
		mcsAPISvcType = mcsapiv1alpha1.Headless
	}
	mcsAPISvcSpec := &mcsapitypes.MCSAPIServiceSpec{
		Cluster:                 cluster,
		Name:                    svc.Name,
		Namespace:               svc.Namespace,
		ExportCreationTimestamp: svcExport.CreationTimestamp,
		Ports:                   ports,
		Type:                    mcsAPISvcType,
		SessionAffinity:         svc.Spec.SessionAffinity,
		SessionAffinityConfig:   svc.Spec.SessionAffinityConfig.DeepCopy(),
		Annotations:             maps.Clone(svcExport.Spec.ExportedAnnotations),
		Labels:                  maps.Clone(svcExport.Spec.ExportedLabels),
	}
	return mcsAPISvcSpec
}

type portMerge struct {
	mcsapiv1alpha1.ServicePort

	cluster                 string
	ExportCreationTimestamp metav1.Time
}

// orderSvcExportByPriority order the service export by priority (oldest to newest
// service exports). If export times of two service exports are equal
// it also sort by cluster name.
func orderSvcExportByPriority(svcExportByCluster operator.ServiceExportsByCluster) []*mcsapitypes.MCSAPIServiceSpec {
	return slices.SortedFunc(maps.Values(svcExportByCluster), func(a, b *mcsapitypes.MCSAPIServiceSpec) int {
		if a.ExportCreationTimestamp.Equal(&b.ExportCreationTimestamp) {
			return strings.Compare(a.Cluster, b.Cluster)
		}
		if a.ExportCreationTimestamp.Before(&b.ExportCreationTimestamp) {
			return -1
		}
		return 1
	})
}

func isSimilarPort(a, b mcsapiv1alpha1.ServicePort) bool {
	return a.Port == b.Port && a.Protocol == b.Protocol
}

// checkDuplicatedPortNameConflict check if port has a duplicated port name in portsByName.
func checkDuplicatedPortNameConflict(port portMerge, portsByName map[string]portMerge) string {
	portByName, foundPortByName := portsByName[port.Name]
	if foundPortByName && !isSimilarPort(port.ServicePort, portByName.ServicePort) {
		return fmt.Sprintf(
			"Duplicated port name \"%s\". Using port definition \"%v\" from oldest service export in cluster \"%s\".",
			port.Name, portByName, portByName.cluster,
		)
	}

	return ""
}

func checkPortConflict(port, olderPort portMerge) string {
	if port.Name != olderPort.Name {
		return fmt.Sprintf(
			"Conflicting port name on \"%v\". Using the port name \"%s\" from oldest service export in cluster \"%s\".",
			port, olderPort.Name, olderPort.cluster,
		)
	}
	if ptr.Deref(port.AppProtocol, "") != ptr.Deref(olderPort.AppProtocol, "") {
		return fmt.Sprintf(
			"Conflicting appProtocol on \"%v\". Using the appProtocol \"%s\" from oldest service export in cluster \"%s\".",
			port, ptr.Deref(olderPort.AppProtocol, ""), olderPort.cluster,
		)
	}
	return ""
}

// mergePorts merge all the ports into a map while doing conflict resolution
// with the oldest CreationTimestamp. It also return if it detects any conflict
func mergePorts(orderedSvcExports []*mcsapitypes.MCSAPIServiceSpec) ([]portMerge, mcsapiv1alpha1.ServiceExportConditionReason, string) {
	conflictMsg := ""
	ports := []portMerge{}
	portsByName := map[string]portMerge{}
	for _, svcExport := range orderedSvcExports {
		for _, port := range svcExport.Ports {
			portMergeValue := portMerge{
				ServicePort:             port,
				cluster:                 svcExport.Cluster,
				ExportCreationTimestamp: svcExport.ExportCreationTimestamp,
			}

			conflictDuplicatedPortName := checkDuplicatedPortNameConflict(portMergeValue, portsByName)
			if conflictMsg == "" {
				conflictMsg = conflictDuplicatedPortName
			}
			if conflictDuplicatedPortName != "" {
				continue
			}

			portIndex := slices.IndexFunc(ports, func(currPort portMerge) bool {
				return isSimilarPort(port, currPort.ServicePort)
			})
			if portIndex == -1 {
				// We don't override any port in portsByName so that this map
				// always keep the values from the oldest service export
				// exporting that port name
				portsByName[port.Name] = portMergeValue
				ports = append(ports, portMergeValue)
			} else if conflictMsg == "" {
				conflictMsg = checkPortConflict(portMergeValue, ports[portIndex])
			}
		}
	}
	reason := mcsapiv1alpha1.ServiceExportReasonNoConflicts
	if conflictMsg != "" {
		reason = mcsapiv1alpha1.ServiceExportReasonPortConflict
	}
	return ports, reason, conflictMsg
}

func mergedPortsToMCSPorts(mergedPorts []portMerge) []mcsapiv1alpha1.ServicePort {
	ports := make([]mcsapiv1alpha1.ServicePort, 0, len(mergedPorts))
	for _, port := range mergedPorts {
		ports = append(ports, port.ServicePort)
	}
	return ports
}

func getClustersStatus(svcExportByCluster operator.ServiceExportsByCluster) []mcsapiv1alpha1.ClusterStatus {
	clusters := make([]mcsapiv1alpha1.ClusterStatus, 0, len(svcExportByCluster))
	for _, cluster := range slices.Sorted(maps.Keys(svcExportByCluster)) {
		clusters = append(clusters, mcsapiv1alpha1.ClusterStatus{
			Cluster: cluster,
		})
	}
	return clusters
}

func derefSessionAffinity(sessionAffinityConfig *corev1.SessionAffinityConfig) *int32 {
	if sessionAffinityConfig == nil ||
		sessionAffinityConfig.ClientIP == nil ||
		sessionAffinityConfig.ClientIP.TimeoutSeconds == nil {
		return nil
	}
	return sessionAffinityConfig.ClientIP.TimeoutSeconds
}

// checkConflictExport check if there are any conflict to be added on
// the ServiceExport object. This function does not check for conflict on the
// ports field this aspect should be done by mergePorts
func checkConflictExport(orderedSvcExports []*mcsapitypes.MCSAPIServiceSpec) (mcsapiv1alpha1.ServiceExportConditionReason, string) {
	clusterCount := len(orderedSvcExports)

	fieldStructs := []struct {
		name       string
		reason     mcsapiv1alpha1.ServiceExportConditionReason
		getterFunc func(svcSpec *mcsapitypes.MCSAPIServiceSpec) string
		equalFunc  func(svc1, svc2 *mcsapitypes.MCSAPIServiceSpec) bool
	}{
		{
			name:   "type",
			reason: mcsapiv1alpha1.ServiceExportReasonTypeConflict,
			getterFunc: func(svcSpec *mcsapitypes.MCSAPIServiceSpec) string {
				return string(svcSpec.Type)
			},
			equalFunc: func(svc1, svc2 *mcsapitypes.MCSAPIServiceSpec) bool {
				return svc1.Type == svc2.Type
			},
		},
		{
			name:   "sessionAffinity",
			reason: mcsapiv1alpha1.ServiceExportReasonSessionAffinityConflict,
			getterFunc: func(svcSpec *mcsapitypes.MCSAPIServiceSpec) string {
				return string(svcSpec.SessionAffinity)
			},
			equalFunc: func(svc1, svc2 *mcsapitypes.MCSAPIServiceSpec) bool {
				return svc1.SessionAffinity == svc2.SessionAffinity
			},
		},
		{
			name:   "sessionAffinityConfig.clientIP",
			reason: mcsapiv1alpha1.ServiceExportReasonSessionAffinityConfigConflict,
			getterFunc: func(svcSpec *mcsapitypes.MCSAPIServiceSpec) string {
				timeoutSeconds := derefSessionAffinity(svcSpec.SessionAffinityConfig)
				if timeoutSeconds == nil {
					return ""
				}
				return string(*timeoutSeconds)
			},
			equalFunc: func(svc1, svc2 *mcsapitypes.MCSAPIServiceSpec) bool {
				return ptr.Equal(derefSessionAffinity(svc1.SessionAffinityConfig), derefSessionAffinity(svc2.SessionAffinityConfig))
			},
		},
		{
			name:   "annotations",
			reason: mcsapiv1alpha1.ServiceExportReasonAnnotationsConflict,
			getterFunc: func(svcSpec *mcsapitypes.MCSAPIServiceSpec) string {
				return fmt.Sprintf("%v", svcSpec.Annotations)
			},
			equalFunc: func(svc1, svc2 *mcsapitypes.MCSAPIServiceSpec) bool {
				return maps.Equal(svc1.Annotations, svc2.Annotations)
			},
		},
		{
			name:   "labels",
			reason: mcsapiv1alpha1.ServiceExportReasonLabelsConflict,
			getterFunc: func(svcSpec *mcsapitypes.MCSAPIServiceSpec) string {
				return fmt.Sprintf("%v", svcSpec.Labels)
			},
			equalFunc: func(svc1, svc2 *mcsapitypes.MCSAPIServiceSpec) bool {
				return maps.Equal(svc1.Labels, svc2.Labels)
			},
		},
	}
	for i, svcExport := range orderedSvcExports[1:] {
		for _, fieldStruct := range fieldStructs {
			if fieldStruct.equalFunc(orderedSvcExports[0], svcExport) {
				continue
			}

			conflictCount := 1
			// The iterator "i" ranges from the second element in the array which means
			// we have to look for i+2 to process the next element
			if i+2 < len(orderedSvcExports) {
				for _, otherSvcExport := range orderedSvcExports[i+2:] {
					if !fieldStruct.equalFunc(orderedSvcExports[0], otherSvcExport) {
						conflictCount += 1
					}
				}
			}

			return fieldStruct.reason, fmt.Sprintf(
				"Conflicting %s. %d/%d clusters disagree. Using \"%s\" from oldest service export in cluster \"%s\".",
				fieldStruct.name, conflictCount, clusterCount,
				fieldStruct.getterFunc(orderedSvcExports[0]),
				orderedSvcExports[0].Cluster,
			)
		}
	}

	return mcsapiv1alpha1.ServiceExportReasonNoConflicts, ""
}

func setInvalidStatus(conditions *[]metav1.Condition, reason mcsapiv1alpha1.ServiceExportConditionReason, msg string) bool {
	changed := meta.SetStatusCondition(conditions, mcsapiv1alpha1.NewServiceExportCondition(
		mcsapiv1alpha1.ServiceExportConditionValid,
		metav1.ConditionFalse,
		reason,
		msg,
	))
	changed = meta.SetStatusCondition(conditions, mcsapiv1alpha1.NewServiceExportCondition(
		mcsapiv1alpha1.ServiceExportConditionReady,
		metav1.ConditionFalse,
		mcsapiv1alpha1.ServiceExportReasonPending,
		"ServiceExport is not valid",
	)) || changed
	return meta.RemoveStatusCondition(conditions, string(mcsapiv1alpha1.ServiceExportConditionConflict)) || changed
}

func (r *mcsAPIServiceImportReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	nsExists, err := r.doesNamespaceExist(ctx, req)
	if err != nil {
		return controllerruntime.Fail(err)
	}
	if !nsExists {
		return controllerruntime.Success()
	}

	svcImport, svcImportExists, err := r.getSvcImportBase(ctx, req)
	if err != nil {
		return controllerruntime.Fail(err)
	}
	svcExport, err := r.getSvcExport(ctx, req)
	if err != nil {
		return controllerruntime.Fail(err)
	}

	svcExportByCluster := r.globalServiceExports.GetServiceExportByCluster(req.NamespacedName)
	if len(svcExportByCluster) == 0 && svcExport == nil {
		if svcImportExists {
			return controllerruntime.Fail(r.Client.Delete(ctx, svcImport))
		}
		return controllerruntime.Success()
	}

	if svcExport != nil {
		localSvc, err := r.getLocalService(ctx, req)
		if err != nil {
			return controllerruntime.Fail(err)
		}
		if localSvc == nil {
			if setInvalidStatus(
				&svcExport.Status.Conditions,
				mcsapiv1alpha1.ServiceExportReasonNoService,
				"Service doesn't exist",
			) {
				if err := r.Client.Status().Update(ctx, svcExport); err != nil {
					return controllerruntime.Fail(err)
				}
			}
			return controllerruntime.Success()
		}
		localSvcSpec := fromServiceToMCSAPIServiceSpec(localSvc, r.cluster, svcExport)
		if svcExportByCluster == nil {
			svcExportByCluster = operator.ServiceExportsByCluster{}
		}
		svcExportByCluster[r.cluster] = localSvcSpec

		if localSvc.Spec.Type == corev1.ServiceTypeExternalName {
			if setInvalidStatus(
				&svcExport.Status.Conditions,
				mcsapiv1alpha1.ServiceExportReasonInvalidServiceType,
				"Service type ExternalName is not supported",
			) {
				if err := r.Client.Status().Update(ctx, svcExport); err != nil {
					return controllerruntime.Fail(err)
				}
			}
			return controllerruntime.Success()
		}
	}

	orderedSvcExports := orderSvcExportByPriority(svcExportByCluster)
	mergedPorts, conflictReason, conflictMsg := mergePorts(orderedSvcExports)
	if conflictReason == mcsapiv1alpha1.ServiceExportReasonNoConflicts {
		conflictReason, conflictMsg = checkConflictExport(orderedSvcExports)
	}

	if svcExport != nil {
		changedCondition := meta.SetStatusCondition(&svcExport.Status.Conditions, mcsapiv1alpha1.NewServiceExportCondition(
			mcsapiv1alpha1.ServiceExportConditionValid,
			metav1.ConditionTrue,
			mcsapiv1alpha1.ServiceExportReasonValid,
			"ServiceExport is valid",
		))
		changedCondition = meta.SetStatusCondition(&svcExport.Status.Conditions, mcsapiv1alpha1.NewServiceExportCondition(
			mcsapiv1alpha1.ServiceExportConditionReady,
			metav1.ConditionTrue,
			mcsapiv1alpha1.ServiceExportReasonReady,
			"ServiceExport is ready",
		)) || changedCondition

		if conflictReason != mcsapiv1alpha1.ServiceExportReasonNoConflicts {
			changedCondition = meta.SetStatusCondition(&svcExport.Status.Conditions, mcsapiv1alpha1.NewServiceExportCondition(
				mcsapiv1alpha1.ServiceExportConditionConflict,
				metav1.ConditionTrue,
				conflictReason,
				conflictMsg,
			)) || changedCondition
		} else {
			changedCondition = meta.SetStatusCondition(&svcExport.Status.Conditions, mcsapiv1alpha1.NewServiceExportCondition(
				mcsapiv1alpha1.ServiceExportConditionConflict,
				metav1.ConditionFalse,
				mcsapiv1alpha1.ServiceExportReasonNoConflicts,
				"ServiceExport has no conflicts",
			)) || changedCondition
		}
		if changedCondition {
			if err := r.Client.Status().Update(ctx, svcExport); err != nil {
				return controllerruntime.Fail(err)
			}
		}
	}

	oldestClusterSvc := orderedSvcExports[0]
	svcImport.Spec.Ports = mergedPortsToMCSPorts(mergedPorts)
	svcImport.Spec.Type = oldestClusterSvc.Type
	svcImport.Spec.SessionAffinity = oldestClusterSvc.SessionAffinity
	svcImport.Spec.SessionAffinityConfig = oldestClusterSvc.SessionAffinityConfig.DeepCopy()
	svcImport.Labels = maps.Clone(oldestClusterSvc.Labels)
	annotations := maps.Clone(oldestClusterSvc.Annotations)
	_, derivedSvcAnnotationExists := svcImport.Annotations[mcsapicontrollers.DerivedServiceAnnotation]
	if derivedSvcAnnotationExists {
		if annotations == nil {
			annotations = map[string]string{}
		}
		annotations[mcsapicontrollers.DerivedServiceAnnotation] = svcImport.Annotations[mcsapicontrollers.DerivedServiceAnnotation]
	}
	svcImport.Annotations = annotations

	svcImport, err = r.createOrUpdateServiceImport(ctx, svcImport)
	if err != nil {
		return controllerruntime.Fail(err)
	}

	svcImportStatusOriginal := svcImport.Status.DeepCopy()
	svcImport.Status.Clusters = getClustersStatus(svcExportByCluster)
	if derivedSvcAnnotationExists {
		meta.SetStatusCondition(&svcImport.Status.Conditions, mcsapiv1alpha1.NewServiceImportCondition(
			mcsapiv1alpha1.ServiceImportConditionReady,
			metav1.ConditionTrue,
			mcsapiv1alpha1.ServiceImportReasonReady,
			"ServiceImport is ready",
		))
	} else {
		meta.SetStatusCondition(&svcImport.Status.Conditions, mcsapiv1alpha1.NewServiceImportCondition(
			mcsapiv1alpha1.ServiceImportConditionReady,
			metav1.ConditionFalse,
			mcsapiv1alpha1.ServiceImportReasonPending,
			"Waiting for the derived Service to be created",
		))
	}
	if !reflect.DeepEqual(svcImportStatusOriginal, svcImport.Status) {
		if err := r.Client.Status().Update(ctx, svcImport); err != nil {
			return controllerruntime.Fail(err)
		}
	}
	return controllerruntime.Success()
}

func (r *mcsAPIServiceImportReconciler) createOrUpdateServiceImport(ctx context.Context, desiredSvcImport *mcsapiv1alpha1.ServiceImport) (*mcsapiv1alpha1.ServiceImport, error) {
	svcImport := &mcsapiv1alpha1.ServiceImport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      desiredSvcImport.Name,
			Namespace: desiredSvcImport.Namespace,
		},
	}

	result, err := controllerutil.CreateOrUpdate(ctx, r.Client, svcImport, func() error {
		svcImport.Annotations = desiredSvcImport.Annotations
		svcImport.Labels = desiredSvcImport.Labels
		svcImport.Spec = desiredSvcImport.Spec
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create or update ServiceImport: %w", err)
	}

	r.Logger.Debug(fmt.Sprintf("ServiceImport %s has been %s", client.ObjectKeyFromObject(svcImport), result))

	return svcImport, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *mcsAPIServiceImportReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&mcsapiv1alpha1.ServiceImport{}).
		// Watch for changes to ServiceExport
		Watches(&mcsapiv1alpha1.ServiceExport{}, &handler.EnqueueRequestForObject{}).
		// Watch for changes to Services
		Watches(&corev1.Service{}, &handler.EnqueueRequestForObject{}).
		// Watch for changes to Namespace to requeue remote service exports
		Watches(&corev1.Namespace{}, handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []ctrl.Request {
			requests := []ctrl.Request{}
			for _, name := range r.globalServiceExports.GetServiceExportsName(obj.GetName()) {
				requests = append(requests, ctrl.Request{
					NamespacedName: types.NamespacedName{
						Namespace: obj.GetName(),
						Name:      name,
					},
				})
			}

			return requests
		})).
		// Watch changes to external services
		WatchesRawSource(r.remoteClusterServiceSource).
		Complete(r)
}

// remoteClusterServiceExportSource is a source to watch remote cluster service exports.
// The actual type returned by the watch is a ServiceExport to match the interface
// needed by a regular controller-runtime controller. This prevents us from
// implementing a more complicated/hands-on pattern of controller.
type remoteClusterServiceExportSource struct {
	Logger *slog.Logger

	ctx   context.Context
	queue workqueue.TypedRateLimitingInterface[ctrl.Request]
}

func (s *remoteClusterServiceExportSource) onClusterServiceExportEvent(svcExport *mcsapitypes.MCSAPIServiceSpec) {
	if s.ctx == nil || s.queue == nil {
		// At this point the controller is not started yet and the namespace
		// watcher will enqueue any initial state from remote clusters
		// on start.
		return
	}

	s.Logger.
		Debug(
			"Queueing update from remote cluster",
			logfields.K8sNamespace, svcExport.Namespace,
			logfields.K8sExportName, svcExport.Name,
		)
	s.queue.Add(ctrl.Request{NamespacedName: types.NamespacedName{
		Name:      svcExport.Name,
		Namespace: svcExport.Namespace,
	}})
}

func (s *remoteClusterServiceExportSource) Start(
	ctx context.Context,
	queue workqueue.TypedRateLimitingInterface[ctrl.Request],
) error {
	s.ctx = ctx
	s.queue = queue
	return nil
}
