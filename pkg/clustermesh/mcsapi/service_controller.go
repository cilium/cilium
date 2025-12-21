// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mcsapi

import (
	"context"
	"crypto/sha256"
	"encoding/base32"
	"log/slog"
	"maps"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	k8sApiErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	mcsapicontrollers "sigs.k8s.io/mcs-api/controllers"
	mcsapiv1alpha1 "sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"

	controllerruntime "github.com/cilium/cilium/operator/pkg/controller-runtime"
	"github.com/cilium/cilium/pkg/annotation"
	mcsapitypes "github.com/cilium/cilium/pkg/clustermesh/mcsapi/types"
)

// mcsAPIServiceReconciler is a controller that creates a derived service from
// a ServiceImport object. The derived Service is created with the Cilium
// annotations to mark it as a global Service so that we can take advantage of
// the existing clustermesh features for the MCS API Support.
type mcsAPIServiceReconciler struct {
	client.Client
	Logger *slog.Logger
}

func newMCSAPIServiceReconciler(mgr ctrl.Manager, logger *slog.Logger) *mcsAPIServiceReconciler {
	return &mcsAPIServiceReconciler{
		Client: mgr.GetClient(),
		Logger: logger,
	}
}

func getOwnerReferenceName(refs []metav1.OwnerReference, apiVersion string, kind string) string {
	for _, ref := range refs {
		if ref.APIVersion != apiVersion {
			continue
		}
		if ref.Kind == kind {
			return ref.Name
		}
	}
	return ""
}

// derivedName derive the original name in the format "derived-$hash".
// This function was taken from the mcs-api repo: https://github.com/kubernetes-sigs/mcs-api/blob/4231f56e5ff985676b8ac99034b05609cf4a9e0d/pkg/controllers/common.go#L39
func derivedName(name types.NamespacedName) string {
	hash := sha256.New()
	hash.Write([]byte(name.String()))
	return "derived-" + strings.ToLower(base32.HexEncoding.WithPadding(base32.NoPadding).EncodeToString(hash.Sum(nil)))[:10]
}

func servicePorts(svcImport *mcsapiv1alpha1.ServiceImport) []corev1.ServicePort {
	ports := make([]corev1.ServicePort, 0, len(svcImport.Spec.Ports))
	for _, port := range svcImport.Spec.Ports {
		ports = append(ports, corev1.ServicePort{
			Name:        port.Name,
			Protocol:    port.Protocol,
			AppProtocol: port.AppProtocol,
			Port:        port.Port,
		})
	}

	return ports
}

// getDesiredIPs returns the IPs of the ServiceImport based on the derived Service
func getDesiredIPs(svc *corev1.Service) []string {
	if svc.Spec.ClusterIP == corev1.ClusterIPNone {
		return []string{}
	}

	valIPFamilies, ok := svc.Annotations[annotation.SupportedIPFamilies]
	ipFamilies, err := mcsapitypes.IPFamiliesFromString(valIPFamilies)
	if !ok || err != nil {
		// Fallback to all ips if the annotation is not set. This is likely
		// because we are upgrading to Cilium 1.19
		return slices.Clone(svc.Spec.ClusterIPs)
	}

	// get IPs in the order of the supported ip families
	ips := make([]string, 0, len(ipFamilies))
	for _, family := range ipFamilies {
		switch family {
		case corev1.IPv4Protocol:
			i := slices.IndexFunc(svc.Spec.ClusterIPs, func(ip string) bool {
				return !strings.Contains(ip, ":")
			})
			if i == -1 {
				continue
			}
			ips = append(ips, svc.Spec.ClusterIPs[i])
		case corev1.IPv6Protocol:
			i := slices.IndexFunc(svc.Spec.ClusterIPs, func(ip string) bool {
				return strings.Contains(ip, ":")
			})
			if i == -1 {
				continue
			}
			ips = append(ips, svc.Spec.ClusterIPs[i])
		}
	}
	return ips
}

// patchServiceImport patches the ServiceImport with the derived service name and
// also report back the IPs of the derived service to the ServiceImport.
func (r *mcsAPIServiceReconciler) patchServiceImport(
	ctx context.Context, svcImport *mcsapiv1alpha1.ServiceImport,
	derivedServiceName string, desiredIPs []string,
) error {
	updated := false
	desired := svcImport.DeepCopy()
	if desired.Annotations == nil {
		desired.Annotations = map[string]string{}
	}
	if desired.Annotations[mcsapicontrollers.DerivedServiceAnnotation] != derivedServiceName {
		desired.Annotations[mcsapicontrollers.DerivedServiceAnnotation] = derivedServiceName
		updated = true
	}

	if !slices.Equal(desired.Spec.IPs, desiredIPs) {
		desired.Spec.IPs = desiredIPs
		updated = true
	}

	if updated {
		return r.Client.Patch(ctx, desired, client.MergeFrom(svcImport))
	}
	return nil
}

// getDerivedService get the derived service if it exist or else a minimally constructed
// service. If the base service has the wrong headlessness it will be auto deleted as well.
func (r *mcsAPIServiceReconciler) getBaseDerivedService(
	ctx context.Context,
	req ctrl.Request,
	derivedServiceName string,
	svcImport *mcsapiv1alpha1.ServiceImport,
) (*corev1.Service, bool, error) {
	isHeadless := false
	if svcImport != nil {
		isHeadless = svcImport.Spec.Type == mcsapiv1alpha1.Headless
	}

	svcBase := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: req.Namespace,
			Name:      derivedServiceName,
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeClusterIP,
			// Always prefer dual stack as we always rely on the supported
			// ip families annotation to get the real ip families anyway
			IPFamilyPolicy: ptr.To(corev1.IPFamilyPolicyPreferDualStack),
		},
	}
	if isHeadless {
		svcBase.Spec.ClusterIP = corev1.ClusterIPNone
	}

	var svc corev1.Service
	if err := r.Client.Get(ctx, types.NamespacedName{Namespace: req.Namespace, Name: derivedServiceName}, &svc); err != nil {
		if !k8sApiErrors.IsNotFound(err) {
			return nil, false, err
		}
		return svcBase, false, nil
	}

	// Force prefer dual stack to migrate old services created in Cilium 1.18 or older
	svc.Spec.IPFamilyPolicy = ptr.To(corev1.IPFamilyPolicyPreferDualStack)
	if isHeadless != (svc.Spec.ClusterIP == corev1.ClusterIPNone) {
		// We need to delete the derived service first if we need to switch
		// to/from headless on a Service that already exists.
		if err := r.Client.Delete(ctx, &svc); err != nil {
			return nil, false, err
		}
		return svcBase, false, nil
	}
	return &svc, true, nil
}

func (r *mcsAPIServiceReconciler) getSvcImport(ctx context.Context, req ctrl.Request) (*mcsapiv1alpha1.ServiceImport, error) {
	var svcImport mcsapiv1alpha1.ServiceImport
	if err := r.Client.Get(ctx, req.NamespacedName, &svcImport); err != nil {
		return nil, client.IgnoreNotFound(err)
	}
	return &svcImport, nil
}

func (r *mcsAPIServiceReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	svcImport, err := r.getSvcImport(ctx, req)
	if err != nil {
		return controllerruntime.Fail(err)
	}
	if svcImport == nil {
		return controllerruntime.Success()
	}

	derivedServiceName := derivedName(req.NamespacedName)
	svc, svcExists, err := r.getBaseDerivedService(ctx, req, derivedServiceName, svcImport)
	if err != nil {
		return controllerruntime.Fail(err)
	}

	if val, ok := svcImport.Annotations[annotation.SupportedIPFamilies]; val == "" && ok {
		// If we don't have any supported ip families, we can bail out and cleanup
		// any existing derived service
		if svcExists {
			return controllerruntime.Fail(r.Client.Delete(ctx, svc))
		}
		return controllerruntime.Success()
	}

	svc.Spec.Selector = map[string]string{}
	svc.Spec.Ports = servicePorts(svcImport)
	svc.Spec.InternalTrafficPolicy = ptr.To(ptr.Deref(svcImport.Spec.InternalTrafficPolicy, corev1.ServiceInternalTrafficPolicyCluster))
	if svcImport.Spec.TrafficDistribution != nil {
		svc.Spec.TrafficDistribution = ptr.To(*svcImport.Spec.TrafficDistribution)
	} else {
		svc.Spec.TrafficDistribution = nil
	}

	if err := ctrl.SetControllerReference(svcImport, svc, r.Scheme()); err != nil {
		return controllerruntime.Fail(err)
	}

	svc.Annotations = maps.Clone(svcImport.Annotations)
	if svc.Annotations == nil {
		svc.Annotations = map[string]string{}
	}
	svc.Annotations[annotation.GlobalService] = "true"

	svc.Labels = maps.Clone(svcImport.Labels)
	if svc.Labels == nil {
		svc.Labels = map[string]string{}
	}
	svc.Labels[mcsapiv1alpha1.LabelServiceName] = req.NamespacedName.Name

	if !svcExists {
		if err := r.Client.Create(ctx, svc); err != nil {
			if k8sApiErrors.IsForbidden(err) && k8sApiErrors.HasStatusCause(err, corev1.NamespaceTerminatingCause) {
				r.Logger.InfoContext(ctx, "Aborting reconciliation because namespace is being terminated")
				return controllerruntime.Success()
			}
			return controllerruntime.Fail(err)
		}
	} else {
		if err := r.Client.Update(ctx, svc); err != nil {
			return controllerruntime.Fail(err)
		}
	}

	// Update the ServiceImport object after the derived Service creation
	return controllerruntime.Fail(r.patchServiceImport(ctx, svcImport, derivedServiceName, getDesiredIPs(svc)))
}

// SetupWithManager sets up the controller with the Manager.
func (r *mcsAPIServiceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		// Technically this controller owns the derived Services rather than the ServiceImports.
		// However we operate on the ServiceImport (and ServiceExport) name rather than
		// the derived service name so we say that we own ServiceImport here
		// and always derive the name in the Reconcile function anyway.
		Named("ServiceMCSAPI").
		For(&mcsapiv1alpha1.ServiceImport{}).
		// Watch for changes to ServiceExport
		Watches(&mcsapiv1alpha1.ServiceExport{}, &handler.EnqueueRequestForObject{}).
		// Watch for changes to Services
		Watches(&corev1.Service{}, handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []ctrl.Request {
			svcImportOwner := getOwnerReferenceName(obj.GetOwnerReferences(), mcsapiv1alpha1.GroupVersion.String(), mcsapiv1alpha1.ServiceImportKindName)
			if svcImportOwner == "" {
				return []ctrl.Request{{NamespacedName: types.NamespacedName{
					Name: obj.GetName(), Namespace: obj.GetNamespace(),
				}}}
			}
			return []ctrl.Request{{NamespacedName: types.NamespacedName{
				Name: svcImportOwner, Namespace: obj.GetNamespace(),
			}}}
		})).
		Complete(r)
}
