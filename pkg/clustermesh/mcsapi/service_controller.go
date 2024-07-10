// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mcsapi

import (
	"context"
	"crypto/sha256"
	"encoding/base32"
	"maps"
	"strings"

	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	k8sApiErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	mcsapiv1alpha1 "sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"
	mcsapicontrollers "sigs.k8s.io/mcs-api/pkg/controllers"

	controllerruntime "github.com/cilium/cilium/operator/pkg/controller-runtime"
	"github.com/cilium/cilium/pkg/annotation"
)

const (
	kindServiceImport = "ServiceImport"
	kindServiceExport = "ServiceExport"
)

// mcsAPIServiceReconciler is a controller that creates a derived service from
// a ServiceImport and ServiceExport objects. The derived Service is created
// with the Cilium annotations to mark it as a global Service so that we can
// take advantage of the existing clustermesh features for the MCS API Support.
type mcsAPIServiceReconciler struct {
	client.Client
	Logger logrus.FieldLogger

	clusterName string
}

func newMCSAPIServiceReconciler(mgr ctrl.Manager, logger logrus.FieldLogger, clusterName string) *mcsAPIServiceReconciler {
	return &mcsAPIServiceReconciler{
		Client:      mgr.GetClient(),
		Logger:      logger,
		clusterName: clusterName,
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

func getMCSAPIOwner(refs []metav1.OwnerReference) string {
	if ref := getOwnerReferenceName(refs, mcsapiv1alpha1.GroupVersion.String(), kindServiceImport); ref != "" {
		return ref
	}
	if ref := getOwnerReferenceName(refs, mcsapiv1alpha1.GroupVersion.String(), kindServiceExport); ref != "" {
		return ref
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

func addOwnerReference(svc *corev1.Service, objOwner client.Object) {
	apiVersion := objOwner.GetObjectKind().GroupVersionKind().GroupVersion().String()
	kind := objOwner.GetObjectKind().GroupVersionKind().Kind

	svc.OwnerReferences = append(svc.OwnerReferences,
		metav1.OwnerReference{
			Name:       objOwner.GetName(),
			Kind:       kind,
			APIVersion: apiVersion,
			UID:        objOwner.GetUID(),
		})
}

func (r *mcsAPIServiceReconciler) addServiceImportDerivedAnnotation(ctx context.Context, svcImport *mcsapiv1alpha1.ServiceImport, derivedServiceName string) error {
	if svcImport == nil {
		return nil
	}
	if svcImport.Annotations == nil {
		svcImport.Annotations = map[string]string{}
	}
	if svcImport.Annotations[mcsapicontrollers.DerivedServiceAnnotation] != derivedServiceName {
		svcImport.Annotations[mcsapicontrollers.DerivedServiceAnnotation] = derivedServiceName
		if err := r.Client.Update(ctx, svcImport); err != nil {
			return err
		}
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

func (r *mcsAPIServiceReconciler) getLocalService(ctx context.Context, req ctrl.Request) (*corev1.Service, error) {
	var svc corev1.Service
	if err := r.Client.Get(ctx, req.NamespacedName, &svc); err != nil {
		return nil, err
	}
	return &svc, nil
}

func (r *mcsAPIServiceReconciler) getSvcExport(ctx context.Context, req ctrl.Request) (*mcsapiv1alpha1.ServiceExport, error) {
	var svcExport mcsapiv1alpha1.ServiceExport
	if err := r.Client.Get(ctx, req.NamespacedName, &svcExport); err != nil {
		if k8sApiErrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	return &svcExport, nil
}

func (r *mcsAPIServiceReconciler) getSvcImport(ctx context.Context, req ctrl.Request) (*mcsapiv1alpha1.ServiceImport, error) {
	var svcImport mcsapiv1alpha1.ServiceImport
	if err := r.Client.Get(ctx, req.NamespacedName, &svcImport); err != nil {
		if k8sApiErrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	return &svcImport, nil
}

func (r *mcsAPIServiceReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	svcImport, err := r.getSvcImport(ctx, req)
	if err != nil {
		return controllerruntime.Fail(err)
	}
	svcExport, err := r.getSvcExport(ctx, req)
	if err != nil {
		return controllerruntime.Fail(err)
	}

	if svcExport == nil && svcImport == nil {
		return controllerruntime.Success()
	}

	derivedServiceName := derivedName(req.NamespacedName)
	svc, svcExists, err := r.getBaseDerivedService(ctx, req, derivedServiceName, svcImport)
	if err != nil {
		return controllerruntime.Fail(err)
	}

	svc.Spec.Ports = []corev1.ServicePort{}
	svc.Spec.Selector = map[string]string{}
	svc.OwnerReferences = []metav1.OwnerReference{}
	svc.Annotations = map[string]string{}
	svc.Labels = map[string]string{}

	localSvc, err := r.getLocalService(ctx, req)
	if err != nil && (!k8sApiErrors.IsNotFound(err) || svcExport != nil) {
		return controllerruntime.Fail(err)
	}

	// Copy the local Service selector to let kube-controller-manager do
	// the actual syncing of the endpoints.
	// This has the drawback that this implementation doesn't
	// support the endpoints created with the `kubernetes.io/service-name`
	// label without any pod backing them (i.e.: endpoints created manually
	// or by some third party tooling).
	if localSvc != nil {
		svc.Spec.Selector = localSvc.Spec.Selector
		svc.Spec.Ports = localSvc.Spec.Ports

		// Use the local Service on creation as reference to determine the headlessness
		// if the ServiceImport is not yet created. This allow to save a potential switch
		// from non headless to headless (which involved a deletion + recreation)
		// if there is no export conflict.
		if svcImport == nil && !svcExists && localSvc.Spec.ClusterIP == corev1.ClusterIPNone {
			svc.Spec.ClusterIP = corev1.ClusterIPNone
		}
	}

	if svcImport != nil {
		addOwnerReference(svc, svcImport)
		svc.Spec.Ports = servicePorts(svcImport)
		maps.Copy(svc.Annotations, svcImport.Annotations)
		maps.Copy(svc.Labels, svcImport.Labels)
	}

	svc.Annotations[annotation.GlobalService] = "true"
	svc.Annotations[annotation.SharedService] = "false"

	svc.Labels[mcsapiv1alpha1.LabelServiceName] = req.NamespacedName.Name
	// We set the source cluster label on the service as well so that the
	// EndpointSlices created by kube-controller-manager will also mirror that label.
	svc.Labels[mcsapiv1alpha1.LabelSourceCluster] = r.clusterName

	if svcExport != nil {
		addOwnerReference(svc, svcExport)
		svc.Annotations[annotation.SharedService] = "true"
	}

	if !svcExists {
		if err := r.Client.Create(ctx, svc); err != nil {
			return controllerruntime.Fail(err)
		}
	} else {
		if err := r.Client.Update(ctx, svc); err != nil {
			return controllerruntime.Fail(err)
		}
	}

	// Update the derived Service annotation on the ServiceImport object
	// only after that the derived Service has been created for higher consistency.
	return controllerruntime.Fail(r.addServiceImportDerivedAnnotation(ctx, svcImport, derivedServiceName))
}

// SetupWithManager sets up the controller with the Manager.
func (r *mcsAPIServiceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		// Technically this controller owns the derived Services rather than the ServiceImports.
		// However we operate on the ServiceImport (and ServiceExport) name rather than
		// the derived service name so we say that we own ServiceImport here
		// and always derive the name in the Reconcile function anyway.
		For(&mcsapiv1alpha1.ServiceImport{}).
		// Watch for changes to ServiceExport
		Watches(&mcsapiv1alpha1.ServiceExport{}, &handler.EnqueueRequestForObject{}).
		// Watch for changes to Services
		Watches(&corev1.Service{}, handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []ctrl.Request {
			mcsAPIOwner := getMCSAPIOwner(obj.GetOwnerReferences())
			if mcsAPIOwner == "" {
				return []ctrl.Request{{NamespacedName: types.NamespacedName{
					Name: obj.GetName(), Namespace: obj.GetNamespace(),
				}}}
			}
			return []ctrl.Request{{NamespacedName: types.NamespacedName{
				Name: mcsAPIOwner, Namespace: obj.GetNamespace(),
			}}}
		})).
		Complete(r)
}
