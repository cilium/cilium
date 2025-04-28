// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ingestion

import (
	"fmt"
	"log/slog"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
	"sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/operator/pkg/model"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// GammaInput is the input for GatewayAPI.
type GammaInput struct {
	HTTPRoutes      []gatewayv1.HTTPRoute
	ReferenceGrants []gatewayv1beta1.ReferenceGrant
	Services        []corev1.Service
}

// GammaHTTPRoutes takes a GammaInput and gives back the associated HTTP Listeners
// It does not support TLS Routes because GAMMA is only for cleartext config -
// it is assumed that any TLS will be performed transparently by the underlying
// implementation in the spec.
func GammaHTTPRoutes(log *slog.Logger, input GammaInput) []model.HTTPListener {
	// GAMMA processing process:
	// Process HTTPRoutes
	var resHTTP []model.HTTPListener

	// Search algorithm:
	// Loop through all HTTPRoutes in input, validate that each is parented by a
	//   svc that's also in input, in the same namespace, etc.
	// Add each parentRef service to some tracker to know if we need to create
	//   a new HTTPListener or not.
	// Add the rules from the HTTPRoute to the relevant HTTPListener.
	//   unresolved: How to order these rules?
	// ReferenceGrants are only relevant for backends, I think, because parents
	//  _can_ be across namespace boundaries, but that makes them a consumer
	// route, not a producer one.

	// Set of services that will be parents for these HTTPRoutes
	parentServices := make(map[types.NamespacedName]model.FullyQualifiedResource)

	for _, hr := range input.HTTPRoutes {
		// First, we find which parentRefs are Services, so that we can add the
		// route rules to Listeners for those Services.
		var gammaParents []gatewayv1.ParentReference
		for _, parent := range hr.Spec.ParentRefs {
			if helpers.IsGammaService(parent) {
				gammaParents = append(gammaParents, parent)
			}
		}

		// When retrieving objects from the apiserver, generally this should not
		// happen, because controller-tools should screen out HTTPRoutes with zero GAMMA parents.
		// However, if one of the watch predicates does not also check for GAMMA parents, we can end up here.
		// So this is a final safety.
		if len(gammaParents) == 0 {
			log.Debug("gamma Ingestion: No GAMMA parents found for HTTPRoute",
				logfields.ServiceNamespace, hr.Namespace,
				logfields.ServiceName, hr.Name,
			)
			continue
		}

		hrSource := model.FullyQualifiedResource{
			Name:      hr.GetName(),
			Namespace: hr.GetNamespace(),
			Group:     gatewayv1.GroupVersion.Group,
			Kind:      "HTTPRoute",
			Version:   gatewayv1.GroupVersion.Version,
			UID:       string(hr.GetUID()),
		}

		for _, gp := range gammaParents {

			if gp.Name == "" {
				continue
			}

			parentName := types.NamespacedName{
				Name: string(gp.Name),
			}

			if gp.Namespace != nil {
				parentName.Namespace = string(*gp.Namespace)
			}

			parentSvc, err := getMatchingService(parentName.Name, parentName.Namespace, hr.GetNamespace(), input.Services)
			if err != nil {
				log.Warn(
					"Can't find parent Service in input. This is a bug, please report it to the developers.",
					logfields.K8sNamespace, parentName.Namespace,
					logfields.Name, parentName.Name,
				)
				continue
			}

			if parentSvc.GetName() == "" {
				// skip processing this parent because it's not in the input.
				// This situation should not arise - there should be multiple
				// layers of protection.
				log.Warn("Can't find any parent Service in input. This is a bug, please report it to the developers.")
				continue
			}

			// Record the service as relevant if it's not already
			if _, ok := parentServices[parentName]; !ok {
				parentServices[parentName] = model.FullyQualifiedResource{
					Name:      parentSvc.GetName(),
					Namespace: parentSvc.GetNamespace(),
					Group:     corev1.GroupName,
					Kind:      "Service",
					Version:   corev1.SchemeGroupVersion.Version,
					UID:       string(parentSvc.GetUID()),
				}
			}

			// Pick which ports from the Service are relevant.
			var relevantPorts []uint32
			// If there's a Port set in the parentRef, then that's the only relevant port.
			if gp.Port != nil && *gp.Port != 0 {
				relevantPorts = append(relevantPorts, uint32(*gp.Port))
			} else {
				// Otherwise, we find ones where appProtocol is http
				for _, port := range parentSvc.Spec.Ports {
					if port.Protocol == "" || port.Protocol == "TCP" {
						// This is a little suspect, but we should only be using ones where AppProtocol is http
						// _apparently_
						if (port.AppProtocol == nil) || (port.AppProtocol != nil && *port.AppProtocol != "http") {
							continue
						}
					}

					relevantPorts = append(relevantPorts, uint32(port.Port))
				}
			}

			// We need a Listener per port on the Service that we are handling.
			for _, portVal := range relevantPorts {
				res := model.HTTPListener{}
				// Record the parent Service as the source of the Listener.
				res.Sources = append(res.Sources, parentServices[parentName])
				// Record the HTTPRoute as another Source, so that we can ensure that the CEC will get cleaned up
				// when the HTTPRoute does
				res.Sources = append(res.Sources, hrSource)
				res.Name = fmt.Sprintf("%s-%s-%d", parentSvc.GetNamespace(), parentSvc.GetName(), portVal)
				res.Port = portVal
				// GAMMA spec _explicitly_ says that we must not filter by hostname, only address and port
				res.Hostname = "*"

				res.Service = &model.Service{
					Type: string(corev1.ServiceTypeClusterIP),
				}
				res.Gamma = true
				res.Routes = append(res.Routes, extractRoutes(int32(portVal), []string{res.Hostname}, hr, input.Services, []v1alpha1.ServiceImport{}, input.ReferenceGrants)...)
				resHTTP = append(resHTTP, res)
			}

		}
	}
	return resHTTP
}

func getMatchingService(name string, parentNamespace string, hrNamespace string, services []corev1.Service) (corev1.Service, error) {
	for _, svc := range services {
		if svc.GetName() == name {
			if (parentNamespace == svc.GetNamespace()) || (parentNamespace == "" && hrNamespace == svc.GetNamespace()) {
				return svc, nil
			}
		}
	}

	return corev1.Service{}, fmt.Errorf("service not found in input")
}
