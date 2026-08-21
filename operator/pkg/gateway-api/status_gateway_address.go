// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/shortener"
)

type GatewayAddressStatusManager struct {
	client client.Client
	logger *slog.Logger
}

func NewGatewayAddressStatusManager(client client.Client, logger *slog.Logger) *GatewayAddressStatusManager {
	return &GatewayAddressStatusManager{
		client: client,
		logger: logger,
	}
}

// VerifyGatewayStaticAddresses validates spec.addresses before resource
// reconciliation continues. It only checks the requested static address shape;
// it does not look at assigned Service status.
func (m *GatewayAddressStatusManager) VerifyGatewayStaticAddresses(gw *gatewayv1.Gateway) error {
	if len(gw.Spec.Addresses) == 0 {
		return nil
	}
	for _, address := range gw.Spec.Addresses {
		if address.Type != nil && *address.Type != gatewayv1.IPAddressType {
			return fmt.Errorf("address type is not supported")
		}
		if address.Value == "" {
			return fmt.Errorf("address value is not set")
		}
		if _, err := netip.ParseAddr(address.Value); err != nil {
			return fmt.Errorf("invalid ip address")
		}
	}
	return nil
}

// SetAddressStatus reads the managed frontend Service and projects its observed
// addresses into Gateway status. When at least one usable address is present,
// it also marks the Gateway and accepted listeners as Programmed.
func (m *GatewayAddressStatusManager) SetAddressStatus(ctx context.Context, gw *gatewayv1.Gateway) error {
	m.logger.InfoContext(ctx, "Checking address status for Gateway", logfields.Resource, client.ObjectKeyFromObject(gw).String())
	svcList := &corev1.ServiceList{}
	if err := m.client.List(ctx, svcList, client.MatchingLabels{
		owningGatewayLabel: shortener.ShortenK8sResourceName(gw.GetName()),
	}, client.InNamespace(gw.GetNamespace())); err != nil {
		return err
	}

	if len(svcList.Items) == 0 {
		return fmt.Errorf("no service found")
	}
	svc := svcList.Items[0]

	var addresses []gatewayv1.GatewayStatusAddress
	// Check the svc type
	switch svc.Spec.Type {
	case corev1.ServiceTypeNodePort:
		// NodePort service gets as many Node
		// IP addresses as we can fit into Status
		nodes := &corev1.NodeList{}
		if err := m.client.List(ctx, nodes); err != nil {
			return fmt.Errorf("unable to list nodes")
		}

		ips := make([]netip.Addr, 0)
		for _, node := range nodes.Items {
			if len(node.Status.Addresses) == 0 {
				continue
			}
			nodeAddress := node.Status.Addresses[0]
			ip, err := netip.ParseAddr(nodeAddress.Address)
			if err != nil {
				// the first address is not an IP address (e.g. a hostname),
				// skip the node instead of reporting an invalid address.
				continue
			}
			ips = append(ips, ip.Unmap())
		}

		// sort the addresses for consistent ip addresses assigned
		slices.SortFunc(ips, netip.Addr.Compare)
		// allows for only a max of 16 addresses
		if len(ips) > 16 {
			ips = ips[:16]
		}
		for _, ipAddress := range ips {
			addresses = append(addresses, gatewayv1.GatewayStatusAddress{
				Type:  GatewayAddressTypePtr(gatewayv1.IPAddressType),
				Value: ipAddress.String(),
			})
		}
	case corev1.ServiceTypeLoadBalancer:
		if len(svc.Status.LoadBalancer.Ingress) == 0 {
			// Potential loadbalancer service isn't ready yet. No need to report as an error, because
			// reconciliation should be triggered when the loadbalancer services gets updated.
			return nil
		}
		for _, s := range svc.Status.LoadBalancer.Ingress {
			if len(s.IP) != 0 {
				addresses = append(addresses, gatewayv1.GatewayStatusAddress{
					Type:  GatewayAddressTypePtr(gatewayv1.IPAddressType),
					Value: s.IP,
				})
			}
			if len(s.Hostname) != 0 {
				addresses = append(addresses, gatewayv1.GatewayStatusAddress{
					Type:  GatewayAddressTypePtr(gatewayv1.HostnameAddressType),
					Value: s.Hostname,
				})
			}
		}
	default:
		return fmt.Errorf("Invalid service type for gateway")
	}

	if len(addresses) > 0 {
		m.logger.InfoContext(ctx, "At least one valid address, marking gateway programmed", logfields.Resource, client.ObjectKeyFromObject(gw).String())
		setGatewayProgrammed(gw, metav1.ConditionTrue, "Gateway Programmed", gatewayv1.GatewayReasonProgrammed)
		for i := range gw.Status.Listeners {
			l := &gw.Status.Listeners[i]
			// Is Listener Accepted?
			accepted := false

			for _, cond := range l.Conditions {
				if cond.Type == string(gatewayv1.GatewayConditionAccepted) &&
					cond.Status == metav1.ConditionTrue {
					accepted = true
					break
				}
			}
			if accepted {
				l.Conditions = merge(l.Conditions, metav1.Condition{
					Type:               string(gatewayv1.ListenerConditionProgrammed),
					Status:             metav1.ConditionTrue,
					Reason:             string(gatewayv1.ListenerReasonProgrammed),
					Message:            "Listener Programmed",
					ObservedGeneration: gw.Generation,
					LastTransitionTime: metav1.Now(),
				})
			}
		}
	}

	gw.Status.Addresses = addresses
	return nil
}

// SetStaticAddressStatus compares requested static addresses with the assigned
// load balancer ingress addresses. It is a post-reconcile check for whether
// the requested static addresses were actually satisfied.
func (m *GatewayAddressStatusManager) SetStaticAddressStatus(ctx context.Context, gw *gatewayv1.Gateway) error {
	if len(gw.Spec.Addresses) == 0 {
		return nil
	}
	svcList := &corev1.ServiceList{}
	if err := m.client.List(ctx, svcList, client.MatchingLabels{
		owningGatewayLabel: shortener.ShortenK8sResourceName(gw.GetName()),
	}, client.InNamespace(gw.GetNamespace())); err != nil {
		return err
	}

	if len(svcList.Items) == 0 {
		return fmt.Errorf("no service found")
	}

	svc := svcList.Items[0]
	if len(svc.Status.LoadBalancer.Ingress) == 0 {
		// Potential loadbalancer service isn't ready yet. No need to report as an error, because
		// reconciliation should be triggered when the loadbalancer services gets updated.
		return nil
	}

	// Compare parsed addresses because the same IP address can have multiple
	// textual representations.
	addresses := make(map[netip.Addr]struct{}, len(svc.Status.LoadBalancer.Ingress))
	for _, addr := range svc.Status.LoadBalancer.Ingress {
		ip, err := netip.ParseAddr(addr.IP)
		if err != nil {
			// Ignore hostname-only ingress entries.
			continue
		}
		addresses[ip] = struct{}{}
	}

	for _, addr := range gw.Spec.Addresses {
		ip, err := netip.ParseAddr(addr.Value)
		if err != nil {
			return fmt.Errorf("static address %q can't be used", addr.Value)
		}
		if _, ok := addresses[ip]; !ok {
			return fmt.Errorf("static address %q can't be used", addr.Value)
		}
	}

	return nil
}
