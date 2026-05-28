// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package routechecks

import (
	"context"
	"fmt"
	"log/slog"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

type ListenerOwner interface {
	GetListeners() []gatewayv1.Listener
	GetNamespace() string
}

type GatewayListenerOwner struct {
	*gatewayv1.Gateway
}

func (g *GatewayListenerOwner) GetListeners() []gatewayv1.Listener {
	return g.Spec.Listeners
}

type ListenerSetListenerOwner struct {
	Listeners []gatewayv1.Listener
	Namespace string
}

func (l *ListenerSetListenerOwner) GetListeners() []gatewayv1.Listener {
	return l.Listeners
}

func (l *ListenerSetListenerOwner) GetNamespace() string {
	return l.Namespace
}

func ResolveListenerOwner(
	ctx context.Context,
	c client.Client,
	parent gatewayv1.ParentReference,
	defaultNamespace string,
) (ListenerOwner, error) {
	ns := helpers.NamespaceDerefOr(parent.Namespace, defaultNamespace)

	if helpers.IsListenerSet(parent) {
		ls := &gatewayv1.ListenerSet{}
		if err := c.Get(ctx, client.ObjectKey{Namespace: ns, Name: string(parent.Name)}, ls); err != nil {
			if !k8serrors.IsNotFound(err) {
				return nil, fmt.Errorf("error while getting listenerset: %w", err)
			}
			return nil, fmt.Errorf("listenerset %q does not exist: %w", parent.Name, err)
		}

		listeners := make([]gatewayv1.Listener, 0, len(ls.Spec.Listeners))
		for _, entry := range ls.Spec.Listeners {
			listeners = append(listeners, helpers.ListenerEntryToListener(entry))
		}
		return &ListenerSetListenerOwner{
			Listeners: listeners,
			Namespace: ls.GetNamespace(),
		}, nil
	}

	gw := &gatewayv1.Gateway{}
	if err := c.Get(ctx, client.ObjectKey{Namespace: ns, Name: string(parent.Name)}, gw); err != nil {
		if !k8serrors.IsNotFound(err) {
			return nil, fmt.Errorf("error while getting gateway: %w", err)
		}
		return nil, fmt.Errorf("gateway %q does not exist: %w", parent.Name, err)
	}
	return &GatewayListenerOwner{Gateway: gw}, nil
}

// GenericRule exposes rule fields shared by all supported Gateway API route kinds.
type GenericRule interface {
	GetBackendRefs() []gatewayv1.BackendRef
}

// extensionRefRule is implemented by route rules that support Gateway API ExtensionRef filters.
type extensionRefRule interface {
	GetExtensionRefs() []gatewayv1.LocalObjectReference
}

// ExtensionRefInput is implemented by route inputs that support ExtensionRef filter resolution
// (i.e. HTTP and gRPC routes). L4 routes (TLS/TCP/UDP) do not implement this interface.
type ExtensionRefInput interface {
	GetExtensionRefFilters() []v2alpha1.CiliumEnvoyExtProcFilter
	GetExtensionRefFiltersEnabled() bool
}

type Input interface {
	GetRules() []GenericRule
	GetNamespace() string
	GetClient() client.Client
	GetContext() context.Context
	GetGVK() schema.GroupVersionKind
	GetGrants() []gatewayv1.ReferenceGrant
	GetListenerOwner(parent gatewayv1.ParentReference) (ListenerOwner, error)
	GetParentGammaService(parent gatewayv1.ParentReference) (*corev1.Service, error)
	GetHostnames() []gatewayv1.Hostname
	GetValidProtocols() []gatewayv1.ProtocolType

	SetParentCondition(ref gatewayv1.ParentReference, condition metav1.Condition)
	Log() *slog.Logger
}

type (
	CheckWithParentFunc func(input Input, ref gatewayv1.ParentReference) (bool, error)
)
