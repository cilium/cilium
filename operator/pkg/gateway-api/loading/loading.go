// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loading

import (
	"context"
	"fmt"
	"log/slog"
	"sort"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	corev1 "k8s.io/api/core/v1"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrl "sigs.k8s.io/controller-runtime/pkg/manager"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	mcsapiv1beta1 "sigs.k8s.io/mcs-api/pkg/apis/v1beta1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/operator/pkg/gateway-api/indexers"
	"github.com/cilium/cilium/operator/pkg/model"
	"github.com/cilium/cilium/operator/pkg/model/ingestion"
	ciliumv2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

type TranslationInputs struct {
	GatewayClass         gatewayv1.GatewayClass
	GatewayClassConfig   *ciliumv2alpha1.CiliumGatewayClassConfig
	MergedListeners      []ingestion.ListenerWithContext
	AttachedListenerSets []gatewayv1.ListenerSet
	HTTPRoutes           []gatewayv1.HTTPRoute
	TLSRoutes            []gatewayv1.TLSRoute
	GRPCRoutes           []gatewayv1.GRPCRoute
	TCPRoutes            []gatewayv1.TCPRoute
	UDPRoutes            []gatewayv1.UDPRoute
	ReferenceGrants      []gatewayv1.ReferenceGrant
	Namespaces           []corev1.Namespace
	BackendTLSPolicies   []gatewayv1.BackendTLSPolicy
	Services             []corev1.Service
	ServiceImports       []mcsapiv1beta1.ServiceImport
}

const lastTransitionTimeField = "LastTransitionTime"

type TranslationInputLoaderConfig struct {
	IncludeTCPRoutes      bool
	IncludeUDPRoutes      bool
	IncludeServiceImports bool
	IncludeListenerSets   bool
}

type TranslationInputLoader struct {
	client         client.Client
	logger         *slog.Logger
	controllerName string
	config         TranslationInputLoaderConfig
}

func NewTranslationInputLoader(client client.Client, logger *slog.Logger, controllerName string, config TranslationInputLoaderConfig) *TranslationInputLoader {
	return &TranslationInputLoader{
		client:         client,
		logger:         logger,
		controllerName: controllerName,
		config:         config,
	}
}

func (l *TranslationInputLoader) SetupIndexes(mgr ctrl.Manager) error {
	for indexName, indexerFunc := range map[string]client.IndexerFunc{
		indexers.BackendServiceHTTPRouteIndex: indexers.GenerateIndexerHTTPRouteByBackendService(l.client, l.logger),
		indexers.GatewayHTTPRouteIndex:        indexers.IndexHTTPRouteByGateway,
	} {
		if err := mgr.GetFieldIndexer().IndexField(context.Background(), &gatewayv1.HTTPRoute{}, indexName, indexerFunc); err != nil {
			return fmt.Errorf("failed to setup field indexer %q: %w", indexName, err)
		}
	}

	if l.config.IncludeServiceImports {
		if err := mgr.GetFieldIndexer().IndexField(context.Background(), &gatewayv1.HTTPRoute{}, indexers.BackendServiceImportHTTPRouteIndex, indexers.IndexHTTPRouteByBackendServiceImport); err != nil {
			return fmt.Errorf("failed to setup field indexer %q: %w", indexers.BackendServiceImportHTTPRouteIndex, err)
		}
		if err := mgr.GetFieldIndexer().IndexField(context.Background(), &gatewayv1.GRPCRoute{}, indexers.BackendServiceImportGRPCRouteIndex, indexers.IndexGRPCRouteByBackendServiceImport); err != nil {
			return fmt.Errorf("failed to setup field indexer %q: %w", indexers.BackendServiceImportGRPCRouteIndex, err)
		}
		if err := mgr.GetFieldIndexer().IndexField(context.Background(), &gatewayv1.TLSRoute{}, indexers.BackendServiceImportTLSRouteIndex, indexers.IndexTLSRouteByBackendServiceImport); err != nil {
			return fmt.Errorf("failed to setup field indexer %q: %w", indexers.BackendServiceImportTLSRouteIndex, err)
		}
		if l.config.IncludeTCPRoutes {
			if err := mgr.GetFieldIndexer().IndexField(context.Background(), &gatewayv1.TCPRoute{}, indexers.BackendServiceImportTCPRouteIndex, indexers.IndexTCPRouteByBackendServiceImport); err != nil {
				return fmt.Errorf("failed to setup field indexer %q: %w", indexers.BackendServiceImportTCPRouteIndex, err)
			}
		}
		if l.config.IncludeUDPRoutes {
			if err := mgr.GetFieldIndexer().IndexField(context.Background(), &gatewayv1.UDPRoute{}, indexers.BackendServiceImportUDPRouteIndex, indexers.IndexUDPRouteByBackendServiceImport); err != nil {
				return fmt.Errorf("failed to setup field indexer %q: %w", indexers.BackendServiceImportUDPRouteIndex, err)
			}
		}
	}

	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &gatewayv1.Gateway{}, indexers.ImplementationGatewayIndex, indexers.GenerateIndexerGatewayByImplementation(l.client, gatewayv1.GatewayController(l.controllerName))); err != nil {
		return fmt.Errorf("failed to setup field indexer %q: %w", indexers.ImplementationGatewayIndex, err)
	}

	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &gatewayv1.Gateway{}, helpers.GatewaySecretIndex, indexers.IndexGatewayBySecret); err != nil {
		return fmt.Errorf("failed to setup field indexer %q: %w", helpers.GatewaySecretIndex, err)
	}

	for indexName, indexerFunc := range map[string]client.IndexerFunc{
		indexers.BackendServiceTLSRouteIndex: indexers.GenerateIndexerTLSRoutebyBackendService(l.client, l.logger),
		indexers.GatewayTLSRouteIndex:        indexers.IndexTLSRouteByGateway,
	} {
		if err := mgr.GetFieldIndexer().IndexField(context.Background(), &gatewayv1.TLSRoute{}, indexName, indexerFunc); err != nil {
			return fmt.Errorf("failed to setup field indexer %q: %w", indexName, err)
		}
	}

	if l.config.IncludeTCPRoutes {
		for indexName, indexerFunc := range map[string]client.IndexerFunc{
			indexers.BackendServiceTCPRouteIndex: indexers.GenerateIndexerTCPRoutebyBackendService(l.client, l.logger),
			indexers.GatewayTCPRouteIndex:        indexers.IndexTCPRouteByGateway,
		} {
			if err := mgr.GetFieldIndexer().IndexField(context.Background(), &gatewayv1.TCPRoute{}, indexName, indexerFunc); err != nil {
				return fmt.Errorf("failed to setup field indexer %q: %w", indexName, err)
			}
		}
	}

	if l.config.IncludeUDPRoutes {
		for indexName, indexerFunc := range map[string]client.IndexerFunc{
			indexers.BackendServiceUDPRouteIndex: indexers.GenerateIndexerUDPRoutebyBackendService(l.client, l.logger),
			indexers.GatewayUDPRouteIndex:        indexers.IndexUDPRouteByGateway,
		} {
			if err := mgr.GetFieldIndexer().IndexField(context.Background(), &gatewayv1.UDPRoute{}, indexName, indexerFunc); err != nil {
				return fmt.Errorf("failed to setup field indexer %q: %w", indexName, err)
			}
		}
	}

	for indexName, indexerFunc := range map[string]client.IndexerFunc{
		indexers.BackendServiceGRPCRouteIndex: indexers.GenerateIndexerGRPCRoutebyBackendService(l.client, l.logger),
		indexers.GatewayGRPCRouteIndex:        indexers.IndexGRPCRouteByGateway,
	} {
		if err := mgr.GetFieldIndexer().IndexField(context.Background(), &gatewayv1.GRPCRoute{}, indexName, indexerFunc); err != nil {
			return fmt.Errorf("failed to setup field indexer %q: %w", indexName, err)
		}
	}

	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &gatewayv1.BackendTLSPolicy{}, indexers.BackendTLSPolicyConfigMapIndex, indexers.IndexBTLSPolicyByConfigMap); err != nil {
		return fmt.Errorf("failed to setup field indexer %q: %w", indexers.BackendTLSPolicyConfigMapIndex, err)
	}

	if l.config.IncludeListenerSets {
		if err := mgr.GetFieldIndexer().IndexField(context.Background(), &gatewayv1.ListenerSet{}, indexers.ListenerSetGatewayIndex, indexers.IndexListenerSetByGateway); err != nil {
			return fmt.Errorf("failed to setup field indexer %q: %w", indexers.ListenerSetGatewayIndex, err)
		}
		if err := mgr.GetFieldIndexer().IndexField(context.Background(), &gatewayv1.ListenerSet{}, helpers.ListenerSetSecretIndex, indexers.IndexListenerSetBySecret); err != nil {
			return fmt.Errorf("failed to setup field indexer %q: %w", helpers.ListenerSetSecretIndex, err)
		}
		if err := mgr.GetFieldIndexer().IndexField(context.Background(), &gatewayv1.HTTPRoute{}, indexers.HTTPRouteListenerSetIndex, indexers.IndexHTTPRouteByListenerSet); err != nil {
			return fmt.Errorf("failed to setup field indexer %q: %w", indexers.HTTPRouteListenerSetIndex, err)
		}
		if err := mgr.GetFieldIndexer().IndexField(context.Background(), &gatewayv1.GRPCRoute{}, indexers.GRPCRouteListenerSetIndex, indexers.IndexGRPCRouteByListenerSet); err != nil {
			return fmt.Errorf("failed to setup field indexer %q: %w", indexers.GRPCRouteListenerSetIndex, err)
		}
		if err := mgr.GetFieldIndexer().IndexField(context.Background(), &gatewayv1.TLSRoute{}, indexers.TLSRouteListenerSetIndex, indexers.IndexTLSRouteByListenerSet); err != nil {
			return fmt.Errorf("failed to setup field indexer %q: %w", indexers.TLSRouteListenerSetIndex, err)
		}
		if l.config.IncludeTCPRoutes {
			if err := mgr.GetFieldIndexer().IndexField(context.Background(), &gatewayv1.TCPRoute{}, indexers.TCPRouteListenerSetIndex, indexers.IndexTCPRouteByListenerSet); err != nil {
				return fmt.Errorf("failed to setup field indexer %q: %w", indexers.TCPRouteListenerSetIndex, err)
			}
		}
		if l.config.IncludeUDPRoutes {
			if err := mgr.GetFieldIndexer().IndexField(context.Background(), &gatewayv1.UDPRoute{}, indexers.UDPRouteListenerSetIndex, indexers.IndexUDPRouteByListenerSet); err != nil {
				return fmt.Errorf("failed to setup field indexer %q: %w", indexers.UDPRouteListenerSetIndex, err)
			}
		}
	}

	return nil
}

func (l *TranslationInputLoader) Load(ctx context.Context, scopedLog *slog.Logger, gw *gatewayv1.Gateway, gatewayClass *gatewayv1.GatewayClass) (TranslationInputs, error) {
	gatewayClassConfig := l.getGatewayClassConfig(ctx, gatewayClass)

	httpRouteList := &gatewayv1.HTTPRouteList{}
	if err := l.client.List(ctx, httpRouteList, &client.ListOptions{
		FieldSelector: fields.OneTermEqualSelector(indexers.GatewayHTTPRouteIndex, client.ObjectKeyFromObject(gw).String()),
	}); err != nil {
		return TranslationInputs{}, fmt.Errorf("failed to list HTTPRoutes: %w", err)
	}

	grpcRouteList := &gatewayv1.GRPCRouteList{}
	if err := l.client.List(ctx, grpcRouteList, &client.ListOptions{
		FieldSelector: fields.OneTermEqualSelector(indexers.GatewayGRPCRouteIndex, client.ObjectKeyFromObject(gw).String()),
	}); err != nil {
		return TranslationInputs{}, fmt.Errorf("failed to list GRPCRoutes: %w", err)
	}

	tlsRouteList := &gatewayv1.TLSRouteList{}
	if err := l.client.List(ctx, tlsRouteList, &client.ListOptions{
		FieldSelector: fields.OneTermEqualSelector(indexers.GatewayTLSRouteIndex, client.ObjectKeyFromObject(gw).String()),
	}); err != nil {
		return TranslationInputs{}, fmt.Errorf("failed to list TLSRoutes: %w", err)
	}

	tcpRouteList := &gatewayv1.TCPRouteList{}
	if l.config.IncludeTCPRoutes {
		if err := l.client.List(ctx, tcpRouteList, &client.ListOptions{
			FieldSelector: fields.OneTermEqualSelector(indexers.GatewayTCPRouteIndex, client.ObjectKeyFromObject(gw).String()),
		}); err != nil {
			return TranslationInputs{}, fmt.Errorf("failed to list TCPRoutes: %w", err)
		}
	}

	udpRouteList := &gatewayv1.UDPRouteList{}
	if l.config.IncludeUDPRoutes {
		if err := l.client.List(ctx, udpRouteList, &client.ListOptions{
			FieldSelector: fields.OneTermEqualSelector(indexers.GatewayUDPRouteIndex, client.ObjectKeyFromObject(gw).String()),
		}); err != nil {
			return TranslationInputs{}, fmt.Errorf("failed to list UDPRoutes: %w", err)
		}
	}

	mergedListeners := l.resolveAllowedListenersFromGateway(ctx, scopedLog, gw)
	var attachedListenerSets []gatewayv1.ListenerSet
	if l.config.IncludeListenerSets {
		listenerSets, err := l.listenerSetsForGateway(ctx, gw)
		if err != nil {
			return TranslationInputs{}, err
		}
		attachedListenerSets = l.filterToAllowedListenerSets(ctx, scopedLog, gw, listenerSets)
		mergedListeners = append(mergedListeners, l.resolveAllowedListenersFromListenerSets(ctx, scopedLog, attachedListenerSets)...)

		for _, ls := range attachedListenerSets {
			lsKey := client.ObjectKeyFromObject(&ls).String()
			if err := l.appendListenerSetRoutes(ctx, &ls, lsKey, httpRouteList, grpcRouteList, tlsRouteList, tcpRouteList, udpRouteList); err != nil {
				return TranslationInputs{}, err
			}
		}

		httpRouteList.Items = deduplicateHTTPRoutes(httpRouteList.Items)
		grpcRouteList.Items = deduplicateGRPCRoutes(grpcRouteList.Items)
		tlsRouteList.Items = deduplicateTLSRoutes(tlsRouteList.Items)
		tcpRouteList.Items = deduplicateTCPRoutes(tcpRouteList.Items)
		udpRouteList.Items = deduplicateUDPRoutes(udpRouteList.Items)
	}

	btlspList := &gatewayv1.BackendTLSPolicyList{}
	if err := l.client.List(ctx, btlspList); err != nil {
		return TranslationInputs{}, fmt.Errorf("failed to list BackendTLSPolicies: %w", err)
	}

	var namespaces []corev1.Namespace
	if hasAllowedRoutesNamespaceSelector(gw, attachedListenerSets) {
		namespaceList := &corev1.NamespaceList{}
		if err := l.client.List(ctx, namespaceList); err != nil {
			return TranslationInputs{}, fmt.Errorf("failed to list Namespaces: %w", err)
		}
		namespaces = namespaceList.Items
	}

	servicesList := &corev1.ServiceList{}
	if err := l.client.List(ctx, servicesList); err != nil {
		return TranslationInputs{}, fmt.Errorf("failed to list Services: %w", err)
	}

	serviceImportsList := &mcsapiv1beta1.ServiceImportList{}
	if l.config.IncludeServiceImports {
		if err := l.client.List(ctx, serviceImportsList); err != nil {
			return TranslationInputs{}, fmt.Errorf("failed to list ServiceImports: %w", err)
		}
	}

	grants := &gatewayv1.ReferenceGrantList{}
	if err := l.client.List(ctx, grants); err != nil {
		return TranslationInputs{}, fmt.Errorf("failed to list ReferenceGrants: %w", err)
	}

	return TranslationInputs{
		GatewayClass:         *gatewayClass,
		GatewayClassConfig:   gatewayClassConfig,
		MergedListeners:      mergedListeners,
		AttachedListenerSets: attachedListenerSets,
		HTTPRoutes:           httpRouteList.Items,
		TLSRoutes:            tlsRouteList.Items,
		GRPCRoutes:           grpcRouteList.Items,
		TCPRoutes:            tcpRouteList.Items,
		UDPRoutes:            udpRouteList.Items,
		ReferenceGrants:      grants.Items,
		Namespaces:           namespaces,
		BackendTLSPolicies:   btlspList.Items,
		Services:             servicesList.Items,
		ServiceImports:       serviceImportsList.Items,
	}, nil
}

func (l *TranslationInputLoader) appendListenerSetRoutes(
	ctx context.Context,
	ls *gatewayv1.ListenerSet,
	lsKey string,
	httpRouteList *gatewayv1.HTTPRouteList,
	grpcRouteList *gatewayv1.GRPCRouteList,
	tlsRouteList *gatewayv1.TLSRouteList,
	tcpRouteList *gatewayv1.TCPRouteList,
	udpRouteList *gatewayv1.UDPRouteList,
) error {
	lsHTTPRoutes := &gatewayv1.HTTPRouteList{}
	if err := l.client.List(ctx, lsHTTPRoutes, &client.ListOptions{
		FieldSelector: fields.OneTermEqualSelector(indexers.HTTPRouteListenerSetIndex, lsKey),
	}); err != nil {
		return fmt.Errorf("failed to list HTTPRoutes for ListenerSet %s/%s: %w", ls.Namespace, ls.Name, err)
	}
	httpRouteList.Items = append(httpRouteList.Items, lsHTTPRoutes.Items...)

	lsGRPCRoutes := &gatewayv1.GRPCRouteList{}
	if err := l.client.List(ctx, lsGRPCRoutes, &client.ListOptions{
		FieldSelector: fields.OneTermEqualSelector(indexers.GRPCRouteListenerSetIndex, lsKey),
	}); err != nil {
		return fmt.Errorf("failed to list GRPCRoutes for ListenerSet %s/%s: %w", ls.Namespace, ls.Name, err)
	}
	grpcRouteList.Items = append(grpcRouteList.Items, lsGRPCRoutes.Items...)

	lsTLSRoutes := &gatewayv1.TLSRouteList{}
	if err := l.client.List(ctx, lsTLSRoutes, &client.ListOptions{
		FieldSelector: fields.OneTermEqualSelector(indexers.TLSRouteListenerSetIndex, lsKey),
	}); err != nil {
		return fmt.Errorf("failed to list TLSRoutes for ListenerSet %s/%s: %w", ls.Namespace, ls.Name, err)
	}
	tlsRouteList.Items = append(tlsRouteList.Items, lsTLSRoutes.Items...)

	if l.config.IncludeTCPRoutes {
		lsTCPRoutes := &gatewayv1.TCPRouteList{}
		if err := l.client.List(ctx, lsTCPRoutes, &client.ListOptions{
			FieldSelector: fields.OneTermEqualSelector(indexers.TCPRouteListenerSetIndex, lsKey),
		}); err != nil {
			return fmt.Errorf("failed to list TCPRoutes for ListenerSet %s/%s: %w", ls.Namespace, ls.Name, err)
		}
		tcpRouteList.Items = append(tcpRouteList.Items, lsTCPRoutes.Items...)
	}

	if l.config.IncludeUDPRoutes {
		lsUDPRoutes := &gatewayv1.UDPRouteList{}
		if err := l.client.List(ctx, lsUDPRoutes, &client.ListOptions{
			FieldSelector: fields.OneTermEqualSelector(indexers.UDPRouteListenerSetIndex, lsKey),
		}); err != nil {
			return fmt.Errorf("failed to list UDPRoutes for ListenerSet %s/%s: %w", ls.Namespace, ls.Name, err)
		}
		udpRouteList.Items = append(udpRouteList.Items, lsUDPRoutes.Items...)
	}

	return nil
}

func (l *TranslationInputLoader) getGatewayClassConfig(ctx context.Context, gwc *gatewayv1.GatewayClass) *ciliumv2alpha1.CiliumGatewayClassConfig {
	if gwc.Spec.ParametersRef == nil ||
		gwc.Spec.ParametersRef.Group != ciliumv2alpha1.CustomResourceDefinitionGroup ||
		gwc.Spec.ParametersRef.Kind != ciliumv2alpha1.CGCCKindDefinition ||
		gwc.Spec.ParametersRef.Namespace == nil {
		return nil
	}

	res := &ciliumv2alpha1.CiliumGatewayClassConfig{}
	if err := l.client.Get(ctx, client.ObjectKey{
		Namespace: string(*gwc.Spec.ParametersRef.Namespace),
		Name:      gwc.Spec.ParametersRef.Name,
	}, res); err != nil {
		return nil
	}

	return res
}

func (l *TranslationInputLoader) resolveAllowedListenersFromGateway(ctx context.Context, scopedLog *slog.Logger, gw *gatewayv1.Gateway) []ingestion.ListenerWithContext {
	gwSource := gatewayFQR(gw)

	var listeners []ingestion.ListenerWithContext
	for _, listener := range gw.Spec.Listeners {
		listeners = append(listeners, ingestion.ListenerWithContext{
			Listener:          listener,
			Source:            gwSource,
			SourceGeneration:  gw.Generation,
			AllowedNamespaces: resolveAllowedNamespaces(ctx, l.client, gw.GetNamespace(), listener, scopedLog),
		})
	}

	return listeners
}

func (l *TranslationInputLoader) resolveAllowedListenersFromListenerSets(
	ctx context.Context,
	scopedLog *slog.Logger,
	listenerSets []gatewayv1.ListenerSet,
) []ingestion.ListenerWithContext {
	var merged []ingestion.ListenerWithContext
	for i := range listenerSets {
		ls := &listenerSets[i]
		lsSource := listenerSetFQR(ls)
		for _, entry := range ls.Spec.Listeners {
			listener := helpers.ListenerEntryToListener(entry)
			merged = append(merged, ingestion.ListenerWithContext{
				Listener:          listener,
				Source:            lsSource,
				SourceGeneration:  ls.Generation,
				AllowedNamespaces: resolveAllowedNamespaces(ctx, l.client, ls.GetNamespace(), listener, scopedLog),
			})
		}
	}

	return merged
}

func (l *TranslationInputLoader) listenerSetsForGateway(
	ctx context.Context,
	gw *gatewayv1.Gateway,
) ([]gatewayv1.ListenerSet, error) {
	lsList := &gatewayv1.ListenerSetList{}
	if err := l.client.List(ctx, lsList, &client.ListOptions{
		FieldSelector: fields.OneTermEqualSelector(indexers.ListenerSetGatewayIndex, client.ObjectKeyFromObject(gw).String()),
	}); err != nil {
		return nil, fmt.Errorf("failed to list ListenerSets: %w", err)
	}

	sortListenerSets(lsList.Items)
	return lsList.Items, nil
}

func (l *TranslationInputLoader) filterToAllowedListenerSets(
	ctx context.Context,
	scopedLog *slog.Logger,
	gw *gatewayv1.Gateway,
	listenerSets []gatewayv1.ListenerSet,
) []gatewayv1.ListenerSet {
	var attachedSets []gatewayv1.ListenerSet
	for i := range listenerSets {
		ls := &listenerSets[i]
		if !isListenerSetAllowed(ctx, l.client, gw, ls, scopedLog) {
			if err := l.updateDisallowedListenerSetStatus(ctx, ls); err != nil {
				scopedLog.ErrorContext(ctx, "Unable to update ListenerSet status", logfields.Error, err)
			}
			continue
		}

		attachedSets = append(attachedSets, *ls)
	}

	return attachedSets
}

func isListenerSetAllowed(
	ctx context.Context,
	c client.Client,
	gw *gatewayv1.Gateway,
	ls *gatewayv1.ListenerSet,
	logger *slog.Logger,
) bool {
	if gw.Spec.AllowedListeners == nil {
		return false
	}
	ns := gw.Spec.AllowedListeners.Namespaces
	if ns == nil || ns.From == nil {
		return false
	}
	switch *ns.From {
	case gatewayv1.NamespacesFromNone:
		return false
	case gatewayv1.NamespacesFromAll:
		return true
	case gatewayv1.NamespacesFromSame:
		return ls.GetNamespace() == gw.GetNamespace()
	case gatewayv1.NamespacesFromSelector:
		nsList := &corev1.NamespaceList{}
		selector, err := metav1.LabelSelectorAsSelector(ns.Selector)
		if err != nil {
			logger.ErrorContext(ctx, "Unable to parse namespace selector", logfields.Error, err)
			return false
		}
		if err := c.List(ctx, nsList, client.MatchingLabelsSelector{Selector: selector}); err != nil {
			logger.ErrorContext(ctx, "Unable to list namespaces", logfields.Error, err)
			return false
		}
		for _, n := range nsList.Items {
			if n.Name == ls.GetNamespace() {
				return true
			}
		}
	}
	return false
}

func gatewayFQR(gw *gatewayv1.Gateway) model.FullyQualifiedResource {
	return model.FullyQualifiedResource{
		Name:      gw.GetName(),
		Namespace: gw.GetNamespace(),
		Group:     gatewayv1.SchemeGroupVersion.Group,
		Version:   gatewayv1.SchemeGroupVersion.Version,
		Kind:      "Gateway",
		UID:       string(gw.GetUID()),
	}
}

func listenerSetFQR(ls *gatewayv1.ListenerSet) model.FullyQualifiedResource {
	return model.FullyQualifiedResource{
		Name:      ls.GetName(),
		Namespace: ls.GetNamespace(),
		Group:     gatewayv1.SchemeGroupVersion.Group,
		Version:   gatewayv1.SchemeGroupVersion.Version,
		Kind:      "ListenerSet",
		UID:       string(ls.GetUID()),
	}
}

func sortListenerSets(sets []gatewayv1.ListenerSet) {
	sort.Slice(sets, func(i, j int) bool {
		ti := sets[i].CreationTimestamp.Time
		tj := sets[j].CreationTimestamp.Time
		if !ti.Equal(tj) {
			return ti.Before(tj)
		}
		ni := sets[i].GetNamespace() + "/" + sets[i].GetName()
		nj := sets[j].GetNamespace() + "/" + sets[j].GetName()
		return ni < nj
	})
}

func hasAllowedRoutesNamespaceSelector(gw *gatewayv1.Gateway, attachedListenerSets []gatewayv1.ListenerSet) bool {
	for _, listener := range gw.Spec.Listeners {
		if listener.AllowedRoutes == nil || listener.AllowedRoutes.Namespaces == nil {
			continue
		}
		if listener.AllowedRoutes.Namespaces.From != nil && *listener.AllowedRoutes.Namespaces.From == gatewayv1.NamespacesFromSelector {
			return true
		}
		if listener.AllowedRoutes.Namespaces.From == nil && listener.AllowedRoutes.Namespaces.Selector != nil {
			return true
		}
	}
	for _, ls := range attachedListenerSets {
		for _, entry := range ls.Spec.Listeners {
			listener := helpers.ListenerEntryToListener(entry)
			if listener.AllowedRoutes == nil || listener.AllowedRoutes.Namespaces == nil {
				continue
			}
			if listener.AllowedRoutes.Namespaces.From != nil && *listener.AllowedRoutes.Namespaces.From == gatewayv1.NamespacesFromSelector {
				return true
			}
			if listener.AllowedRoutes.Namespaces.From == nil && listener.AllowedRoutes.Namespaces.Selector != nil {
				return true
			}
		}
	}
	return false
}

func resolveAllowedNamespaces(ctx context.Context, c client.Client, listenerNamespace string, listener gatewayv1.Listener, logger *slog.Logger) map[string]struct{} {
	if listener.AllowedRoutes == nil || listener.AllowedRoutes.Namespaces == nil || listener.AllowedRoutes.Namespaces.From == nil {
		return map[string]struct{}{listenerNamespace: {}}
	}
	switch *listener.AllowedRoutes.Namespaces.From {
	case gatewayv1.NamespacesFromAll:
		return nil
	case gatewayv1.NamespacesFromSame:
		return map[string]struct{}{listenerNamespace: {}}
	case gatewayv1.NamespacesFromSelector:
		nsList := &corev1.NamespaceList{}
		selector, _ := metav1.LabelSelectorAsSelector(listener.AllowedRoutes.Namespaces.Selector)
		if err := c.List(ctx, nsList, client.MatchingLabelsSelector{Selector: selector}); err != nil {
			logger.ErrorContext(ctx, "Unable to list namespaces for listener", logfields.Error, err)
			return map[string]struct{}{listenerNamespace: {}}
		}
		allowed := make(map[string]struct{})
		for _, ns := range nsList.Items {
			allowed[ns.Name] = struct{}{}
		}
		return allowed
	}
	return map[string]struct{}{listenerNamespace: {}}
}

func (l *TranslationInputLoader) updateDisallowedListenerSetStatus(ctx context.Context, ls *gatewayv1.ListenerSet) error {
	original := ls.DeepCopy()

	setListenerSetAccepted(ls, false, "ListenerSet is not allowed by the Gateway's allowedListeners policy", gatewayv1.ListenerSetReasonNotAllowed)
	setListenerSetProgrammed(ls, false, "ListenerSet is not allowed by the Gateway's allowedListeners policy", gatewayv1.ListenerSetReasonNotAllowed)

	if cmp.Equal(original.Status, ls.Status, cmpopts.IgnoreFields(metav1.Condition{}, lastTransitionTimeField)) {
		return nil
	}

	return l.client.Status().Update(ctx, ls)
}

func setListenerSetAccepted(ls *gatewayv1.ListenerSet, accepted bool, msg string, reason gatewayv1.ListenerSetConditionReason) {
	status := metav1.ConditionTrue
	if !accepted {
		status = metav1.ConditionFalse
	}

	apimeta.SetStatusCondition(&ls.Status.Conditions, metav1.Condition{
		Type:               string(gatewayv1.ListenerSetConditionAccepted),
		Status:             status,
		Reason:             string(reason),
		Message:            msg,
		ObservedGeneration: ls.GetGeneration(),
		LastTransitionTime: metav1.NewTime(time.Now()),
	})
}

func setListenerSetProgrammed(ls *gatewayv1.ListenerSet, programmed bool, msg string, reason gatewayv1.ListenerSetConditionReason) {
	status := metav1.ConditionTrue
	if !programmed {
		status = metav1.ConditionFalse
	}

	apimeta.SetStatusCondition(&ls.Status.Conditions, metav1.Condition{
		Type:               string(gatewayv1.ListenerSetConditionProgrammed),
		Status:             status,
		Reason:             string(reason),
		Message:            msg,
		ObservedGeneration: ls.GetGeneration(),
		LastTransitionTime: metav1.NewTime(time.Now()),
	})
}

func deduplicateHTTPRoutes(routes []gatewayv1.HTTPRoute) []gatewayv1.HTTPRoute {
	seen := make(map[types.NamespacedName]struct{}, len(routes))
	result := make([]gatewayv1.HTTPRoute, 0, len(routes))
	for _, route := range routes {
		key := types.NamespacedName{Namespace: route.Namespace, Name: route.Name}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, route)
	}
	return result
}

func deduplicateGRPCRoutes(routes []gatewayv1.GRPCRoute) []gatewayv1.GRPCRoute {
	seen := make(map[types.NamespacedName]struct{}, len(routes))
	result := make([]gatewayv1.GRPCRoute, 0, len(routes))
	for _, route := range routes {
		key := types.NamespacedName{Namespace: route.Namespace, Name: route.Name}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, route)
	}
	return result
}

func deduplicateTLSRoutes(routes []gatewayv1.TLSRoute) []gatewayv1.TLSRoute {
	seen := make(map[types.NamespacedName]struct{}, len(routes))
	result := make([]gatewayv1.TLSRoute, 0, len(routes))
	for _, route := range routes {
		key := types.NamespacedName{Namespace: route.Namespace, Name: route.Name}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, route)
	}
	return result
}

func deduplicateTCPRoutes(routes []gatewayv1.TCPRoute) []gatewayv1.TCPRoute {
	seen := make(map[types.NamespacedName]struct{}, len(routes))
	result := make([]gatewayv1.TCPRoute, 0, len(routes))
	for _, route := range routes {
		key := types.NamespacedName{Namespace: route.Namespace, Name: route.Name}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, route)
	}
	return result
}

func deduplicateUDPRoutes(routes []gatewayv1.UDPRoute) []gatewayv1.UDPRoute {
	seen := make(map[types.NamespacedName]struct{}, len(routes))
	result := make([]gatewayv1.UDPRoute, 0, len(routes))
	for _, route := range routes {
		key := types.NamespacedName{Namespace: route.Namespace, Name: route.Name}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, route)
	}
	return result
}
