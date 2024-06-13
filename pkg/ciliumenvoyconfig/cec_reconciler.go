// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumenvoyconfig

import (
	"context"
	"errors"
	"fmt"
	"maps"

	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
)

type ciliumEnvoyConfigReconciler struct {
	logger logrus.FieldLogger

	manager ciliumEnvoyConfigManager

	mutex           lock.Mutex
	configs         map[resource.Key]*config
	localNodeLabels map[string]string
}

type config struct {
	meta metav1.ObjectMeta
	spec *ciliumv2.CiliumEnvoyConfigSpec
	// Keeping the state whether the config matched as dedicated field.
	// This is only used when checking whether an existing config selected
	// the local node. (instead of re-evaluating using the node selector)
	selectsLocalNode bool
}

func newCiliumEnvoyConfigReconciler(logger logrus.FieldLogger,
	manager ciliumEnvoyConfigManager,
) *ciliumEnvoyConfigReconciler {
	return &ciliumEnvoyConfigReconciler{
		logger:  logger,
		manager: manager,
		configs: map[resource.Key]*config{},
	}
}

func (r *ciliumEnvoyConfigReconciler) handleCECEvent(ctx context.Context, event resource.Event[*ciliumv2.CiliumEnvoyConfig]) error {
	scopedLogger := r.logger.
		WithField(logfields.K8sNamespace, event.Key.Namespace).
		WithField(logfields.CiliumEnvoyConfigName, event.Key.Name)

	var err error

	switch event.Kind {
	case resource.Upsert:
		scopedLogger.Debug("Received CiliumEnvoyConfig upsert event")
		err = r.configUpserted(ctx, event.Key, &config{meta: event.Object.ObjectMeta, spec: &event.Object.Spec})
		if err != nil {
			scopedLogger.WithError(err).Error("failed to handle CEC upsert")
			err = fmt.Errorf("failed to handle CEC upsert: %w", err)
		}
	case resource.Delete:
		scopedLogger.Debug("Received CiliumEnvoyConfig delete event")
		err = r.configDeleted(ctx, event.Key)
		if err != nil {
			scopedLogger.WithError(err).Error("failed to handle CEC delete")
			err = fmt.Errorf("failed to handle CEC delete: %w", err)
		}
	}

	event.Done(err)

	return err
}

func (r *ciliumEnvoyConfigReconciler) handleCCECEvent(ctx context.Context, event resource.Event[*ciliumv2.CiliumClusterwideEnvoyConfig]) error {
	scopedLogger := r.logger.
		WithField(logfields.K8sNamespace, event.Key.Namespace).
		WithField(logfields.CiliumClusterwideEnvoyConfigName, event.Key.Name)

	var err error

	switch event.Kind {
	case resource.Upsert:
		scopedLogger.Debug("Received CiliumClusterwideEnvoyConfig upsert event")
		err = r.configUpserted(ctx, event.Key, &config{meta: event.Object.ObjectMeta, spec: &event.Object.Spec})
		if err != nil {
			scopedLogger.WithError(err).Error("failed to handle CCEC upsert")
			err = fmt.Errorf("failed to handle CCEC upsert: %w", err)
		}
	case resource.Delete:
		scopedLogger.Debug("Received CiliumClusterwideEnvoyConfig delete event")
		err = r.configDeleted(ctx, event.Key)
		if err != nil {
			scopedLogger.WithError(err).Error("failed to handle CCEC delete")
			err = fmt.Errorf("failed to handle CCEC delete: %w", err)
		}
	}

	event.Done(err)

	return err
}

func (r *ciliumEnvoyConfigReconciler) handleLocalNodeEvent(ctx context.Context, localNode node.LocalNode) error {
	r.logger.Debug("Received LocalNode changed event")

	if err := r.handleLocalNodeLabels(ctx, localNode); err != nil {
		r.logger.WithError(err).Error("failed to handle LocalNode changed event")
		return fmt.Errorf("failed to handle LocalNode changed event: %w", err)
	}

	return nil
}

func (r *ciliumEnvoyConfigReconciler) handleLocalNodeLabels(ctx context.Context, localNode node.LocalNode) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if maps.Equal(r.localNodeLabels, localNode.Labels) {
		r.logger.Debug("Labels of local Node didn't change")
		return nil
	}

	r.localNodeLabels = localNode.Labels
	r.logger.Debug("Labels of local Node changed - updated local store")

	// Best effort attempt to reconcile existing configs as fast as possible.
	//
	// Errors are only logged and not reported. Otherwise the healthmanager state will be degraded
	// until the next label change on the node.
	// It's the responsibility of the corresponding TimerJob to perform a periodic reconciliation.
	if err := r.reconcileExistingConfigsLocked(ctx); err != nil {
		r.logger.WithError(err).Error("failed to reconcile existing configs due to changed node labels")
	}

	return nil
}

func (r *ciliumEnvoyConfigReconciler) reconcileExistingConfigs(ctx context.Context) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	return r.reconcileExistingConfigsLocked(ctx)
}

func (r *ciliumEnvoyConfigReconciler) reconcileExistingConfigsLocked(ctx context.Context) error {
	r.logger.Debug("Checking whether existing configs need to be applied or filtered")

	// Error containing all potential errors during reconciliation of the configs.
	// On error, only the reconciliation of the faulty config is skipped. All other
	// configs should be reconciled.
	var reconcileErr error

	for key, cfg := range r.configs {
		scopedLogger := r.logger.WithField("key", key)

		err := r.configUpsertedInternal(ctx, key, cfg, false /* spec didn't change */)
		if err != nil {
			scopedLogger.WithError(err).Error("failed to reconcile existing configs")
			// don't prevent reconciliation of other configs in case of an error for a particular config
			reconcileErr = errors.Join(reconcileErr, fmt.Errorf("failed to reconcile existing config (%s): %w", key, err))
			continue
		}
	}

	return reconcileErr
}

func (r *ciliumEnvoyConfigReconciler) configUpserted(ctx context.Context, key resource.Key, cfg *config) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	return r.configUpsertedInternal(ctx, key, cfg, true /* spec may have changed */)
}

func (r *ciliumEnvoyConfigReconciler) configUpsertedInternal(ctx context.Context, key resource.Key, cfg *config, specMayChanged bool) error {
	scopedLogger := r.logger.WithField("key", key)

	selectsLocalNode, err := r.configSelectsLocalNode(cfg)
	if err != nil {
		return fmt.Errorf("failed to match Node labels with config nodeselector (%s): %w", key, err)
	}

	appliedConfig, isApplied := r.configs[key]

	switch {
	case !isApplied && !selectsLocalNode:
		scopedLogger.Debug("New config doesn't select the local Node")

	case !isApplied && selectsLocalNode:
		scopedLogger.Debug("New config selects the local node - adding config")
		if err := r.manager.addCiliumEnvoyConfig(cfg.meta, cfg.spec); err != nil {
			return err
		}

	case isApplied && selectsLocalNode && !appliedConfig.selectsLocalNode:
		scopedLogger.Debug("Config now selects the local Node - adding previously filtered config")
		if err := r.manager.addCiliumEnvoyConfig(cfg.meta, cfg.spec); err != nil {
			return err
		}

	case isApplied && selectsLocalNode && appliedConfig.selectsLocalNode && specMayChanged:
		scopedLogger.Debug("Config still selects the local Node - updating applied config")
		if err := r.manager.updateCiliumEnvoyConfig(appliedConfig.meta, appliedConfig.spec, cfg.meta, cfg.spec); err != nil {
			return err
		}

	case isApplied && !selectsLocalNode && !appliedConfig.selectsLocalNode:
		scopedLogger.Debug("Config still doesn't select the local Node")

	case isApplied && !selectsLocalNode && appliedConfig.selectsLocalNode:
		scopedLogger.Debug("Config no longer selects the local Node - deleting previously applied config")
		if err := r.manager.deleteCiliumEnvoyConfig(appliedConfig.meta, appliedConfig.spec); err != nil {
			return err
		}
	}

	r.configs[key] = &config{meta: cfg.meta, spec: cfg.spec, selectsLocalNode: selectsLocalNode}

	return nil
}

func (r *ciliumEnvoyConfigReconciler) configDeleted(ctx context.Context, key resource.Key) error {
	scopedLogger := r.logger.
		WithField("key", key)

	r.mutex.Lock()
	defer r.mutex.Unlock()

	appliedConfig, isApplied := r.configs[key]

	switch {
	case !isApplied:
		scopedLogger.Warn("Deleted Envoy config has never been applied")

	case isApplied && !appliedConfig.selectsLocalNode:
		scopedLogger.Debug("Deleted CEC was already filtered by NodeSelector")

	case isApplied && appliedConfig.selectsLocalNode:
		scopedLogger.Debug("Deleting applied CEC")
		if err := r.manager.deleteCiliumEnvoyConfig(appliedConfig.meta, appliedConfig.spec); err != nil {
			return err
		}
	}

	delete(r.configs, key)

	return nil
}

func (r *ciliumEnvoyConfigReconciler) configSelectsLocalNode(cfg *config) (bool, error) {
	if cfg != nil && cfg.spec != nil && cfg.spec.NodeSelector != nil {
		ls, err := slim_metav1.LabelSelectorAsSelector(cfg.spec.NodeSelector)
		if err != nil {
			return false, fmt.Errorf("invalid NodeSelector: %w", err)
		}

		if !ls.Matches(labels.Set(r.localNodeLabels)) {
			return false, nil
		}
	}

	return true, nil
}

func (r *ciliumEnvoyConfigReconciler) syncHeadlessService(_ context.Context) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	var reconcileErr error

	for key, cfg := range r.configs {
		if err := r.manager.syncCiliumEnvoyConfigService(cfg.meta.Name, cfg.meta.Namespace, cfg.spec); err != nil {
			r.logger.WithField("key", key).WithError(err).Error("failed to sync headless service")
			reconcileErr = errors.Join(reconcileErr, fmt.Errorf("failed to reconcile existing config (%s): %w", key, err))
			continue
		}
	}

	return reconcileErr
}
