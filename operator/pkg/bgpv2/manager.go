// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bgpv2

import (
	"context"
	"errors"
	"fmt"
	"runtime/pprof"

	"github.com/sirupsen/logrus"
	k8s_errors "k8s.io/apimachinery/pkg/api/errors"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8s_client "github.com/cilium/cilium/pkg/k8s/client"
	cilium_client_v2alpha1 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

var (
	// retry options used in reconcileWithRetry method.
	// steps will repeat for ~8.5 minutes.
	bo = wait.Backoff{
		Duration: 1 * time.Second,
		Factor:   2,
		Jitter:   0,
		Steps:    10,
		Cap:      0,
	}

	// maxErrorLen is the maximum length of error message to be logged.
	maxErrorLen = 140
)

type BGPParams struct {
	cell.In

	Logger       logrus.FieldLogger
	LC           cell.Lifecycle
	Clientset    k8s_client.Clientset
	DaemonConfig *option.DaemonConfig
	JobRegistry  job.Registry
	Scope        cell.Scope
	Config       Config

	// resource tracking
	LegacyBGPResource          resource.Resource[*cilium_api_v2alpha1.CiliumBGPPeeringPolicy]
	ClusterConfigResource      resource.Resource[*cilium_api_v2alpha1.CiliumBGPClusterConfig]
	NodeConfigOverrideResource resource.Resource[*cilium_api_v2alpha1.CiliumBGPNodeConfigOverride]
	NodeConfigResource         resource.Resource[*cilium_api_v2alpha1.CiliumBGPNodeConfig]
	NodeResource               resource.Resource[*cilium_api_v2.CiliumNode]
	AdvertisementResource      resource.Resource[*cilium_api_v2alpha1.CiliumBGPAdvertisement]
	PeerConfigResource         resource.Resource[*cilium_api_v2alpha1.CiliumBGPPeerConfig]
}

type BGPResourceManager struct {
	logger    logrus.FieldLogger
	clientset k8s_client.Clientset
	lc        cell.Lifecycle
	jobs      job.Registry
	scope     cell.Scope

	// For BGP Cluster Config
	clusterConfig           resource.Resource[*cilium_api_v2alpha1.CiliumBGPClusterConfig]
	nodeConfigOverride      resource.Resource[*cilium_api_v2alpha1.CiliumBGPNodeConfigOverride]
	nodeConfig              resource.Resource[*cilium_api_v2alpha1.CiliumBGPNodeConfig]
	ciliumNode              resource.Resource[*cilium_api_v2.CiliumNode]
	clusterConfigStore      resource.Store[*cilium_api_v2alpha1.CiliumBGPClusterConfig]
	nodeConfigOverrideStore resource.Store[*cilium_api_v2alpha1.CiliumBGPNodeConfigOverride]
	nodeConfigStore         resource.Store[*cilium_api_v2alpha1.CiliumBGPNodeConfig]
	ciliumNodeStore         resource.Store[*cilium_api_v2.CiliumNode]
	nodeConfigClient        cilium_client_v2alpha1.CiliumBGPNodeConfigInterface

	// For legacy BGP Peering Policy
	peeringPolicy      resource.Resource[*cilium_api_v2alpha1.CiliumBGPPeeringPolicy]
	advert             resource.Resource[*cilium_api_v2alpha1.CiliumBGPAdvertisement]
	peerConfig         resource.Resource[*cilium_api_v2alpha1.CiliumBGPPeerConfig]
	peeringPolicyStore resource.Store[*cilium_api_v2alpha1.CiliumBGPPeeringPolicy]
	advertStore        resource.Store[*cilium_api_v2alpha1.CiliumBGPAdvertisement]
	peerConfigStore    resource.Store[*cilium_api_v2alpha1.CiliumBGPPeerConfig]
	advertClient       cilium_client_v2alpha1.CiliumBGPAdvertisementInterface
	peerConfigClient   cilium_client_v2alpha1.CiliumBGPPeerConfigInterface

	// internal state
	reconcileCh      chan struct{}
	bgpPolicySyncCh  chan struct{}
	bgpClusterSyncCh chan struct{}
}

// registerBGPResourceManager creates a new BGPResourceManager operator instance.
func registerBGPResourceManager(p BGPParams) *BGPResourceManager {
	// if BGPResourceManager Control Plane is not enabled or BGPv2 API is not enabled, return nil
	if !p.DaemonConfig.BGPControlPlaneEnabled() || !p.Config.BGPv2Enabled {
		return nil
	}

	b := &BGPResourceManager{
		logger:    p.Logger,
		clientset: p.Clientset,
		jobs:      p.JobRegistry,
		lc:        p.LC,
		scope:     p.Scope,

		reconcileCh:        make(chan struct{}, 1),
		bgpPolicySyncCh:    make(chan struct{}, 1),
		bgpClusterSyncCh:   make(chan struct{}, 1),
		clusterConfig:      p.ClusterConfigResource,
		nodeConfigOverride: p.NodeConfigOverrideResource,
		nodeConfig:         p.NodeConfigResource,
		ciliumNode:         p.NodeResource,
		peeringPolicy:      p.LegacyBGPResource,
		advert:             p.AdvertisementResource,
		peerConfig:         p.PeerConfigResource,
	}

	b.nodeConfigClient = b.clientset.CiliumV2alpha1().CiliumBGPNodeConfigs()
	b.peerConfigClient = b.clientset.CiliumV2alpha1().CiliumBGPPeerConfigs()
	b.advertClient = b.clientset.CiliumV2alpha1().CiliumBGPAdvertisements()

	// initialize jobs and register them with lifecycle
	jobs := b.initializeJobs()
	p.LC.Append(jobs)

	return b
}

func (b *BGPResourceManager) initializeJobs() job.Group {
	jobGroup := b.jobs.NewGroup(
		b.scope,
		job.WithLogger(b.logger),
		job.WithPprofLabels(pprof.Labels("cell", "bgpv2-cp-operator")),
	)

	jobGroup.Add(
		job.OneShot("bgpv2-operator-main", func(ctx context.Context, health cell.HealthReporter) error {
			// initialize resource stores
			err := b.initializeStores(ctx)
			if err != nil {
				return err
			}

			b.logger.Info("BGPv2 control plane operator started")

			return b.Run(ctx)
		}),

		// Tracking jobs to do
		job.OneShot("bgpv2-operator-peering-policy-tracker", func(ctx context.Context, health cell.HealthReporter) error {
			for e := range b.peeringPolicy.Events(ctx) {
				if e.Kind == resource.Sync {
					select {
					case b.bgpPolicySyncCh <- struct{}{}:
					default:
					}
				}

				b.triggerReconcile()
				e.Done(nil)
			}
			return nil
		}),

		job.OneShot("bgpv2-operator-cluster-config-tracker", func(ctx context.Context, health cell.HealthReporter) error {
			for e := range b.clusterConfig.Events(ctx) {
				if e.Kind == resource.Sync {
					select {
					case b.bgpClusterSyncCh <- struct{}{}:
					default:
					}
				}

				b.triggerReconcile()
				e.Done(nil)
			}
			return nil
		}),

		job.OneShot("bgpv2-operator-node-config-override-tracker", func(ctx context.Context, health cell.HealthReporter) error {
			for e := range b.nodeConfigOverride.Events(ctx) {
				b.triggerReconcile()
				e.Done(nil)
			}
			return nil
		}),

		job.OneShot("bgpv2-operator-node-tracker", func(ctx context.Context, health cell.HealthReporter) error {
			for e := range b.ciliumNode.Events(ctx) {
				b.triggerReconcile()
				e.Done(nil)
			}
			return nil
		}),
	)

	return jobGroup
}

func (b *BGPResourceManager) initializeStores(ctx context.Context) (err error) {
	defer func() {
		hr := cell.GetHealthReporter(b.scope, "bgpv2-store-initialization")
		if err != nil {
			hr.Stopped("store initialization failed")
		} else {
			hr.OK("store initialization successful")
		}
	}()

	b.clusterConfigStore, err = b.clusterConfig.Store(ctx)
	if err != nil {
		return
	}

	b.nodeConfigOverrideStore, err = b.nodeConfigOverride.Store(ctx)
	if err != nil {
		return
	}

	b.nodeConfigStore, err = b.nodeConfig.Store(ctx)
	if err != nil {
		return
	}

	b.advertStore, err = b.advert.Store(ctx)
	if err != nil {
		return
	}

	b.peerConfigStore, err = b.peerConfig.Store(ctx)
	if err != nil {
		return
	}

	b.ciliumNodeStore, err = b.ciliumNode.Store(ctx)
	if err != nil {
		return
	}

	b.peeringPolicyStore, err = b.peeringPolicy.Store(ctx)
	if err != nil {
		return
	}

	return nil
}

// triggerReconcile initiates level triggered reconciliation.
func (b *BGPResourceManager) triggerReconcile() {
	select {
	case b.reconcileCh <- struct{}{}:
		b.logger.Debug("BGP reconciliation triggered")
	default:
	}
}

// Run starts the BGPResourceManager operator.
func (b *BGPResourceManager) Run(ctx context.Context) (err error) {
	// make sure both policy and cluster config are synced before starting the reconciliation
	<-b.bgpClusterSyncCh
	<-b.bgpPolicySyncCh

	// trigger reconciliation for first time.
	b.triggerReconcile()

	for {
		select {
		case <-ctx.Done():
			return

		case _, open := <-b.reconcileCh:
			if !open {
				return
			}

			err := b.reconcileWithRetry(ctx)
			if err != nil {
				b.logger.WithError(err).Error("BGP reconciliation failed")
			} else {
				b.logger.Debug("BGP reconciliation successful")
			}
		}
	}
}

// reconcileWithRetry retries reconcile with exponential backoff.
func (b *BGPResourceManager) reconcileWithRetry(ctx context.Context) error {
	retryFn := func(ctx context.Context) (bool, error) {
		err := b.reconcile(ctx)

		switch {
		case err != nil:
			// log error, continue retry
			b.logger.WithError(TrimError(err, maxErrorLen)).Warn("BGP reconciliation error")
			return false, nil
		default:
			// no error, stop retry
			return true, nil
		}
	}

	return wait.ExponentialBackoffWithContext(ctx, bo, retryFn)
}

// reconcile is called when any interesting resource change event is triggered.
func (b *BGPResourceManager) reconcile(ctx context.Context) error {
	var err error
	ppEnabled, ccEnabled := len(b.peeringPolicyStore.List()) > 0, len(b.clusterConfigStore.List()) > 0

	switch {
	case ppEnabled && ccEnabled:
		// If both legacy CiliumBGPPeeringPolicy and new CiliumBGPClusterConfig is enabled,
		// we only reconcile new CiliumBGPClusterConfig.
		// This is done for migration from legacy to new BGP resources.
		err = b.reconcileBGPClusterConfigs(ctx)
	case ppEnabled:
		err = b.reconcileBGPPeeringPolicies(ctx)
	case ccEnabled:
		err = b.reconcileBGPClusterConfigs(ctx)
	}

	// clean up any orphan objects
	dErr := b.deleteOrphanObjects(ctx)
	if dErr != nil {
		err = errors.Join(err, dErr)
	}

	return err
}

// deleteOrphanObjects deletes stale BGP object.
//
// If BGP objects were created by operator on behalf of CiliumBGPPeeringPolicy or CiliumBGPClusterConfig,
// then owner field is set explicitly.
// If the owner is deleted, then we need to clean up objects which were created by the operator on behalf of the owner.
func (b *BGPResourceManager) deleteOrphanObjects(ctx context.Context) error {
	var err error

	// cleanup orphan CiliumBGPNodeConfig objects
	dErr := b.deleteOrphanBGPNC(ctx)
	if dErr != nil {
		err = errors.Join(err, dErr)
	}

	dErr = b.deleteOrphanBGPA(ctx)
	if dErr != nil {
		err = errors.Join(err, dErr)
	}

	dErr = b.deleteOrphanBGPPC(ctx)
	if dErr != nil {
		err = errors.Join(err, dErr)
	}

	return err
}

// deleteOrphanBGPNC deletes orphan CiliumBGPNodeConfig objects. If owner is not of kind BGP peering policy or BGP cluster config,
// or if the owner does not exist, then the CiliumNodeConfig object is deleted.
func (b *BGPResourceManager) deleteOrphanBGPNC(ctx context.Context) error {
	var allErr error
	for _, nc := range b.nodeConfigStore.List() {
		var err error
		ownerExists := false

		kind, name := getOwnerKindAndName(nc)
		switch kind {
		case cilium_api_v2alpha1.BGPPKindDefinition:
			_, ownerExists, err = b.peeringPolicyStore.GetByKey(resource.Key{Name: name})

		case cilium_api_v2alpha1.BGPCCKindDefinition:
			_, ownerExists, err = b.clusterConfigStore.GetByKey(resource.Key{Name: name})
		}

		if err != nil {
			allErr = errors.Join(allErr, err)
			continue
		}

		if !ownerExists {
			// Parent policy which resulted in creation of this CiliumBGPNodeConfig object is missing.
			// We can go ahead and delete this node config object.

			dErr := b.nodeConfigClient.Delete(ctx, nc.GetName(), meta_v1.DeleteOptions{})
			if dErr != nil && k8s_errors.IsNotFound(dErr) {
				// object is already removed from API server.
				continue
			} else if dErr != nil {
				allErr = errors.Join(allErr, dErr)
			} else {
				b.logger.WithFields(logrus.Fields{
					"node config":   nc.GetName(),
					"parent policy": name,
					"parent kind":   kind,
				}).Info("Deleting BGP node config object, parent policy not found")
			}
		}
	}
	return allErr
}

// deleteOrphanBGPA deletes orphan CiliumBGPAdvertisement objects. If owner is of kind BGP peering policy, but policy is not found,
// we delete the CiliumBGPAdvertisement object.
func (b *BGPResourceManager) deleteOrphanBGPA(ctx context.Context) error {
	var allErr error
	for _, advert := range b.advertStore.List() {
		kind, name := getOwnerKindAndName(advert)

		if kind != cilium_api_v2alpha1.BGPPKindDefinition {
			// skip advertisements which are not created by CiliumBGPPeeringPolicy
			continue
		}

		_, ownerExists, err := b.peeringPolicyStore.GetByKey(resource.Key{Name: name})
		if err != nil {
			allErr = errors.Join(allErr, err)
			continue
		}

		if !ownerExists {
			dErr := b.advertClient.Delete(ctx, advert.GetName(), meta_v1.DeleteOptions{})
			if dErr != nil && k8s_errors.IsNotFound(dErr) {
				// object is already removed from API server.
				continue
			} else if dErr != nil {
				allErr = errors.Join(allErr, dErr)
			} else {
				b.logger.WithFields(logrus.Fields{
					"advertisement": advert.GetName(),
					"parent policy": name,
					"parent kind":   kind,
				}).Info("Deleting BGP advertisement object, parent policy not found")
			}
		}
	}
	return allErr
}

// deleteOrphanBGPPC deletes orphan CiliumBGPPeerConfig objects. If owner is of kind BGP peering policy, but policy is not found,
// we delete the CiliumBGPPeerConfig object.
func (b *BGPResourceManager) deleteOrphanBGPPC(ctx context.Context) error {
	var allErr error
	for _, pc := range b.peerConfigStore.List() {
		kind, name := getOwnerKindAndName(pc)

		if kind != cilium_api_v2alpha1.BGPPKindDefinition {
			// skip peer configs which are not created by CiliumBGPPeeringPolicy
			continue
		}

		_, ownerExists, err := b.peeringPolicyStore.GetByKey(resource.Key{Name: name})
		if err != nil {
			allErr = errors.Join(allErr, err)
			continue
		}

		if !ownerExists {
			dErr := b.peerConfigClient.Delete(ctx, pc.GetName(), meta_v1.DeleteOptions{})
			if dErr != nil && k8s_errors.IsNotFound(dErr) {
				// object is already removed from API server.
				continue
			} else if dErr != nil {
				allErr = errors.Join(allErr, dErr)
			} else {
				b.logger.WithFields(logrus.Fields{
					"peer config":   pc.GetName(),
					"parent policy": name,
					"parent kind":   kind,
				}).Info("Deleting BGP peer config object, parent policy not found")
			}
		}
	}
	return allErr
}

// getOwnerKindAndName returns owner kind and name for a given object.
// BGP resources created by operator will have only 1 owner.
func getOwnerKindAndName[T meta_v1.Object](obj T) (string, string) {
	owners := obj.GetOwnerReferences()

	// we expect only 1 owner for BGP resources
	if len(owners) != 1 {
		return "", ""
	}

	return owners[0].Kind, owners[0].Name
}

// TrimError trims error message to maxLen.
func TrimError(err error, maxLen int) error {
	if err == nil {
		return nil
	}

	if len(err.Error()) > maxLen {
		return fmt.Errorf("%s... ", err.Error()[:maxLen])
	}
	return err
}
