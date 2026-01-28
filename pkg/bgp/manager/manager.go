// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package manager

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strings"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/cilium/cilium/api/v1/models"
	restapi "github.com/cilium/cilium/api/v1/server/restapi/bgp"
	"github.com/cilium/cilium/pkg/bgp/agent"
	"github.com/cilium/cilium/pkg/bgp/api"
	"github.com/cilium/cilium/pkg/bgp/manager/instance"
	"github.com/cilium/cilium/pkg/bgp/manager/reconciler"
	"github.com/cilium/cilium/pkg/bgp/manager/tables"
	"github.com/cilium/cilium/pkg/bgp/types"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/defaults"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

// LocalInstanceMap maps instance names to their associated BgpInstances and
// configuration info.
type LocalInstanceMap map[string]*instance.BGPInstance

type bgpRouterManagerParams struct {
	cell.In
	Logger              *slog.Logger
	Lifecycle           cell.Lifecycle
	JobGroup            job.Group
	DaemonConfig        *option.DaemonConfig
	Metrics             *BGPManagerMetrics
	DB                  *statedb.DB
	ReconcileErrorTable statedb.RWTable[*tables.BGPReconcileError]
	RouterProvider      types.RouterProvider
	Reconcilers         []reconciler.ConfigReconciler `group:"bgp-config-reconciler"`
	StateReconcilers    []reconciler.StateReconciler  `group:"bgp-state-reconciler"`
}

type State struct {
	// reconcilers are list of state reconcilers which will be called when instance state changes.
	reconcilers []reconciler.StateReconciler

	// notifications is a map of instance name to the channel which will be used to get notification
	// from underlying BGP instance. This map is used for bookkeeping and closing of channel when
	// instance is deleted.
	notifications map[string]types.StateNotificationCh

	// pendingInstancesMutex is used to protect the pendingInstances set.
	//
	// pendingInstancesMutex in BGPRouterManager is introduced as we can have high number of
	// state notifications. We do not want to hold the BGPRouterManager.Lock for each
	// state update.
	//
	// Order of locking: pendingInstancesMutex -> BGPRouterManager.Lock
	// DO NOT take BGPRouterManager.Lock and then State.pendingInstancesMutex.
	pendingInstancesMutex lock.Mutex

	// pendingInstances set contains the instances which need to be reconciled for state change.
	pendingInstances sets.Set[string]

	// reconcileSignal is used to signal bgp-state-observer to reconcile the state based on
	// pendingInstances set.
	reconcileSignal chan struct{}

	// instanceDeletionSignal is used to signal bgp-state-observer to reconcile the cleanup of
	// instance. Instance name is signaled on this channel.
	instanceDeletionSignal chan string
}

// BGPRouterManager implements the agent's BGPRouterManager interface.
//
// Logically, this manager views each BGP instance within a
// CiliumBGPClusterConfig as a BGP router instantiated on its host.
//
// This manager employs two main data structures to implement its high level
// business logic:
//
// A reconcileDiff is used to establish which BGP instances must be created,
// and removed from the Manager along with which instances must have their
// configurations reconciled.
//
// A set of ConfigReconcilers, which usages are wrapped by the
// reconcileBGPConfig function, reconcile configuration of individual BGP instances.
//
// Together, the high-level flow the manager takes is:
//   - instantiate a reconcilerDiff to compute which BGP instances to create, remove,
//     and reconcile,
//   - create any instances necessary, run reconcileBGPConfig on each,
//   - run each config reconciler, by way of calling reconcileBGPConfig
//     on any instances marked for reconcile.
type BGPRouterManager struct {
	logger *slog.Logger

	lock.RWMutex

	// BGP router provider
	routerProvider types.RouterProvider

	// BGP instances and reconcilers
	BGPInstances      LocalInstanceMap
	ConfigReconcilers []reconciler.ConfigReconciler

	// statedb tables
	DB                  *statedb.DB
	ReconcileErrorTable statedb.RWTable[*tables.BGPReconcileError]

	// running is set when the manager is running, and unset when it is stopped.
	running bool

	// destroyRouterOnStop should be true if the underlying router should be fully destroyed upon Stop().
	// Note that this causes sending a Cease notification to BGP peers, which terminates Graceful Restart progress.
	destroyRouterOnStop bool

	// state management
	state State

	// internal metrics
	metrics *BGPManagerMetrics
}

// NewBGPRouterManager constructs a new BGPRouterManager.
func NewBGPRouterManager(params bgpRouterManagerParams) agent.BGPRouterManager {
	if !params.DaemonConfig.BGPControlPlaneEnabled() {
		return &BGPRouterManager{}
	}

	activeReconcilers := reconciler.GetActiveReconcilers(params.Logger, params.Reconcilers)

	m := &BGPRouterManager{
		logger:         params.Logger,
		routerProvider: params.RouterProvider,
		running:        true, // start with running state set

		BGPInstances:      make(LocalInstanceMap),
		ConfigReconcilers: activeReconcilers,

		// statedb
		DB:                  params.DB,
		ReconcileErrorTable: params.ReconcileErrorTable,

		// By default, do not destroy the GobGP router on Stop() as that causes sending Cease notification to peers,
		// which terminates Graceful Restart progress. We set this to true only for tests, where GR is not needed
		// and full cleanup is necessary.
		destroyRouterOnStop: false,

		// state
		state: State{
			reconcilers:            reconciler.GetActiveStateReconcilers(params.Logger, params.StateReconcilers),
			notifications:          make(map[string]types.StateNotificationCh),
			pendingInstances:       sets.New[string](),
			reconcileSignal:        make(chan struct{}, 1),
			instanceDeletionSignal: make(chan string),
		},

		metrics: params.Metrics,
	}

	params.Lifecycle.Append(m)

	params.JobGroup.Add(
		job.OneShot("bgp-state-observer", func(ctx context.Context, health cell.Health) (err error) {
			for {
				select {
				case <-ctx.Done():
					return nil
				case <-m.state.reconcileSignal:
					err := m.reconcileStateWithRetry(ctx)
					if err != nil {
						m.logger.Error("failed to reconcile state", logfields.Error, err)
					}
				case instanceName := <-m.state.instanceDeletionSignal:
					m.reconcileInstanceDeletion(ctx, instanceName)
				}
			}
		}),
	)

	return m
}

func (m *BGPRouterManager) reconcileStateWithRetry(ctx context.Context) error {
	bo := wait.Backoff{
		Duration: 100 * time.Millisecond,
		Factor:   1.2,
		Steps:    10,
	}

	retryFn := func(ctx context.Context) (bool, error) {
		err := m.reconcileState(ctx)
		if err != nil {
			m.logger.Error("failed to reconcile state", logfields.Error, err)
			return false, nil
		}
		return true, nil
	}

	return wait.ExponentialBackoffWithContext(ctx, bo, retryFn)
}

func (m *BGPRouterManager) GetPeers(ctx context.Context, req *agent.GetPeersRequest) (*agent.GetPeersResponse, error) {
	m.RLock()
	defer m.RUnlock()

	if !m.running {
		return nil, fmt.Errorf("bgp router manager is not running")
	}

	var res agent.GetPeersResponse
	for _, i := range m.BGPInstances {
		r, err := i.Router.GetPeerState(ctx, &types.GetPeerStateRequest{})
		if err != nil {
			return nil, err
		}
		res.Instances = append(res.Instances, agent.InstancePeerStates{
			Name:  i.Name,
			Peers: r.Peers,
		})
	}

	return &res, nil
}

// GetPeersLegacy gets peering state from previously initialized bgp instances.
func (m *BGPRouterManager) GetPeersLegacy(ctx context.Context) ([]*models.BgpPeer, error) {
	m.RLock()
	defer m.RUnlock()

	if !m.running {
		return nil, fmt.Errorf("bgp router manager is not running")
	}

	var res []*models.BgpPeer
	for _, i := range m.BGPInstances {
		getPeerResp, err := i.Router.GetPeerStateLegacy(ctx)
		if err != nil {
			return nil, err
		}
		res = append(res, getPeerResp.Peers...)
	}
	return res, nil
}

// GetRoutes retrieves routes from the RIB of underlying router
func (m *BGPRouterManager) GetRoutes(ctx context.Context, params restapi.GetBgpRoutesParams) ([]*models.BgpRoute, error) {
	m.RLock()
	defer m.RUnlock()

	if !m.running {
		return nil, fmt.Errorf("bgp router manager is not running")
	}

	// validate router ASN
	if params.RouterAsn != nil {
		if !m.asnExistsInInstances(*params.RouterAsn) {
			return nil, fmt.Errorf("virtual router with ASN %d does not exist", *params.RouterAsn)
		}
	}

	// validate that router ASN is set for the neighbor if there are multiple servers
	if params.Neighbor != nil && len(m.BGPInstances) > 1 && params.RouterAsn == nil {
		return nil, fmt.Errorf("multiple virtual routers configured, router ASN must be specified")
	}

	// determine if we need to retrieve the routes for each peer (in case of adj-rib but no peer specified)
	tt := types.ParseTableType(params.TableType)
	allPeers := (tt == types.TableTypeAdjRIBIn || tt == types.TableTypeAdjRIBOut) && (params.Neighbor == nil || *params.Neighbor == "")

	var res []*models.BgpRoute
	for _, i := range m.BGPInstances {
		if params.RouterAsn != nil && i.Config.LocalASN != nil && *params.RouterAsn != *i.Config.LocalASN {
			continue // return routes matching provided router ASN only
		}
		if allPeers {
			// get routes for each peer of the server
			getPeerResp, err := i.Router.GetPeerStateLegacy(ctx)
			if err != nil {
				return nil, err
			}
			for _, peer := range getPeerResp.Peers {
				params.Neighbor = &peer.PeerAddress
				routes, err := m.getRoutesFromInstance(ctx, i, params)
				if err != nil {
					return nil, err
				}
				res = append(res, routes...)
			}
		} else {
			// get routes with provided params
			routes, err := m.getRoutesFromInstance(ctx, i, params)
			if err != nil {
				return nil, err
			}
			res = append(res, routes...)
		}
	}
	return res, nil
}

// getRoutesFromInstance retrieves routes from the RIB of the specified BGP instance
func (m *BGPRouterManager) getRoutesFromInstance(ctx context.Context, i *instance.BGPInstance, params restapi.GetBgpRoutesParams) ([]*models.BgpRoute, error) {
	if i.Config.LocalASN == nil {
		return nil, fmt.Errorf("local ASN not set for instance")
	}

	req, err := api.ToAgentGetRoutesRequest(params)
	if err != nil {
		return nil, err
	}

	rs, err := i.Router.GetRoutes(ctx, req)
	if err != nil {
		return nil, err
	}

	neighbor := ""
	if params.Neighbor != nil {
		neighbor = *params.Neighbor
	}
	return api.ToAPIRoutes(rs.Routes, *i.Config.LocalASN, neighbor)
}

func (m *BGPRouterManager) asnExistsInInstances(asn int64) bool {
	for _, instance := range m.BGPInstances {
		if instance.Config.LocalASN != nil && *instance.Config.LocalASN == asn {
			return true
		}
	}
	return false
}

// GetRoutePolicies fetches BGP routing policies from underlying routing daemon.
func (m *BGPRouterManager) GetRoutePolicies(ctx context.Context, params restapi.GetBgpRoutePoliciesParams) ([]*models.BgpRoutePolicy, error) {
	m.RLock()
	defer m.RUnlock()

	if !m.running {
		return nil, fmt.Errorf("bgp router manager is not running")
	}

	// validate router ASN
	if params.RouterAsn != nil {
		if !m.asnExistsInInstances(*params.RouterAsn) {
			return nil, fmt.Errorf("virtual router with ASN %d does not exist", *params.RouterAsn)
		}
	}

	var res []*models.BgpRoutePolicy
	for _, i := range m.BGPInstances {
		if params.RouterAsn != nil && i.Config.LocalASN != nil && *params.RouterAsn != *i.Config.LocalASN {
			continue // return policies matching provided router ASN only
		}
		rs, err := i.Router.GetRoutePolicies(ctx)
		if err != nil {
			return nil, err
		}
		res = append(res, api.ToAPIRoutePolicies(rs.Policies, *i.Config.LocalASN)...)
	}
	return res, nil
}

func (m *BGPRouterManager) Start(_ cell.HookContext) error {
	return nil
}

// Stop cleans up all servers, called by hive lifecycle at shutdown
func (m *BGPRouterManager) Stop(ctx cell.HookContext) error {
	m.Lock()
	defer m.Unlock()

	for name, i := range m.BGPInstances {
		i.CancelCtx()
		i.Router.Stop(ctx, types.StopRequest{FullDestroy: m.destroyRouterOnStop})
		notifCh, exists := m.state.notifications[name]
		if exists {
			close(notifCh)
		}
	}

	m.BGPInstances = make(LocalInstanceMap)
	m.state.notifications = make(map[string]types.StateNotificationCh)
	m.running = false
	return nil
}

// DestroyRouterOnStop should be set to true if the underlying router should be fully destroyed upon Stop().
// Note that this causes sending a Cease notification to BGP peers, which terminates Graceful Restart.
// Full destroy is useful especially for tests, where multiple instances of the RouterManager may be running.
func (m *BGPRouterManager) DestroyRouterOnStop(destroy bool) {
	m.Lock()
	defer m.Unlock()

	m.destroyRouterOnStop = destroy
}

// ReconcileInstances is an API for configuring the BGP Instances from the
// desired CiliumBGPNodeConfig resource.
//
// ReconcileInstances will evaluate BGP instances to be created, removed and
// reconciled.
func (m *BGPRouterManager) ReconcileInstances(ctx context.Context,
	nodeObj *v2.CiliumBGPNodeConfig,
	ciliumNode *v2.CiliumNode) error {
	m.Lock()
	defer m.Unlock()

	// use a reconcileDiff to compute which BgpServers must be created, removed
	// and reconciled.
	rd := newReconcileDiff(ciliumNode)

	if nodeObj == nil {
		m.withdrawAll(ctx, rd)
		return nil
	}

	err := rd.diff(m.BGPInstances, nodeObj)
	if err != nil {
		return err
	}

	if rd.empty() {
		m.logger.Debug("BGP instance up-to-date with CiliumBGPNodeConfig", types.BGPNodeConfigLogField, nodeObj.Name)
		return nil
	}
	m.logger.Debug("Reconciling BGP instances",
		types.DiffLogField, rd,
		types.BGPNodeConfigLogField, nodeObj.Name,
	)

	// withdraw before registering to ensure re-create works properly
	if len(rd.withdraw) > 0 {
		m.withdraw(ctx, rd)
	}
	if len(rd.register) > 0 {
		err = errors.Join(err, m.register(ctx, rd))
	}
	if len(rd.reconcile) > 0 {
		err = errors.Join(err, m.reconcile(ctx, rd))
	}

	return err
}

// register instantiates and configures BGP Instance(s) as instructed by the provided
// work diff.
func (m *BGPRouterManager) register(ctx context.Context, rd *reconcileDiff) error {
	var (
		instancesWithError []string
		lastErr            error
	)
	for _, name := range rd.register {
		var config *v2.CiliumBGPNodeInstance
		var ok bool
		if config, ok = rd.seen[name]; !ok {
			m.logger.Debug("Work diff (add) contains unseen instance, skipping", types.InstanceLogField, name)
			instancesWithError = append(instancesWithError, name)
			lastErr = errors.New("unseen instance")
			continue
		}
		if rErr := m.registerBGPInstance(ctx, config, rd.ciliumNode); rErr != nil {
			// we'll log the error and attempt to register the next instance.
			m.logger.Debug("Error registering new BGP instance",
				logfields.Error, rErr,
				types.InstanceLogField, name,
			)
			instancesWithError = append(instancesWithError, name)
			lastErr = rErr
		}
	}
	if len(instancesWithError) > 0 {
		return fmt.Errorf("error registering new BGP instances: %v (last error: %w)", instancesWithError, lastErr)
	}
	return nil
}

// registerBGPInstance encapsulates the logic for instantiating a
// BGPInstance
func (m *BGPRouterManager) registerBGPInstance(ctx context.Context,
	c *v2.CiliumBGPNodeInstance,
	ciliumNode *v2.CiliumNode) error {

	l := m.logger.With(types.InstanceLogField, c.Name)

	l.Info("Registering BGP instance")

	localASN, err := getLocalASN(c)
	if err != nil {
		return err
	}
	localPort, err := getLocalPort(c)
	if err != nil {
		return err
	}
	routerID, err := getRouterID(c, ciliumNode)
	if err != nil {
		return err
	}

	globalConfig := types.ServerParameters{
		Global: types.BGPGlobal{
			ASN:        uint32(localASN),
			RouterID:   routerID,
			ListenPort: localPort,
			RouteSelectionOptions: &types.RouteSelectionOptions{
				AdvertiseInactiveRoutes: true,
			},
		},
		StateNotification: make(types.StateNotificationCh, 1),
	}

	i, err := instance.NewBGPInstance(ctx, m.routerProvider, l, c.Name, globalConfig)
	if err != nil {
		return fmt.Errorf("failed to start BGP instance: %w", err)
	}

	// register with manager
	m.BGPInstances[c.Name] = i
	m.state.notifications[c.Name] = globalConfig.StateNotification

	// start consuming state notifications
	go m.trackInstanceStateChange(c.Name, globalConfig.StateNotification)

	// initialize the reconcilers for this instance
	for _, r := range m.ConfigReconcilers {
		err = r.Init(i)
		if err != nil {
			return fmt.Errorf("%s reconciler initialization failed: %w", r.Name(), err)
		}
	}

	if err = m.reconcileBGPConfig(ctx, i, c, ciliumNode); err != nil {
		return fmt.Errorf("failed initial reconciliation of BGP instance: %w", err)
	}

	m.logger.Info(
		"Successfully registered BGP instance",
		types.LocalASNLogField, localASN,
		types.ListenPortLogField, localPort,
		types.RouterIDLogField, routerID,
	)

	return err
}

// reconcileBGPConfig will utilize the current set of ConfigReconciler
// to push a BGP Instance to its desired configuration.
//
// Each reconciler is responsible for getting the desired configuration from
// resource store and applying it to the BGP Instance.
func (m *BGPRouterManager) reconcileBGPConfig(ctx context.Context,
	i *instance.BGPInstance,
	newc *v2.CiliumBGPNodeInstance,
	ciliumNode *v2.CiliumNode) error {

	reconcileStart := time.Now()

	var reconcileErrs []error
	for _, r := range m.ConfigReconcilers {
		if rErr := r.Reconcile(ctx, reconciler.ReconcileParams{
			BGPInstance:   i,
			DesiredConfig: newc,
			CiliumNode:    ciliumNode,
		}); rErr != nil {
			m.metrics.ReconcileErrorsTotal.WithLabelValues(newc.Name).Inc()
			reconcileErrs = append(reconcileErrs, rErr)
			// If r.Reconcile returns ErrAbortReconcile, we should stop the reconciliation
			// for this instance and return the error.
			// Goal of stopping the reconciliation is twofold:
			// 1. Error in the infrastructure (e.g. stores are not yet initialized ). In this
			// case, we should stop the reconciliation as most of the other reconcilers will
			// also fail.
			// 2. There is hard dependency on the ordering of reconciliation, and we should
			// not proceed with other reconcilers if current reconciler returns ErrAbortReconcile.
			// This is to ensure correctness in the behavior of BGP configuration.
			//
			// If the reconciler returns any other error, we should continue with remaining
			// reconcilers and accumulate the error. This ensures that we try to reconcile
			// as much configuration as possible.
			//
			// High level retry will again call the reconciliation loop as long as we return
			// error.
			if errors.Is(rErr, reconciler.ErrAbortReconcile) {
				break
			}
		}
	}

	reconcileErrs = append(reconcileErrs, m.updateReconcilerErrors(newc.Name, reconcileErrs))
	m.metrics.ReconcileRunDuration.WithLabelValues(newc.Name).Observe(time.Since(reconcileStart).Seconds())
	i.Config = newc
	return errors.Join(reconcileErrs...)
}

func (m *BGPRouterManager) updateReconcilerErrors(instance string, newErrors []error) error {
	txn := m.DB.WriteTxn(m.ReconcileErrorTable)
	defer txn.Abort()

	// We only consider first n errors for matching
	if len(newErrors) > tables.BGPReconcileErrCountPerInstance {
		newErrors = newErrors[:tables.BGPReconcileErrCountPerInstance]
	}

	// get existing errors for this instance from the table
	prevErrors := m.getErrorsFromTable(txn, instance)

	// compare previous and current errors
	if errorsChanged(prevErrors, newErrors) {
		// delete old errors
		err := m.deleteErrorsFromTable(txn, instance)
		if err != nil {
			return err
		}

		// write new errors
		for i, newErr := range newErrors {
			obj := &tables.BGPReconcileError{
				Instance: instance,
				ErrorID:  i,
				Error:    newErr.Error(),
			}
			_, _, err := m.ReconcileErrorTable.Insert(txn, obj)
			if err != nil {
				return fmt.Errorf("error inserting reconcile error into table: %w", err)
			}
		}
	}

	txn.Commit()
	return nil
}

func (m *BGPRouterManager) getErrorsFromTable(txn statedb.WriteTxn, instance string) []error {
	// get existing errors for this instance from the table
	var reconcileErrs []*tables.BGPReconcileError
	iter := m.ReconcileErrorTable.List(txn, tables.BGPReconcileErrorInstance.Query(instance))
	for instanceErr := range iter {
		reconcileErrs = append(reconcileErrs, instanceErr.DeepCopy())
	}
	// sort errors based on ID
	sort.Slice(reconcileErrs, func(i, j int) bool { return reconcileErrs[i].ErrorID < reconcileErrs[j].ErrorID })

	var errs []error
	for _, rErr := range reconcileErrs {
		errs = append(errs, errors.New(rErr.Error))
	}

	return errs
}

func (m *BGPRouterManager) deleteErrorsFromTable(txn statedb.WriteTxn, instance string) error {
	iter := m.ReconcileErrorTable.List(txn, tables.BGPReconcileErrorInstance.Query(instance))
	for instanceErr := range iter {
		_, _, err := m.ReconcileErrorTable.Delete(txn, instanceErr)
		if err != nil {
			return fmt.Errorf("error deleting reconcile error from table: %w", err)
		}
	}
	return nil
}

func errorsChanged(prevErrs, newErrs []error) bool {
	if len(prevErrs) != len(newErrs) {
		return true
	}

	for i, prevErr := range prevErrs {
		if strings.Compare(prevErr.Error(), newErrs[i].Error()) != 0 {
			return true
		}
	}
	return false
}

// withdrawV2 disconnects and removes BGP Instance(s) as instructed by the provided
// work diff.
func (m *BGPRouterManager) withdraw(ctx context.Context, rd *reconcileDiff) {
	txn := m.DB.WriteTxn(m.ReconcileErrorTable)
	defer txn.Abort()

	for _, name := range rd.withdraw {
		var (
			i  *instance.BGPInstance
			ok bool
		)
		if i, ok = m.BGPInstances[name]; !ok {
			m.logger.Warn(
				"BGP instance marked for deletion but does not exist",
				types.InstanceLogField, name,
			)
			continue
		}
		for _, r := range m.ConfigReconcilers {
			r.Cleanup(i)
		}
		i.CancelCtx()

		// Full destroy of the router instance upon Stop() is needed in this case, to not end up with stale routers running.
		// Note that this makes Graceful Restart inefficient by removing & re-adding the instance.
		i.Router.Stop(ctx, types.StopRequest{FullDestroy: true})

		notifCh, exists := m.state.notifications[name]
		if exists {
			close(notifCh)
		}
		delete(m.BGPInstances, name)
		delete(m.state.notifications, name)

		// cleanup any errors from statedb table for this instance
		err := m.deleteErrorsFromTable(txn, name)
		if err != nil {
			m.logger.Warn(
				"error deleting reconcile errors from table",
				logfields.Error, err,
				types.InstanceLogField, name,
			)
		}
		m.logger.Info(
			"Removed BGP instance",
			types.InstanceLogField, name,
		)
	}
	txn.Commit()
}

// withdrawAllV2 will disconnect and remove all currently registered BGP Instance(s).
//
// `rd` must be a newly created reconcileDiff which has not had its `Diff` method
// called.
func (m *BGPRouterManager) withdrawAll(ctx context.Context, rd *reconcileDiff) {
	if len(m.BGPInstances) == 0 {
		return
	}
	for name := range m.BGPInstances {
		rd.withdraw = append(rd.withdraw, name)
	}
	m.withdraw(ctx, rd)
}

// reconcile evaluates existing BGP Instance(s).
func (m *BGPRouterManager) reconcile(ctx context.Context, rd *reconcileDiff) error {
	var (
		instancesWithError []string
		lastErr            error
	)
	for _, name := range rd.reconcile {
		var (
			i    = m.BGPInstances[name]
			newc = rd.seen[name]
		)
		if i == nil {
			m.logger.Error(
				"BUG: BGP instance marked for reconciliation but missing from Manager", // really shouldn't happen, tagging as bug
				types.InstanceLogField, name,
			)
			instancesWithError = append(instancesWithError, name)
			continue
		}
		if newc == nil {
			m.logger.Error(
				"BUG: BGP instance marked for reconciliation but missing from incoming configurations", // also really shouldn't happen
				types.InstanceLogField, name,
			)
			instancesWithError = append(instancesWithError, name)
			continue
		}

		if err := m.reconcileBGPConfig(ctx, i, newc, rd.ciliumNode); err != nil {
			m.logger.Debug(
				"Error reconciling BGP instance",
				logfields.Error, err,
				types.InstanceLogField, name,
			)
			instancesWithError = append(instancesWithError, name)
			lastErr = err
		}
	}

	if len(instancesWithError) > 0 {
		return fmt.Errorf("error reconciling BGP instances: %v (last error: %w)", instancesWithError, lastErr)
	}
	return nil
}

// getLocalASN returns the local ASN for the given BGP instance. If the local ASN is defined in the desired config, it
// will be returned. Currently, we do not support auto-ASN assignment, so if the local ASN is not defined in the
// desired config, an error will be returned.
func getLocalASN(config *v2.CiliumBGPNodeInstance) (int64, error) {
	if config.LocalASN != nil {
		return *config.LocalASN, nil
	}
	// NOTE: for now we require a local ASN to be specified
	// remove this check once we support auto-ASN assignment.
	return 0, fmt.Errorf("missing ASN in desired config")
}

// macToRouterID converts the lower 4 bytes of a MAC address to a router ID
func macToRouterID(mac net.HardwareAddr) (string, error) {
	macLen := len(mac)
	if macLen < 4 {
		return "", fmt.Errorf("MAC address too short: %v", mac)
	}
	// Use the last 4 bytes to generate the router ID
	return fmt.Sprintf("%d.%d.%d.%d", mac[macLen-4], mac[macLen-3], mac[macLen-2], mac[macLen-1]), nil
}

// calcRouterIDFromMacAddress calculates a router ID from the lower 4 bytes of the MAC address
func calcRouterIDFromMacAddress() (string, error) {
	// Use cilium_host device
	hostDeviceName := defaults.HostDevice

	// Retrieve the network link for the host device
	link, err := safenetlink.LinkByName(hostDeviceName)
	if err != nil {
		return "", fmt.Errorf("failed to get device %s: %w", hostDeviceName, err)
	}

	// Get the MAC address
	mac := link.Attrs().HardwareAddr
	if mac == nil {
		return "", fmt.Errorf("no MAC address found for device %s", hostDeviceName)
	}

	routerID, err := macToRouterID(mac)
	if err != nil {
		return "", fmt.Errorf("failed to calculate router ID from MAC address: %w", err)
	} else {
		return routerID, nil
	}
}

// getRouterID returns the router ID for the given ASN. If the router ID is defined in the desired config, it will
// be returned. Otherwise, the router ID will be resolved from the ciliumnode annotations. If the router ID is not
// defined in the annotations, the node IP from cilium node will be returned. If the node IP is not available, the
// router ID will be calculated from the MAC address.
func getRouterID(config *v2.CiliumBGPNodeInstance, ciliumNode *v2.CiliumNode) (string, error) {
	if config.RouterID != nil {
		return *config.RouterID, nil
	}

	// If there are no annotations about router-id, router-id will be allocated based on the allocation mode
	switch option.Config.BGPRouterIDAllocationMode {
	case option.BGPRouterIDAllocationModeDefault:
		if nodeIP := ciliumNode.GetIP(false); nodeIP != nil {
			return nodeIP.String(), nil
		} else {
			return calcRouterIDFromMacAddress()
		}
	case option.BGPRouterIDAllocationModeIPPool:
		if config.RouterID == nil {
			return "", fmt.Errorf("can't find the router-id in the CiliumBGPNodeInstance")
		}
		routerID := *config.RouterID
		if net.ParseIP(routerID).To4() == nil {
			return "", fmt.Errorf("the router-id %s is not a valid IPv4 address", routerID)
		}
		return routerID, nil
	default:
		return "", fmt.Errorf("invalid router-id allocation mode: %s (supported modes: %s, %s)", option.Config.BGPRouterIDAllocationMode, option.BGPRouterIDAllocationModeDefault, option.BGPRouterIDAllocationModeIPPool)
	}
}

// getLocalPort returns the local port for the given ASN. If the local port is defined in the desired config, it will
// be returned. Otherwise, the local port will be resolved from the ciliumnode annotations. If the local port is not
// defined in the annotations, -1 will be returned.
//
// In gobgp, with -1 as the local port, bgp instance will start in non-listening mode.
func getLocalPort(config *v2.CiliumBGPNodeInstance) (int32, error) {
	if config.LocalPort != nil {
		return *config.LocalPort, nil
	}
	return int32(-1), nil
}
