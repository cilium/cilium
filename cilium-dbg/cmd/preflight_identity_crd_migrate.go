// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"errors"
	"path"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/spf13/cobra"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"

	"github.com/cilium/cilium/pkg/allocator"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	cacheKey "github.com/cilium/cilium/pkg/identity/key"
	"github.com/cilium/cilium/pkg/idpool"
	ciliumClient "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/client"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/identitybackend"
	kvstoreallocator "github.com/cilium/cilium/pkg/kvstore/allocator"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

// opTimeout is the time allowed for each operation to complete. This includes
// listing, allocating and getting identities.
const opTimeout = 30 * time.Second

func migrateIdentityCmd() *cobra.Command {

	cmd := &cobra.Command{
		Use:   "migrate-identity",
		Short: "Migrate KVStore-backed identities to kubernetes CRD-backed identities",
		Long: `migrate-identity allows migrating to CRD-backed identities while
	minimizing connection interruptions. It will allocate a CRD-backed identity,
	with the same numeric security identity, for each cilium security identity
	defined in the kvstore. When cilium-agents are restarted with
	identity-allocation-mode set to CRD the numeric identities will then be
	equivalent between new instances and not-upgraded ones. In cases where the
	numeric identity is already in-use by a different set of labels, a new
	numeric identity is created.`,
	}

	hive := hive.New(
		k8sClient.Cell,
		cell.Invoke(func(lc cell.Lifecycle, clientset k8sClient.Clientset, shutdowner hive.Shutdowner) {
			lc.Append(cell.Hook{
				OnStart: func(ctx cell.HookContext) error {
					return migrateIdentities(ctx, clientset, shutdowner)
				},
			})
		}),
	)
	hive.RegisterFlags(cmd.Flags())

	cmd.Run = func(cmd *cobra.Command, args []string) {
		if err := hive.Run(log); err != nil {
			logging.Fatal(log, err.Error())
		}
	}

	return cmd
}

// migrateIdentities attempts to mirror the security identities in the kvstore
// into k8s CRD-backed identities. The identities are snapshotted on startup
// and new identities created during migrations will not be seen.
// It is a little odd because it violates the cilium-agent assumption that only
// 1 Backend is active at a time.
// The steps are:
// 1- Connect to the kvstore via a pkg/allocatore.Backend
// 2- Connect to k8s
//
//	a- Create the ciliumidentity CRD if it is missing.
//
// 3- Iterate over each identity in the kvstore
//
//	a- Attempt to allocate the same numeric ID to this key
//	b- Already allocated identies that match ID->key are skipped
//	c- kvstore IDs with conflicting CRDs are allocated with a different ID
//
// NOTE: It is assumed that the migration is from k8s to k8s installations. The
// key labels different when running in non-k8s mode.
func migrateIdentities(ctx cell.HookContext, clientset k8sClient.Clientset, shutdowner hive.Shutdowner) error {
	defer shutdowner.Shutdown()

	// This allows us to initialize a CRD allocator
	option.Config.IdentityAllocationMode = option.IdentityAllocationModeCRD // force CRD mode to make ciliumid

	// Init Identity backends
	initCtx, initCancel := context.WithTimeout(ctx, opTimeout)
	kvstoreBackend := initKVStore(ctx, initCtx)

	crdBackend, crdAllocator := initK8s(initCtx, clientset)
	initCancel()

	log.Info("Listing identities in kvstore")
	listCtx, listCancel := context.WithTimeout(ctx, opTimeout)
	kvstoreIDs, err := getKVStoreIdentities(listCtx, kvstoreBackend)
	if err != nil {
		logging.Fatal(log, "Unable to initialize Identity Allocator with CRD backend to allocate identities with already allocated IDs", logfields.Error, err)
	}
	listCancel()

	log.Info("Migrating identities to CRD")
	alreadyAllocatedKeys := make(map[idpool.ID]allocator.AllocatorKey) // IDs that are already allocated, maybe with different labels

	for id, key := range kvstoreIDs {
		scopedLog := log.With(
			logfields.Identity, id,
			logfields.IdentityLabels, key.GetKey(),
		)

		ctx, cancel := context.WithTimeout(ctx, opTimeout)
		_, err := crdBackend.AllocateID(ctx, id, key)
		switch {
		case err != nil && k8serrors.IsAlreadyExists(err):
			alreadyAllocatedKeys[id] = key

		case err != nil:
			scopedLog.Error(
				"Cannot allocate CRD ID. This key will be allocated with a new numeric identity",
				logfields.Error, err,
				logfields.Key, key,
			)

		default:
			scopedLog.Info(
				"Migrated identity",
			)
		}
		cancel()
	}

	// Handle IDs that have conflicts. These can be:
	// 1- The same ID -> key (from a previous run). This is a no-op
	// 2- The same ID but with different labels. This is not ideal. A new ID is
	// allocated as a fallback.
	for id, key := range alreadyAllocatedKeys {
		scopedLog := log.With(
			logfields.Identity, id,
			logfields.IdentityLabels, key.GetKey(),
		)

		getCtx, getCancel := context.WithTimeout(ctx, opTimeout)
		upstreamKey, err := crdBackend.GetByID(getCtx, id)
		getCancel()
		scopedLog.Debug(
			"Looking at upstream key",
			logfields.Key, upstreamKey,
		)
		switch {
		case err != nil:
			scopedLog.Error("ID already allocated but we cannot verify whether it is the same key. It may not be migrated", logfields.Error, err)
			continue

		// nil returns mean the key doesn't exist. This shouldn't happen, but treat
		// it like a mismatch and allocate it. The allocator will find it if it has
		// been re-allocated via master key protection.
		case upstreamKey == nil && err == nil:
			// fallthrough

		case key.GetKey() == upstreamKey.GetKey():
			scopedLog.Info("ID was already allocated to this key. It is already migrated")
			continue
		}

		scopedLog = log.With(
			logfields.IdentityOld, id,
			logfields.IdentityLabels, key.GetKey(),
		)
		scopedLog.Warn("ID is allocated to a different key in CRD. A new ID will be allocated for the this key")

		ctx, cancel := context.WithTimeout(context.Background(), opTimeout)
		defer cancel()
		newID, actuallyAllocated, _, err := crdAllocator.Allocate(ctx, key)
		switch {
		case err != nil:
			scopedLog.Error(
				"Cannot allocate CRD ID",
				logfields.Error, err,
				logfields.Key, key,
			)
			continue

		case !actuallyAllocated:
			scopedLog.Debug("Expected to allocate ID but this ID->key mapping re-existed")
		}

		scopedLog.Info(
			"New ID allocated for key in CRD",
			logfields.IdentityOld, id,
			logfields.IdentityNew, newID,
			logfields.IdentityLabels, key.GetKey(),
		)
	}
	return nil
}

// initK8s connects to k8s with a allocator.Backend and an initialized
// allocator.Allocator, using the k8s config passed into the command.
func initK8s(ctx context.Context, clientset k8sClient.Clientset) (crdBackend allocator.Backend, crdAllocator *allocator.Allocator) {
	log.Info("Setting up kubernetes client")

	// Update CRDs to ensure ciliumIdentity is present
	ciliumClient.RegisterCRDs(log, clientset)

	// Create a CRD Backend
	crdBackend, err := identitybackend.NewCRDBackend(log, identitybackend.CRDBackendConfiguration{
		Store:    nil,
		StoreSet: &atomic.Bool{},
		Client:   clientset,
		KeyFunc:  (&cacheKey.GlobalIdentity{}).PutKeyFromMap,
	})
	if err != nil {
		logging.Fatal(log, "Cannot create CRD identity backend", logfields.Error, err)
	}

	// Create a real allocator with CRD as the backend. This mimics the setup in
	// pkg/allocator/cache
	//
	// FIXME: add options to handle clustermesh with this constructor parameter:
	//    allocator.WithPrefixMask(idpool.ID(option.Config.ClusterID<<identity.ClusterIDShift)))
	minID := idpool.ID(identity.GetMinimalAllocationIdentity(option.Config.ClusterID))
	maxID := idpool.ID(identity.GetMaximumAllocationIdentity(option.Config.ClusterID))
	crdAllocator, err = allocator.NewAllocator(log, &cacheKey.GlobalIdentity{}, crdBackend, allocator.WithMax(maxID), allocator.WithMin(minID))
	if err != nil {
		logging.Fatal(log, "Unable to initialize Identity Allocator with CRD backend to allocate identities with already allocated IDs", logfields.Error, err)
	}

	// Wait for the initial sync to complete
	if err := crdAllocator.WaitForInitialSync(ctx); err != nil {
		logging.Fatal(log, "Error waiting for k8s identity allocator to sync. No identities have been migrated.", logfields.Error, err)
	}

	return crdBackend, crdAllocator
}

// initKVStore connects to the kvstore with a allocator.Backend, initialised to
// find identities at the default cilium paths.
func initKVStore(ctx, wctx context.Context) (kvstoreBackend allocator.Backend) {
	log.Info("Setting up kvstore client")
	client := setupKvstore(ctx, log)

	idPath := path.Join(cache.IdentitiesPath, "id")
	kvstoreBackend, err := kvstoreallocator.NewKVStoreBackend(log, kvstoreallocator.KVStoreBackendConfiguration{BasePath: cache.IdentitiesPath, Suffix: idPath, Typ: &cacheKey.GlobalIdentity{}, Backend: client})
	if err != nil {
		logging.Fatal(log, "Cannot create kvstore identity backend", logfields.Error, err)
	}

	return kvstoreBackend
}

// getKVStoreIdentities lists all identities in the kvstore. It will wait for
// the listing to complete.
func getKVStoreIdentities(ctx context.Context, kvstoreBackend allocator.Backend) (identities map[idpool.ID]allocator.AllocatorKey, err error) {
	identities = make(map[idpool.ID]allocator.AllocatorKey)
	listDone := make(chan struct{})

	var wg sync.WaitGroup
	wg.Add(1)
	// Make sure that the watcher terminated before returning, to prevent parallel
	// modifications to the identities map afterwards.
	defer wg.Wait()

	cctx, cancel := context.WithCancel(ctx)
	go func() {
		defer wg.Done()
		kvstoreBackend.ListAndWatch(cctx, kvstoreListHandler{
			onUpsert: func(id idpool.ID, key allocator.AllocatorKey) {
				log.Debug(
					"kvstore listed ID",
					logfields.Identity, id,
					logfields.Key, key,
				)
				identities[id] = key
			},
			onListDone: func() {
				close(listDone)
				cancel()
			},
		})
	}()
	// This makes the ListAndWatch exit after the initial listing or on a timeout
	// that exits this function

	// Wait for the listing to complete
	select {
	case <-listDone:
		log.Debug("kvstore ID list complete")

	case <-ctx.Done():
		return nil, errors.New("Timeout while listing identities")
	}

	return identities, nil
}

// kvstoreListHandler is a dummy type to receive callbacks from the kvstore subsystem
type kvstoreListHandler struct {
	onUpsert   func(id idpool.ID, key allocator.AllocatorKey)
	onListDone func()
}

func (h kvstoreListHandler) OnListDone()                                       { h.onListDone() }
func (h kvstoreListHandler) OnUpsert(id idpool.ID, key allocator.AllocatorKey) { h.onUpsert(id, key) }
func (h kvstoreListHandler) OnDelete(id idpool.ID, key allocator.AllocatorKey) {}
