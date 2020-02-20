// Copyright 2019 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"context"
	"errors"
	"path"
	"time"

	"github.com/cilium/cilium/pkg/allocator"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/idpool"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/identitybackend"
	"github.com/cilium/cilium/pkg/kvstore"
	kvstoreallocator "github.com/cilium/cilium/pkg/kvstore/allocator"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
)

// opTimeout is the time allowed for each operation to complete. This includes
// listing, allocating and getting identities.
const opTimeout = 30 * time.Second

var migrateIdentityCmd = &cobra.Command{
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
	Run: func(cmd *cobra.Command, args []string) {
		migrateIdentities()
	},
}

// migrateIdentities attempts to mirror the security identities in the kvstore
// into k8s CRD-backed identities. The identities are snapshotted on startup
// and new identities created during migrations will not be seen.
// It is a little odd because it violates the cilium-agent assumption that only
// 1 Backend is active at a time.
// The steps are:
// 1- Connect to the kvstore via a pkg/allocatore.Backend
// 2- Connect to k8s
//   a- Create the ciliumidentity CRD if it is missing.
// 3- Iterate over each identity in the kvstore
//   a- Attempt to allocate the same numeric ID to this key
//   b- Already allocated identies that match ID->key are skipped
//   c- kvstore IDs with conflicting CRDs are allocated with a different ID
//
// NOTE: It is assumed that the migration is from k8s to k8s installations. The
// key labels different when running in non-k8s mode.
func migrateIdentities() {
	// The internal packages log things. Make sure they follow the setup of of
	// the CLI tool.
	logging.DefaultLogger.SetFormatter(log.Formatter)

	// Setup global configuration
	// These are defined in cilium/cmd/kvstore.go
	option.Config.KVStore = kvStore
	option.Config.KVStoreOpt = kvStoreOpts

	// This allows us to initialize a CRD allocator
	option.Config.IdentityAllocationMode = option.IdentityAllocationModeCRD // force CRD mode to make ciliumid

	// Init Identity backends
	initCtx, initCancel := context.WithTimeout(context.Background(), opTimeout)
	kvstoreBackend := initKVStore()

	crdBackend, crdAllocator := initK8s(initCtx)
	initCancel()

	log.Info("Listing identities in kvstore")
	listCtx, listCancel := context.WithTimeout(context.Background(), opTimeout)
	kvstoreIDs, err := getKVStoreIdentities(listCtx, kvstoreBackend)
	if err != nil {
		log.WithError(err).Fatal("Unable to initialize Identity Allocator with CRD backend to allocate identities with already allocated IDs")
	}
	listCancel()

	log.Info("Migrating identities to CRD")
	badKeys := make([]allocator.AllocatorKey, 0)                       // keys that have real errors
	alreadyAllocatedKeys := make(map[idpool.ID]allocator.AllocatorKey) // IDs that are already allocated, maybe with different labels

	for id, key := range kvstoreIDs {
		scopedLog := log.WithFields(logrus.Fields{
			logfields.Identity:       id,
			logfields.IdentityLabels: key.GetKey(),
		})

		ctx, cancel := context.WithTimeout(context.Background(), opTimeout)
		err := crdBackend.AllocateID(ctx, id, key)
		switch {
		case err != nil && k8serrors.IsAlreadyExists(err):
			alreadyAllocatedKeys[id] = key

		case err != nil:
			scopedLog.WithError(err).Error("Cannot allocate CRD ID. This key will be allocated with a new numeric identity")
			badKeys = append(badKeys, key)

		default:
			scopedLog.Info("Migrated identity")
		}
		cancel()
	}

	// Handle IDs that have conflicts. These can be:
	// 1- The same ID -> key (from a previous run). This is a no-op
	// 2- The same ID but with different labels. This is not ideal. A new ID is
	// allocated as a fallback.
	for id, key := range alreadyAllocatedKeys {
		scopedLog := log.WithFields(logrus.Fields{
			logfields.Identity:       id,
			logfields.IdentityLabels: key.GetKey(),
		})

		upstreamKey, err := crdBackend.GetByID(id)
		scopedLog.Debugf("Looking at upstream key with this ID: %+v", upstreamKey)
		switch {
		case err != nil:
			log.WithError(err).Error("ID already allocated but we cannot verify whether it is the same key. It may not be migrated")
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

		scopedLog = log.WithFields(logrus.Fields{
			logfields.OldIdentity:    id,
			logfields.IdentityLabels: key.GetKey(),
		})
		scopedLog.Warn("ID is allocated to a different key in CRD. A new ID will be allocated for the this key")

		ctx, cancel := context.WithTimeout(context.Background(), opTimeout)
		defer cancel()
		newID, actuallyAllocated, err := crdAllocator.Allocate(ctx, key)
		switch {
		case err != nil:
			log.WithError(err).Errorf("Cannot allocate new CRD ID for %v", key)
			continue

		case !actuallyAllocated:
			scopedLog.Debug("Expected to allocate ID but this ID->key mapping re-existed")
		}

		log.WithFields(logrus.Fields{
			logfields.OldIdentity:    id,
			logfields.Identity:       newID,
			logfields.IdentityLabels: key.GetKey(),
		}).Info("New ID allocated for key in CRD")
	}
}

// initK8s connects to k8s with a allocator.Backend and an initialized
// allocator.Allocator, using the k8s config passed into the command.
func initK8s(ctx context.Context) (crdBackend allocator.Backend, crdAllocator *allocator.Allocator) {
	log.Info("Setting up kubernetes client")

	k8sClientQPSLimit := viper.GetFloat64(option.K8sClientQPSLimit)
	k8sClientBurst := viper.GetInt(option.K8sClientBurst)

	k8s.Configure(k8sAPIServer, k8sKubeConfigPath, float32(k8sClientQPSLimit), k8sClientBurst)

	if err := k8s.Init(); err != nil {
		log.WithError(err).Fatal("Unable to connect to Kubernetes apiserver")
	}

	// Update CRDs to ensure ciliumIdentity is present
	k8s.RegisterCRDs()

	// Create a CRD Backend
	crdBackend, err := identitybackend.NewCRDBackend(identitybackend.CRDBackendConfiguration{
		NodeName: "cilium-preflight",
		Store:    nil,
		Client:   k8s.CiliumClient(),
		KeyType:  cache.GlobalIdentity{},
	})
	if err != nil {
		log.WithError(err).Fatal("Cannot create CRD identity backend")
	}

	// Create a real allocator with CRD as the backend. This mimics the setup in
	// pkg/allocator/cache
	//
	// FIXME: add options to handle clustermesh with this constructor parameter:
	//    allocator.WithPrefixMask(idpool.ID(option.Config.ClusterID<<identity.ClusterIDShift)))
	minID := idpool.ID(identity.MinimalAllocationIdentity)
	maxID := idpool.ID(identity.MaximumAllocationIdentity)
	crdAllocator, err = allocator.NewAllocator(cache.GlobalIdentity{}, crdBackend,
		allocator.WithMax(maxID), allocator.WithMin(minID))
	if err != nil {
		log.WithError(err).Fatal("Unable to initialize Identity Allocator with CRD backend to allocate identities with already allocated IDs")
	}

	// Wait for the initial sync to complete
	if err := crdAllocator.WaitForInitialSync(ctx); err != nil {
		log.WithError(err).Fatal("Error waiting for k8s identity allocator to sync. No identities have been migrated.")
	}

	return crdBackend, crdAllocator
}

// initKVStore connects to the kvstore with a allocator.Backend, initialised to
// find identities at the default cilium paths.
func initKVStore() (kvstoreBackend allocator.Backend) {
	log.Info("Setting up kvstore client")
	setupKvstore()

	idPath := path.Join(cache.IdentitiesPath, "id")
	kvstoreBackend, err := kvstoreallocator.NewKVStoreBackend(cache.IdentitiesPath, idPath, cache.GlobalIdentity{}, kvstore.Client())
	if err != nil {
		log.WithError(err).Fatal("Cannot create kvstore identity backend")
	}

	return kvstoreBackend
}

// getKVStoreIdentities lists all identities in the kvstore. It will wait for
// the listing to complete.
func getKVStoreIdentities(ctx context.Context, kvstoreBackend allocator.Backend) (identities map[idpool.ID]allocator.AllocatorKey, err error) {
	identities = make(map[idpool.ID]allocator.AllocatorKey)
	stopChan := make(chan struct{})

	go kvstoreBackend.ListAndWatch(kvstoreListHandler{
		onAdd: func(id idpool.ID, key allocator.AllocatorKey) {
			log.Debugf("kvstore listed ID: %+v -> %+v", id, key)
			identities[id] = key
		},
		onListDone: func() {
			close(stopChan)
		},
	}, stopChan)
	// This makes the ListAndWatch exit after the initial listing or on a timeout
	// that exits this function

	// Wait for the listing to complete
	select {
	case <-stopChan:
		log.Debug("kvstore ID list complete")

	case <-ctx.Done():
		return nil, errors.New("Timeout while listing identities")
	}

	return identities, nil
}

// kvstoreListHandler is a dummy type to receive callbacks from the kvstore subsystem
type kvstoreListHandler struct {
	onAdd      func(id idpool.ID, key allocator.AllocatorKey)
	onListDone func()
}

func (h kvstoreListHandler) OnListDone()                                       { h.onListDone() }
func (h kvstoreListHandler) OnAdd(id idpool.ID, key allocator.AllocatorKey)    { h.onAdd(id, key) }
func (h kvstoreListHandler) OnModify(id idpool.ID, key allocator.AllocatorKey) {}
func (h kvstoreListHandler) OnDelete(id idpool.ID, key allocator.AllocatorKey) {}
