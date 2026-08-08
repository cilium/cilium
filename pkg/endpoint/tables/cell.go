// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tables

import (
	"context"
	"sync"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	ciliumv2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	k8stypes "github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/option"
)

// Cell provides a StateDB table of Cilium-managed endpoints.
var Cell = cell.Module(
	"endpoint-tables",
	"Cilium-managed endpoint tables",

	cell.ProvidePrivate(NewEndpointTable),
	cell.Provide(statedb.RWTable[*Endpoint].ToTable),
	cell.Invoke(
		registerEndpointResourceReflector,
		registerKVStoreIPIdentityReflector,
	),
)

type endpointResourceReflectorParams struct {
	cell.In

	JobGroup     job.Group
	DB           *statedb.DB
	Table        statedb.RWTable[*Endpoint]
	ClusterInfo  cmtypes.ClusterInfo
	DaemonConfig *option.DaemonConfig

	CEPs resource.Resource[*k8stypes.CiliumEndpoint]
	CESs resource.Resource[*ciliumv2alpha1.CiliumEndpointSlice]
}

func registerEndpointResourceReflector(p endpointResourceReflectorParams) {
	wtxn := p.DB.WriteTxn(p.Table)
	initDone := p.Table.RegisterInitializer(wtxn, "endpoint-resource-reflector")
	wtxn.Commit()

	r := endpointResourceReflector{
		db:          p.DB,
		table:       p.Table,
		writer:      NewWriter(p.Table),
		clusterName: p.ClusterInfo.Name,
		useCES:      p.DaemonConfig.EnableCiliumEndpointSlice,
		ceps:        p.CEPs,
		cess:        p.CESs,
		initDone:    initDone,
		cesSources:  make(map[resource.Key][]SourceKey),
	}
	p.JobGroup.Add(job.OneShot("endpoint-resource-reflector", r.run))
}

type endpointResourceReflector struct {
	db          *statedb.DB
	table       statedb.RWTable[*Endpoint]
	writer      *Writer
	clusterName string
	useCES      bool
	ceps        resource.Resource[*k8stypes.CiliumEndpoint]
	cess        resource.Resource[*ciliumv2alpha1.CiliumEndpointSlice]
	initDone    func(statedb.WriteTxn)
	initOnce    sync.Once
	cesSources  map[resource.Key][]SourceKey
}

func (r *endpointResourceReflector) run(ctx context.Context, _ cell.Health) error {
	if r.useCES {
		return r.runCES(ctx)
	}
	return r.runCEP(ctx)
}

func (r *endpointResourceReflector) markInitialized() {
	r.initOnce.Do(func() {
		wtxn := r.db.WriteTxn(r.table)
		defer wtxn.Abort()
		r.initDone(wtxn)
		wtxn.Commit()
	})
}

func (r *endpointResourceReflector) runCEP(ctx context.Context) error {
	if r.ceps == nil {
		r.markInitialized()
		return nil
	}

	for event := range r.ceps.Events(ctx) {
		var err error
		switch event.Kind {
		case resource.Sync:
			r.markInitialized()
		case resource.Upsert:
			err = r.upsertCEP(event.Object)
		case resource.Delete:
			err = r.deleteCEP(event.Object)
		}
		event.Done(err)
	}
	return nil
}

func (r *endpointResourceReflector) runCES(ctx context.Context) error {
	if r.cess == nil {
		r.markInitialized()
		return nil
	}

	for event := range r.cess.Events(ctx) {
		var err error
		switch event.Kind {
		case resource.Sync:
			r.markInitialized()
		case resource.Upsert:
			err = r.upsertCES(event.Key, event.Object)
		case resource.Delete:
			err = r.deleteCES(event.Key, event.Object)
		}
		event.Done(err)
	}
	return nil
}

func (r *endpointResourceReflector) upsertCEP(cep *k8stypes.CiliumEndpoint) error {
	src, err := SourceFromCEP(r.clusterName, cep)
	if err != nil {
		return err
	}

	wtxn := r.db.WriteTxn(r.table)
	defer wtxn.Abort()
	_, err = r.writer.Upsert(wtxn, src)
	if err != nil {
		return err
	}
	wtxn.Commit()
	return nil
}

func (r *endpointResourceReflector) deleteCEP(cep *k8stypes.CiliumEndpoint) error {
	src, err := SourceFromCEP(r.clusterName, cep)
	if err != nil {
		return err
	}

	wtxn := r.db.WriteTxn(r.table)
	defer wtxn.Abort()
	_, _, err = r.writer.DeleteSource(wtxn, src.Key)
	if err != nil {
		return err
	}
	wtxn.Commit()
	return nil
}

func (r *endpointResourceReflector) upsertCES(key resource.Key, ces *ciliumv2alpha1.CiliumEndpointSlice) error {
	sources, err := SourcesFromCES(r.clusterName, ces)
	if err != nil {
		return err
	}

	current := make(map[SourceKey]struct{}, len(sources))
	wtxn := r.db.WriteTxn(r.table)
	defer wtxn.Abort()

	for _, src := range sources {
		current[src.Key] = struct{}{}
		if _, err := r.writer.Upsert(wtxn, src); err != nil {
			return err
		}
	}

	for _, oldKey := range r.cesSources[key] {
		if _, ok := current[oldKey]; ok {
			continue
		}
		if _, _, err := r.writer.DeleteSource(wtxn, oldKey); err != nil {
			return err
		}
	}

	r.cesSources[key] = sourceKeys(sources)
	wtxn.Commit()
	return nil
}

func (r *endpointResourceReflector) deleteCES(key resource.Key, ces *ciliumv2alpha1.CiliumEndpointSlice) error {
	sourceKeysToDelete := r.cesSources[key]
	if len(sourceKeysToDelete) == 0 && ces != nil {
		sources, err := SourcesFromCES(r.clusterName, ces)
		if err != nil {
			return err
		}
		sourceKeysToDelete = sourceKeys(sources)
	}

	wtxn := r.db.WriteTxn(r.table)
	defer wtxn.Abort()
	for _, sourceKey := range sourceKeysToDelete {
		if _, _, err := r.writer.DeleteSource(wtxn, sourceKey); err != nil {
			return err
		}
	}
	delete(r.cesSources, key)
	wtxn.Commit()
	return nil
}

func sourceKeys(sources []Source) []SourceKey {
	keys := make([]SourceKey, 0, len(sources))
	for _, src := range sources {
		keys = append(keys, src.Key)
	}
	return keys
}

type kvstoreIPIdentityReflectorParams struct {
	cell.In

	DB      *statedb.DB
	Table   statedb.RWTable[*Endpoint]
	Watcher *ipcache.LocalIPIdentityWatcher `optional:"true"`
}

func registerKVStoreIPIdentityReflector(p kvstoreIPIdentityReflectorParams) {
	if p.Watcher == nil {
		return
	}
	p.Watcher.AddIPIdentityPairObserver(&kvstoreIPIdentityReflector{
		db:     p.DB,
		table:  p.Table,
		writer: NewWriter(p.Table),
	})
}

type kvstoreIPIdentityReflector struct {
	db     *statedb.DB
	table  statedb.RWTable[*Endpoint]
	writer *Writer
}

func (r *kvstoreIPIdentityReflector) OnIPIdentityPairUpsert(clusterName string, pair *identity.IPIdentityPair) error {
	if pair == nil || !pair.IsHost() {
		return nil
	}
	src, err := SourceFromIPIdentityPair(clusterName, pair)
	if err != nil {
		return err
	}

	wtxn := r.db.WriteTxn(r.table)
	defer wtxn.Abort()
	_, err = r.writer.Upsert(wtxn, src)
	if err != nil {
		return err
	}
	wtxn.Commit()
	return nil
}

func (r *kvstoreIPIdentityReflector) OnIPIdentityPairDelete(clusterName string, pair *identity.IPIdentityPair) error {
	if pair == nil {
		return nil
	}
	prefix := pair.PrefixString()
	if prefix == "" || prefix == "<nil>" {
		return nil
	}

	wtxn := r.db.WriteTxn(r.table)
	defer wtxn.Abort()
	_, _, err := r.writer.DeleteSource(wtxn, KVStoreSourceKey(clusterName, prefix))
	if err != nil {
		return err
	}
	wtxn.Commit()
	return nil
}
