package statedb

import (
	"bytes"
	"context"
	"encoding/gob"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/cilium/cilium/pkg/api"
	"github.com/cilium/cilium/pkg/hive/cell"
	statedbGRPC "github.com/cilium/cilium/pkg/statedb/grpc"
)

type grpcServer struct {
	db *DB
}

// Meta implements grpc.StateDBServer.
func (s *grpcServer) Meta(ctx context.Context, req *statedbGRPC.MetaRequest) (*statedbGRPC.MetaResponse, error) {
	var resp statedbGRPC.MetaResponse
	for name, meta := range s.db.tables {
		table := statedbGRPC.Table{
			Name: name,
		}
		table.Index = append(table.Index, meta.primaryIndexer().name)
		for _, indexer := range meta.secondaryIndexers() {
			table.Index = append(table.Index, indexer.name)
		}
		resp.Table = append(resp.Table, &table)
	}
	return &resp, nil
}

// Get implements grpc.StateDBServer
func (s *grpcServer) Get(req *statedbGRPC.QueryRequest, resp statedbGRPC.StateDB_GetServer) error {
	txn := s.db.ReadTxn()
	// FIXME: panics in indexReadTxn now a problem
	indexTxn := txn.getTxn().indexReadTxn(req.Table, req.Index)

	iter := indexTxn.Root().Iterator()
	iter.SeekPrefixWatch(req.Key)

	for _, obj, ok := iter.Next(); ok; _, obj, ok = iter.Next() {
		var buf bytes.Buffer
		enc := gob.NewEncoder(&buf)
		if err := enc.Encode(obj); err != nil {
			return fmt.Errorf("gob.Encode: %w", err)
		}
		resp.Send(&statedbGRPC.Object{
			Revision: obj.revision,
			Value:    buf.Bytes(),
		})
	}
	return nil
}

// LowerBound implements grpc.StateDBServer
func (s *grpcServer) LowerBound(req *statedbGRPC.QueryRequest, resp statedbGRPC.StateDB_LowerBoundServer) error {
	txn := s.db.ReadTxn()
	// FIXME: panics in indexReadTxn now a problem
	indexTxn := txn.getTxn().indexReadTxn(req.Table, req.Index)

	iter := indexTxn.Root().Iterator()
	iter.SeekLowerBound(req.Key)
	for _, obj, ok := iter.Next(); ok; _, obj, ok = iter.Next() {
		var buf bytes.Buffer
		enc := gob.NewEncoder(&buf)
		if err := enc.Encode(obj); err != nil {
			return fmt.Errorf("gob.Encode: %w", err)
		}
		resp.Send(&statedbGRPC.Object{
			Revision: obj.revision,
			Value:    buf.Bytes(),
		})
	}
	return nil
}

// Watch implements grpc.StateDBServer
func (s *grpcServer) Watch(req *statedbGRPC.WatchRequest, resp statedbGRPC.StateDB_WatchServer) error {
	table, ok := s.db.tables[req.Table]
	if !ok {
		return fmt.Errorf("table %q not found", req.Table)
	}
	wtxn := s.db.WriteTxn(table)
	defer wtxn.Abort()
	dt := baseDeleteTracker{
		db:          s.db,
		trackerName: "grpc-watch",
		tableMeta:   table,
	}
	if err := wtxn.getTxn().addDeleteTracker(&dt); err != nil {
		return fmt.Errorf("addDeleteTracker: %w", err)
	}
	wtxn.Commit()
	defer dt.Close()

	// Start from revision 0 to stream all current objects and then follow
	// with incremental updates and deletes.
	rev := Revision(0)

	for {
		var (
			err   error
			watch <-chan struct{}
		)

		rev, watch, err = dt.process(s.db.ReadTxn(), rev,
			func(obj any, deleted bool, rev Revision) error {
				var buf bytes.Buffer
				enc := gob.NewEncoder(&buf)
				if err := enc.Encode(obj); err != nil {
					return fmt.Errorf("gob.Encode: %w", err)
				}
				response := &statedbGRPC.WatchResponse{
					Object: &statedbGRPC.Object{
						Revision: rev,
						Value:    buf.Bytes(),
					},
					Deleted: deleted,
				}
				return resp.Send(response)
			})

		if err != nil {
			return err
		}

		select {
		case <-resp.Context().Done():
			return nil
		case <-watch:
		}
	}
}

var _ statedbGRPC.StateDBServer = &grpcServer{}

type grpcOut struct {
	cell.Out

	Service api.GRPCService `group:"grpc-services"`
}

func newGRPCService(db *DB) grpcOut {
	return grpcOut{
		Service: api.GRPCService{
			Service: &statedbGRPC.StateDB_ServiceDesc,
			Impl:    &grpcServer{db: db},
		},
	}
}

type RemoteTable[Obj any] struct {
	tableName TableName
	client    statedbGRPC.StateDBClient
}

func (t *RemoteTable[Obj]) Get(ctx context.Context, q Query[Obj]) (Iterator[Obj], error) {
	req := statedbGRPC.QueryRequest{
		Table: t.tableName,
		Index: q.index,
		Key:   q.key,
		Limit: 0,
	}
	resp, err := t.client.Get(ctx, &req)
	if err != nil {
		return nil, err
	}
	return &getIterator[Obj]{resp}, nil
}

type getIterator[Obj any] struct {
	Recver interface {
		Recv() (*statedbGRPC.Object, error)
	}
}

func (it *getIterator[Obj]) Next() (obj Obj, revision uint64, ok bool) {
	protoObj, err := it.Recver.Recv()
	if err != nil {
		// FIXME handle errors with logging or use a different iterator interface?
		return
	}
	revision = protoObj.Revision
	err = gob.NewDecoder(bytes.NewBuffer(protoObj.Value)).Decode(&obj)
	if err != nil {
		return
	}
	ok = true
	return
}

// WatchIterator for iterating objects returned by Watch().
type WatchIterator[Obj any] interface {
	// Next returns the next object and its revision if ok is true, otherwise
	// zero values to mean that the iteration has finished.
	Next() (obj Obj, deleted bool, rev Revision, ok bool)
}

type watchIterator[Obj any] struct {
	Recver interface {
		Recv() (*statedbGRPC.WatchResponse, error)
	}
}

func (it *watchIterator[Obj]) Next() (obj Obj, deleted bool, revision uint64, ok bool) {
	resp, err := it.Recver.Recv()
	if err != nil {
		// FIXME handle errors with logging or use a different iterator interface?
		return
	}
	revision = resp.Object.Revision
	deleted = resp.Deleted
	err = gob.NewDecoder(bytes.NewBuffer(resp.Object.Value)).Decode(&obj)
	if err != nil {
		return
	}
	ok = true
	return
}

func (t *RemoteTable[Obj]) Watch(ctx context.Context) (WatchIterator[Obj], error) {
	req := statedbGRPC.WatchRequest{
		Table: t.tableName,
	}
	resp, err := t.client.Watch(ctx, &req)
	if err != nil {
		return nil, err
	}

	return &watchIterator[Obj]{resp}, nil
}

func NewRemoteTable[Obj any](client Client, table TableName) *RemoteTable[Obj] {
	return &RemoteTable[Obj]{tableName: table, client: client}
}

type Client statedbGRPC.StateDBClient

func NewClient(addr string) (Client, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// The connection is local, so we assume using insecure connection is safe in
	// this context.
	conn, err := grpc.DialContext(ctx, addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock())
	if err != nil {
		return nil, err
	}
	return Client(statedbGRPC.NewStateDBClient(conn)), nil
}
