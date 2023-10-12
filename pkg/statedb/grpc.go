package statedb

import (
	"bytes"
	"context"
	"encoding/gob"
	"fmt"
	"time"

	iradix "github.com/hashicorp/go-immutable-radix/v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/cilium/cilium/pkg/api"
	"github.com/cilium/cilium/pkg/hive/cell"
	. "github.com/cilium/cilium/pkg/statedb/grpc"
	"github.com/cilium/cilium/pkg/statedb/index"
)

type grpcServer struct {
	db *DB
}

// Get implements grpc.StateDBServer
func (s *grpcServer) Get(req *QueryRequest, resp StateDB_GetServer) error {
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
		resp.Send(&Object{
			Revision: obj.revision,
			Value:    buf.Bytes(),
		})
	}
	return nil
}

// LowerBound implements grpc.StateDBServer
func (*grpcServer) LowerBound(*QueryRequest, StateDB_LowerBoundServer) error {
	panic("unimplemented")
}

// Watch implements grpc.StateDBServer
func (s *grpcServer) Watch(req *WatchRequest, resp StateDB_WatchServer) error {
	// FIXME: Delete tracking. Current typed DeleteTracker not usable here. Reimplement
	// it in a layered way?

	fmt.Printf(">>> Watch %s\n", req.Table)

	txn := s.db.ReadTxn().getTxn()
	seek := func(rev Revision) (*iradix.Iterator[object], <-chan struct{}) {
		indexTxn := txn.indexReadTxn(req.Table, RevisionIndex)
		root := indexTxn.Root()
		watch, _, _ := root.GetWatch(nil) // Watch channel of the root node
		iter := root.Iterator()
		iter.SeekLowerBound(index.Uint64(rev))

		fmt.Printf(">>> Seek to %d\n", rev)
		return iter, watch
	}
	rev := txn.GetRevision(req.Table)
	iter, watch := seek(rev)

	for {

		for _, obj, ok := iter.Next(); ok; _, obj, ok = iter.Next() {
			var buf bytes.Buffer
			enc := gob.NewEncoder(&buf)
			if err := enc.Encode(obj.data); err != nil {
				fmt.Printf(">>> gob.Encode fail %s\n", err)
				return fmt.Errorf("gob.Encode: %w", err)
			}
			protoObj := &Object{
				Revision: obj.revision,
				Value:    buf.Bytes(),
			}
			fmt.Printf(">>> Sent object\n")
			err := resp.Send(protoObj)

			/*
				err := resp.Send(&WatchResponse{
					Object:  protoObj,
					Deleted: false, // FIXME
				})*/
			if err != nil {
				fmt.Printf(">>> Send fail %s\n", err)
				return err
			}

			// Remember the highest revision sent.
			rev = obj.revision
		}

		select {
		case <-resp.Context().Done():
			return nil

		case <-watch:
			txn = s.db.ReadTxn().getTxn()
			iter, watch = seek(rev)

		}
	}
	return nil
}

var _ StateDBServer = &grpcServer{}

type grpcOut struct {
	cell.Out

	Service api.GRPCService `group:"grpc-services"`
}

func newGRPCService(db *DB) grpcOut {
	return grpcOut{
		Service: api.GRPCService{
			Service: &StateDB_ServiceDesc,
			Impl:    &grpcServer{db: db},
		},
	}
}

type RemoteTable[Obj any] struct {
	tableName TableName
	conn      *grpc.ClientConn
	client    StateDBClient
}

func (t *RemoteTable[Obj]) Get(ctx context.Context, q Query[Obj]) (Iterator[Obj], error) {
	req := QueryRequest{
		Table: t.tableName,
		Index: q.index,
		Key:   q.key,
		Limit: 0,
	}
	resp, err := t.client.Get(ctx, &req)
	if err != nil {
		return nil, err
	}
	return &recvIterator[Obj]{resp}, nil
}

type recvIterator[Obj any] struct {
	Recver interface{ Recv() (*Object, error) }
}

func (it *recvIterator[Obj]) Next() (obj Obj, revision uint64, ok bool) {
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

func (t *RemoteTable[Obj]) Watch(ctx context.Context) (Iterator[Obj], error) {
	req := WatchRequest{
		Table: t.tableName,
	}
	resp, err := t.client.Watch(ctx, &req)
	if err != nil {
		return nil, err
	}

	return &recvIterator[Obj]{resp}, nil
}

func NewRemoteTable[Obj any](table TableName, addr string) (*RemoteTable[Obj], error) {
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
	return &RemoteTable[Obj]{
		tableName: table,
		conn:      conn,
		client:    NewStateDBClient(conn)}, nil
}
