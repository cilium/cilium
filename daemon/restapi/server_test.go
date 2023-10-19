package restapi

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/api/v1/server/restapi"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/statedb/grpc"
	"github.com/cilium/cilium/pkg/statedb/index"
)

// TestServer_StateDB tests the gRPC functionality of the API server using
// StateDB as the guinea pig.
//
// TODO: Probably want to structure the server so that the gRPC part is agnostic
// to the swagger CiliumAPIAPI so that e.g. pkg/statedb/grpc_test.go can
// do this test. CiliumAPIAPI would be just layered on top as "fallback" HTTP/1.1
// handler.
func TestServer_StateDB(t *testing.T) {
	primIndex := statedb.Index[int, int]{
		Name: "id",
		FromObject: func(obj int) index.KeySet {
			return index.NewKeySet(index.Int(obj))
		},
		FromKey: index.Int,
		Unique:  true,
	}

	var (
		db        *statedb.DB
		testTable statedb.RWTable[int]
	)

	h := hive.New(
		cell.Provide(func() *restapi.CiliumAPIAPI { return nil }),
		serverCell,
		statedb.Cell,
		statedb.NewTableCell[int]("test", primIndex),
		cell.Invoke(func(db_ *statedb.DB, t statedb.RWTable[int]) {
			db = db_
			testTable = t
		}),
	)
	hive.AddConfigOverride(
		h,
		func(cfg *APIServerConfig) {
			os.Remove("/tmp/test.sock")
			cfg.SocketPath = "/tmp/test.sock" // TODO tmpfile
		})

	require.NoError(t, h.Start(context.TODO()), "Start")

	client, err := statedb.NewClient("unix:/tmp/test.sock")
	require.NoError(t, err, "NewClient")

	resp, err := client.Meta(context.TODO(), &grpc.MetaRequest{})
	require.NoError(t, err, "Meta")

	fmt.Printf("resp: %+v\n", resp)

	wtxn := db.WriteTxn(testTable)
	testTable.Insert(wtxn, 100)
	testTable.Insert(wtxn, 200)
	testTable.Insert(wtxn, 300)
	wtxn.Commit()

	remoteTestTable := statedb.NewRemoteTable[int](client, "test")
	iter, err := remoteTestTable.Get(context.TODO(), primIndex.Query(100))
	require.NoError(t, err, "Get")
	items := statedb.Collect(iter)
	require.ElementsMatch(t, items, []int{100})

	iter, err = remoteTestTable.LowerBound(context.TODO(), primIndex.Query(200))
	require.NoError(t, err, "LowerBound")
	items = statedb.Collect(iter)
	require.ElementsMatch(t, items, []int{200, 300})

	ctx, cancel := context.WithCancel(context.TODO())
	watchIter, err := remoteTestTable.Watch(ctx)
	require.NoError(t, err, "Watch")

	obj, deleted, rev, ok := watchIter.Next()
	require.True(t, ok)
	require.False(t, deleted)
	require.Greater(t, rev, statedb.Revision(0))
	require.Equal(t, obj, 100)

	obj, deleted, rev, ok = watchIter.Next()
	require.True(t, ok)
	require.False(t, deleted)
	require.Greater(t, rev, statedb.Revision(0))
	require.Equal(t, obj, 200)

	obj, deleted, rev, ok = watchIter.Next()
	require.True(t, ok)
	require.False(t, deleted)
	require.Greater(t, rev, statedb.Revision(0))
	require.Equal(t, obj, 300)

	wtxn = db.WriteTxn(testTable)
	testTable.Delete(wtxn, 100)
	wtxn.Commit()

	obj, deleted, rev, ok = watchIter.Next()
	require.True(t, ok)
	require.True(t, deleted)
	require.Greater(t, rev, statedb.Revision(0))
	require.Equal(t, obj, 100)

	cancel()
	_, _, _, ok = watchIter.Next()
	require.False(t, ok)

	client.Close()

	require.NoError(t, h.Stop(context.TODO()), "Stop")
}
