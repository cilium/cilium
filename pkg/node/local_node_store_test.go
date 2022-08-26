package node

import (
	"context"
	"sync"
	"testing"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/node/types"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"go.uber.org/fx"
	"golang.org/x/exp/slices"
)

func TestLocalNodeStore(t *testing.T) {
	var waitObserve sync.WaitGroup
	var observed []uint32
	expected := []uint32{1, 2, 3}

	waitObserve.Add(1)

	// observe observes changes to the LocalNodeStore and completes
	// waitObserve after the last change has been observed.
	observe := func(store LocalNodeStore) {
		store.Observe(context.TODO(),
			func(n types.Node) {
				observed = append(observed, n.NodeIdentity)
				if n.NodeIdentity == expected[len(expected)-1] {
					waitObserve.Done()
				}
			},
			func(err error) {},
		)
	}

	// update adds a start hook to the application that modifies
	// the local node.
	update := func(lc fx.Lifecycle, store LocalNodeStore) {
		lc.Append(fx.Hook{
			OnStart: func(context.Context) error {
				for _, i := range expected {
					store.Update(func(n *types.Node) {
						n.NodeIdentity = i
					})
				}
				return nil
			},
		})
	}

	hive := hive.New(
		viper.New(),
		pflag.NewFlagSet("", pflag.ContinueOnError),

		LocalNodeStoreCell,

		hive.NewCell("test",
			fx.Invoke(observe),
			fx.Invoke(update)),
	)

	app, err := hive.TestApp(t)
	if err != nil {
		t.Fatal(err)
	}

	app.RequireStart()

	// Wait until all values have been observed
	waitObserve.Wait()

	app.RequireStop()

	if !slices.Equal(observed, expected) {
		t.Fatalf("unexpected values observed: %v, expected: %v", observed, expected)
	}
}
