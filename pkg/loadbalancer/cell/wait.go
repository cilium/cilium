// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cell

import (
	"context"
	"log/slog"

	"github.com/cilium/statedb/reconciler"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/loadbalancer/writer"
	"github.com/cilium/cilium/pkg/time"
)

const logfieldInitializers = "initializers"

func newInitWaitFunc(log *slog.Logger, w *writer.Writer) loadbalancer.InitWaitFunc {
	return func(ctx context.Context) error {
		// Wait until the frontends table has been initialized.
		initialized, initDone := w.Frontends().Initialized(w.ReadTxn())
		for !initialized {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-initDone:
				initialized = true
			case <-time.After(time.Second):
				pending := w.Frontends().PendingInitializers(w.ReadTxn())
				log.Info("Still waiting for initializers", logfieldInitializers, pending)
			}
		}

		// Wait until no pending frontends remain, e.g. reconciliation has been
		// tried at least once.
		seen := sets.New[loadbalancer.L3n4Addr]()
		for {
			fes, watch := w.Frontends().AllWatch(w.ReadTxn())
			ready := true
			for fe := range fes {
				if seen.Has(fe.Address) {
					continue
				}
				if fe.Status.Kind == reconciler.StatusKindPending {
					ready = false
					break
				}
				seen.Insert(fe.Address)
			}
			if ready {
				return nil
			}

			// Wait until frontends table updates. We don't need to rate limit here
			// as reflector and reconciler processes in large batches.
			select {
			case <-watch:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
}
