// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconcilerv2

import (
	"context"

	"github.com/cilium/cilium/pkg/bgpv1/manager/instance"
)

type FakeReconcilerParams struct {
	Name           string
	ReconcilerFunc func(_ context.Context, _ ReconcileParams) error
}

type fakeReconciler struct {
	name           string
	reconcilerFunc func(_ context.Context, _ ReconcileParams) error
}

func NewFakeReconciler(p FakeReconcilerParams) ConfigReconciler {
	return &fakeReconciler{
		name:           p.Name,
		reconcilerFunc: p.ReconcilerFunc,
	}
}

func (f *fakeReconciler) Name() string {
	return f.name
}

func (f *fakeReconciler) Priority() int {
	return 10 // hardcoded priority
}

func (f *fakeReconciler) Init(_ *instance.BGPInstance) error {
	return nil
}

func (f *fakeReconciler) Cleanup(_ *instance.BGPInstance) {}

func (f *fakeReconciler) Reconcile(ctx context.Context, params ReconcileParams) error {
	return f.reconcilerFunc(ctx, params)
}
