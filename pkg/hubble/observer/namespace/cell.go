// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package namespace

import (
	"context"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
)

var Cell = cell.ProvidePrivate(func(jobGroup job.Group) Manager {
	m := NewManager()
	jobGroup.Add(job.Timer(
		"hubble-namespace-cleanup",
		func(_ context.Context) error {
			m.cleanupNamespaces()
			return nil
		},
		cleanupInterval,
	))
	return m
})
