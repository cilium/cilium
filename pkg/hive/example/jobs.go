// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"context"
	"fmt"
	"math/rand"
	"runtime/pprof"
	"time"

	"github.com/sirupsen/logrus"
	"k8s.io/client-go/util/workqueue"

	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	"github.com/cilium/cilium/pkg/stream"
)

// This example shows a number of use cases in one cell. The cell starts by requesting the job.Registry
// by way of the constructor. The registry can create job groups; in most cases, one is enough.
// You can add jobs in the constructor to this group. Any jobs added in the constructor are queued
// until the lifecycle of the cell starts. The group is added to the lifecycle and manages jobs
// internally. You can also add jobs at runtime, which can be handy for dynamic workloads while still
// guaranteeing a clean shutdown.

// A job group cancels the context to all jobs when the lifecycle ends. Any job callbacks are
// expected to exit as soon as the ``ctx`` is "Done". The group makes sure that all
// jobs are properly shut down before the cell stops. Callbacks that do not stop within a reasonable
// amount of time may cause the hive to perform a hard shutdown.

// There are 3 job types: one-shot jobs, timer jobs, and observer jobs. One-shot jobs run a limited
// number of times: use them for brief jobs, or for jobs that span the entire lifecycle.
// Once the callback exits without error, it is never called again. Optionally, a one-shot job can include retry
// logic and/or trigger hive shutdown if it fails. Timers are called on a specified interval but they
// can also be externally triggered. Lastly, observer jobs are invoked for every event
// on a ``stream.Observable``.

var jobsCell = cell.Provide(newExampleCell)

type exampleCell struct {
	jobGroup job.Group
	workChan chan struct{}
	trigger  job.Trigger
	logger   logrus.FieldLogger
}

func newExampleCell(
	lifecycle cell.Lifecycle,
	logger logrus.FieldLogger,
	registry job.Registry,
	scope cell.Scope,
) *exampleCell {
	ex := exampleCell{
		jobGroup: registry.NewGroup(
			scope,
			job.WithLogger(logger),
			job.WithPprofLabels(pprof.Labels("cell", "example")),
		),
		workChan: make(chan struct{}, 3),
		trigger:  job.NewTrigger(),
		logger:   logger,
	}

	ex.jobGroup.Add(
		job.OneShot(
			"sync-on-startup",
			ex.sync,
			job.WithRetry(3, workqueue.DefaultControllerRateLimiter()),
			job.WithShutdown(), // if the retries fail, shutdown the hive
		),
		job.OneShot("daemon", ex.daemon),
		job.Timer("timer", ex.timer, 5*time.Second, job.WithTrigger(ex.trigger)),
		job.Observer("observer", ex.observer, stream.FromChannel(ex.workChan)),
	)

	lifecycle.Append(ex.jobGroup)

	return &ex
}

func (ex *exampleCell) sync(ctx context.Context, health cell.HealthReporter) error {
	for i := 0; i < 3; i++ {
		if err := ex.doSomeWork(); err != nil {
			return fmt.Errorf("doSomeWork: %w", err)
		}
	}

	return nil
}

func (ex *exampleCell) daemon(ctx context.Context, health cell.HealthReporter) error {
	for {
		randomTimeout := time.NewTimer(time.Duration(rand.Intn(3000)) * time.Millisecond)
		select {
		case <-ctx.Done():
			return nil

		case <-randomTimeout.C:
			ex.doSomeWork()
		}
	}
}

func (ex *exampleCell) timer(ctx context.Context) error {
	if err := ex.doSomeWork(); err != nil {
		return fmt.Errorf("doSomeWork: %w", err)
	}

	return nil
}

func (ex *exampleCell) Trigger() {
	ex.trigger.Trigger()
}

func (ex *exampleCell) observer(ctx context.Context, event struct{}) error {
	ex.logger.Info("Observed event")
	return nil
}

func (ex *exampleCell) HeavyLifting() {
	ex.jobGroup.Add(job.OneShot("long-running-job", func(ctx context.Context, health cell.HealthReporter) error {
		for i := 0; i < 1_000_000; i++ {
			// Do some heavy lifting
		}
		return nil
	}))
}

func (ex *exampleCell) doSomeWork() error {
	ex.workChan <- struct{}{}
	return nil
}
