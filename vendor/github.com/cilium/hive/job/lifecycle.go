// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package job

import (
	"context"
	"log/slog"
	"sync"

	"github.com/cilium/hive/cell"
)

// jobLifecycle tracks jobs started after the [registry] has been started
// (and thus not appended to application lifecycle) and to stop them when
// [registry] stops. Jobs that are stopped earlier are removed from the
// lifecycle.
type jobLifecycle struct {
	mu sync.Mutex

	// jobs is a doubly linked-list of started jobs. The head is the latest
	// started jobs, e.g. they're in the order they should be stopped.
	jobs *queuedJob

	// stopped is true if the lifecycle has been stopped and no new jobs
	// can be added.
	stopped bool
}

func (r *jobLifecycle) insertAndStart(job *queuedJob) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.stopped {
		return
	}

	if r.jobs != nil {
		r.jobs.prev = job
	}
	job.next = r.jobs
	r.jobs = job
	job.Start(context.Background())
}

func (r *jobLifecycle) remove(qj *queuedJob) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.jobs == nil {
		qj.prev = nil
		qj.next = nil
		return
	}

	if qj.next != nil {
		qj.next.prev = qj.prev
	}
	if qj == r.jobs {
		r.jobs = qj.next
	} else if qj.prev != nil {
		qj.prev.next = qj.next
	}
	qj.prev = nil
	qj.next = nil
}

func (r *jobLifecycle) stop(ctx cell.HookContext, log *slog.Logger) error {
	// Collect jobs to stop and unlink them. We must stop them without holding the
	// lock as [queuedJob.Stop] will try to call [jobLifecycle.remove].
	var jobsToStop []*queuedJob
	r.mu.Lock()
	var next *queuedJob
	for job := r.jobs; job != nil; job = next {
		next = job.next
		job.next = nil
		job.prev = nil
		jobsToStop = append(jobsToStop, job)
	}
	r.jobs = nil
	r.stopped = true
	r.mu.Unlock()
	for _, job := range jobsToStop {
		job.Stop(ctx)
		if ctx.Err() != nil {
			log.Error("Stop cancelled while waiting for job to stop",
				"job",
				job.job.info())
			break
		}
	}
	return ctx.Err()
}
