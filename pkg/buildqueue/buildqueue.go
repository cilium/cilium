// Copyright 2016-2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package buildqueue

import (
	"fmt"
	"runtime"
	"sync"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/metrics"
)

const (
	// minWorkerThreads is the minimum number of worker threads to use
	// regardless of the number of cores available in the system
	minWorkerThreads = 2

	// buildQueueSize is the maximum number of builds that can be queued
	// before Enqueue() starts blocking
	buildQueueSize = 4096
)

// buildStatusMap contains the build status of all queued builders
type buildStatusMap map[string]*buildStatus

// buildGroup is a logical grouping of builds
type buildGroup struct {
	// running is the number of builds running of this group
	running int

	// waiting is the number of builds currently blocked in
	// waitForBuildCondition(), waiting for their build condition to be
	// met.
	waiting int

	// condition is the condition that must be met throughout the build.
	// The condition function is called with q.mutex held.
	condition func(q *BuildQueue) bool
}

// waitForBuildCondition is called by a build which has been dequeued and
// assigned to a worker and will block until the build condition associated
// with the builder is being met, e.g. the exclusive build condition will block
// until all currently running regular builds have completed.
func (b *buildGroup) waitForBuildCondition(q *BuildQueue) {
	metric := metrics.BuildQueueEntries.With(map[string]string{
		metrics.LabelBuildQueueName: q.name,
		metrics.LabelBuildState:     metrics.BuildStateBlocked,
	})

	q.mutex.Lock()
	b.waiting++
	metric.Inc()
	for !b.condition(q) {
		q.waitingBuilders.Wait()
	}

	metric.Dec()
	b.waiting--
	b.running++
	q.mutex.Unlock()
}

// finish signals that a build of this buildGroup has completed
func (b *buildGroup) finish(q *BuildQueue, buildStatus *buildStatus) {
	q.mutex.Lock()
	b.running--
	buildStatus.currentBuild = nil
	q.mutex.Unlock()

	q.waitingBuilders.Broadcast()
}

// BuildQueue is a queueing system for builds
type BuildQueue struct {
	// name is the name of the build queue
	name string

	// mutex protects access to the buildStatus map and for the
	// waitingBuilders sync.Condition in waitForBuildCondition()
	mutex lock.Mutex

	// buildStatus contains the status of all builders indexed by UUID
	buildStatus buildStatusMap

	// workerBuildQueue is a buffered channel that contains all scheduled
	// builds
	workerBuildQueue chan Builder

	// stopWorker is used to stop worker threads and exclusive builders
	// when the build queue is shutdown. Workers will run until this
	// channel is closed.
	stopWorker chan struct{}

	// regularBuilds accounts for running regular builds
	regularBuilds buildGroup

	// exclusiveBuilds accounts for running exclusive builds
	exclusiveBuilds buildGroup

	// waitingBuilders is used to wake up builders waiting for their
	// condition to be met
	waitingBuilders *sync.Cond
}

// NewBuildQueue returns a new build queue
func NewBuildQueue(name string) *BuildQueue {
	q := &BuildQueue{
		name:             name,
		buildStatus:      buildStatusMap{},
		workerBuildQueue: make(chan Builder, buildQueueSize),
		stopWorker:       make(chan struct{}, 0),
		regularBuilds: buildGroup{
			condition: func(q *BuildQueue) bool {
				return q.exclusiveBuilds.waiting == 0 && q.exclusiveBuilds.running == 0
			},
		},
		exclusiveBuilds: buildGroup{
			condition: func(q *BuildQueue) bool {
				return q.exclusiveBuilds.running == 0 && q.regularBuilds.running == 0
			},
		},
	}

	q.waitingBuilders = sync.NewCond(&q.mutex)

	nWorkers := numWorkerThreads()
	for w := 0; w < nWorkers; w++ {
		go q.runWorker()
	}

	return q
}

// Stop stops the build queue and terminates all workers
func (q *BuildQueue) Stop() {
	close(q.stopWorker)

	waitForCleanup := sync.WaitGroup{}

	q.mutex.Lock()
	for _, status := range q.buildStatus {
		waitForCleanup.Add(1)
		go func(b Builder) {
			q.Drain(b)
			waitForCleanup.Done()
		}(status.builder)
	}
	q.mutex.Unlock()

	waitForCleanup.Wait()
}

// numWorkerThreads returns the number of worker threads to use. This does not
// apply to exclusive builds.
func numWorkerThreads() int {
	ncpu := runtime.NumCPU()

	if ncpu < minWorkerThreads {
		return minWorkerThreads
	}
	return ncpu
}

// Buildable is an object that is buildable
type Buildable interface {
	// GetUUID must return a unique UUID of the object
	GetUUID() string
}

// Builder is an object that can build itself. A builder must also be Buildable
type Builder interface {
	Buildable

	// BuildQueued is called every time a builder is enqueued
	BuildQueued()

	// BuildsDequeued is called when a scheduled builder has been dequeued
	// for building or has been cancelled. The nbuilds accounts for the
	// number of builders folded together while the builder was queued.
	BuildsDequeued(nbuilds int, cancelled bool)

	// Build must build the Buildable. When a builder was cancelled,
	// Build() will not be called. When a builder is folded into an
	// existing builder, Build() is only called on the first builder.
	Build() error
}

// BuildNotification is a channel to receive the status of a build. The channel
// will receive true if the build was successful. The channel is buffered and
// is guaranteed to only be written to exactly once and is then immediately
// closed. It is up to the caller of Enqueue() to decide whether to read on the
// channel or not.
type BuildNotification <-chan bool

func newBuildNotification() chan bool {
	return make(chan bool, 1)
}

// build is what is returned by Enqueue() to provide information about the
// build
type build struct {
	builder Builder

	// uuid is the UUID of the Buildable
	uuid string

	// notificationChannels is a list of a channels that should be notified
	// about the completion of the build
	notificationChannels []chan bool
}

// createAndAddNotificationChannel creates and adds a build notification
// channel. This function may only be called while the build is not yet in
// progress.
func (b *build) createAndAddNotificationChannel() BuildNotification {
	notify := newBuildNotification()
	b.notificationChannels = append(b.notificationChannels, notify)
	return notify
}

// reportStatus reports the status of a build to all notification channels.
// This function may only be called if the build is the currentBuild. It may
// never be called while the build is still assigned to nextBuild.
func (b *build) reportStatus(q *BuildQueue, success bool) {
	for _, notify := range b.notificationChannels {
		notify <- success
		close(notify)
	}
}

// cancel cancels a scheduled and not yet running build. q.mutex must be held.
func (b *build) cancelScheduled(q *BuildQueue) int {
	numBuilds := b.numFolded()

	metrics.BuildQueueEntries.With(map[string]string{
		metrics.LabelBuildQueueName: q.name,
		metrics.LabelBuildState:     metrics.BuildStateWaiting,
	}).Sub(float64(numBuilds))

	b.reportStatus(q, false)

	return numBuilds
}

// numFolded returns the number of enqueued builders that have been folded into
// this build.
func (b *build) numFolded() int {
	// For each builder folded, the BuildNotification returned via
	// Enqueue() was added to the notoficiationChannels slice of the
	// primary build so we can use the length of the slice to determine the
	// number of folded builds.
	return len(b.notificationChannels)
}

func newBuild(b Builder, uuid string) *build {
	return &build{
		builder:              b,
		uuid:                 uuid,
		notificationChannels: []chan bool{},
	}
}

// buildStatus is the current status of a build
type buildStatus struct {
	builder Builder

	// curentBuild is the building information of any running build
	currentBuild *build

	// nextBuild is the building information of the next build for this
	// UUID
	nextBuild *build
}

func (q *BuildQueue) enqueueBuild(b Builder) (BuildNotification, bool) {
	q.mutex.Lock()
	build, enqueued := q.serializeBuild(b)
	notify := build.createAndAddNotificationChannel()
	builder := build.builder
	q.mutex.Unlock()

	metrics.BuildQueueEntries.With(map[string]string{
		metrics.LabelBuildQueueName: q.name,
		metrics.LabelBuildState:     metrics.BuildStateWaiting,
	}).Inc()

	// Call BuildQueued() on the builder, if the builder was folded, this
	// will not be the builder that was just enqueued.
	builder.BuildQueued()

	return notify, enqueued
}

// serializeBuild verifies whether the UUID of the Builder/Buildable is
// currently being built or already queued. If already queued but not yet being
// built, the build is folded into the already queued build by return the
// already queued build. If the UUID of the builder is currently being built, a
// new build is created and attached to nextBuild to schedule the build for
// queueing via needToBuildAgain().
//
// Returns true if the UUID was entirely unknown to the build queue. This
// indicates that the builder must be enqueued either via the workerBuildQueue
// or by spawning a go routine.
func (q *BuildQueue) serializeBuild(b Builder) (*build, bool) {
	uuid := b.GetUUID()
	build := newBuild(b, uuid)

	if buildStatus, ok := q.buildStatus[uuid]; ok {
		// If the builder is currently being built, prepare the next
		// build and store it in the nextBuild field. When the current
		// build finishes, the next build will automatically be added
		// to the workerBuildQueue
		if buildStatus.currentBuild != nil && buildStatus.nextBuild == nil {
			buildStatus.nextBuild = build
			return build, false
		}

		// The builder is already in the queue but not being built, the
		// build request will be fulfilled when the queued build is
		// executed. The caller can be notified to skip the build.
		return buildStatus.nextBuild, false
	}

	q.buildStatus[uuid] = &buildStatus{
		builder:   b,
		nextBuild: build,
	}

	return build, true
}

// Enqueue schedules Builder for building. A channel is returned to provide the
// ability to wait for the build to complete and check for success or failure.
//
// A regular build fullfils the following build guarantees:
// * The same Buildable, i.e. the same UUID, will not be built in parallel on
//   multiple workers.
// * The order in which regular builds are enqueued is maintained in the build
//   order across different Buildables. If the same Buildable is enqueued
//   multiple times, the buils are automatically folded together until the
//   build is executed. This means in practise that a specific Buildable can only
//   be in the build queue once.
// * In the presence of preemptive, exclusive builds, regular builds get a fair
//   chance to run but preemptive builds always preempt any queued, not yet
//   running regular build.
func (q *BuildQueue) Enqueue(b Builder) BuildNotification {
	notify, notInQueue := q.enqueueBuild(b)
	if notInQueue {
		// This should be non-blocking unless there is contention beyond
		// queueBuildSize in which case this will block until a slot in the
		// queue becomes available.
		q.workerBuildQueue <- b
	}

	return notify
}

// Remove removes the builder from the queue.
func (q *BuildQueue) Remove(b Buildable) {
	uuid := b.GetUUID()
	q.mutex.Lock()
	if status, ok := q.buildStatus[uuid]; ok {
		// Only remove the builder UUID from the buildStatus if no
		// build is currently running. If a build is running, the
		// buildStatus continue to be in place until the build has
		// completed.
		if status.currentBuild == nil {
			delete(q.buildStatus, uuid)
		}

		if status.nextBuild != nil {
			num := status.nextBuild.cancelScheduled(q)
			defer status.builder.BuildsDequeued(num, true)
		}
	}
	q.mutex.Unlock()
}

// Drain will drain the queue from any running or scheduled builds of a
// Buildable. If a build is running, the function will block for the build to
// complete. It is the responsibility of the caller that the Buildable does not
// get re-scheduled during the draining. Returns true if waiting was required.
func (q *BuildQueue) Drain(b Buildable) bool {
	uuid := b.GetUUID()
	waited := false

	q.mutex.Lock()
	status, ok := q.buildStatus[uuid]
	if ok {
		if status.nextBuild != nil {
			num := status.nextBuild.cancelScheduled(q)
			status.nextBuild = nil
			defer status.builder.BuildsDequeued(num, true)
		}

		for status.currentBuild != nil {
			waited = true
			q.waitingBuilders.Wait()
		}

		delete(q.buildStatus, uuid)
	}

	q.mutex.Unlock()
	return waited
}

func (q *BuildQueue) build(b Builder) error {
	metric := metrics.BuildQueueEntries.With(map[string]string{
		metrics.LabelBuildQueueName: q.name,
		metrics.LabelBuildState:     metrics.BuildStateRunning,
	})

	metric.Inc()
	err := b.Build()
	metric.Dec()

	return err
}

func (q *BuildQueue) runExclusiveBuild(b Builder) {
	uuid := b.GetUUID()

	for {
		currentBuild, buildStatus := q.nominateBuild(uuid)
		if currentBuild == nil {
			return
		}

		q.exclusiveBuilds.waitForBuildCondition(q)
		err := q.build(b)
		q.exclusiveBuilds.finish(q, buildStatus)

		currentBuild.reportStatus(q, err == nil)

		if !q.needToBuildAgain(uuid) {
			return
		}

		select {
		case <-q.stopWorker:
			return
		default:
		}
	}
}

// PreemptExclusive enqueues a build at the front of the queue and provides
// exclusive build access. All other builds enqueued via Enqueue()
// PreemptExclusive() have to finish before the exclusive build is executed.
// The exclusive build will then be the only build executed until it finishes.
//
// If an exclusive build for the same UUID is already enqueued but not yet
// running, the build will be folded into the already scheduled build but both
// notification channels will be notified.
func (q *BuildQueue) PreemptExclusive(b Builder) BuildNotification {
	notify, notInQueue := q.enqueueBuild(b)
	if notInQueue {
		go q.runExclusiveBuild(b)
	}

	return notify
}

// nominateBuild is called when a build has made it to the front of the build
// queue or the build is a preemptive build. nominateBuild will pull the
// build information from the buildStatus.nextBuild and nominate the build as
// buildStatus.currentBuild. nominateBuild() returns the build or nil if the
// build has since been cancelled.
func (q *BuildQueue) nominateBuild(uuid string) (*build, *buildStatus) {
	q.mutex.Lock()

	buildStatus, ok := q.buildStatus[uuid]
	if !ok || buildStatus.nextBuild == nil {
		// The builder has been removed since the build was
		// scheduled. Cancel the build.
		q.mutex.Unlock()
		return nil, nil
	}

	// Safety measure: q.serializeBuild() already ensures that the same
	// builder can only be queued once in the go channel. Double check here
	// that the builder is not running in another worker, if so, wait for
	// it to be done.
	for buildStatus.currentBuild != nil {
		q.waitingBuilders.Wait()
	}

	// Mark the scheduled build as building
	currentBuild := buildStatus.nextBuild
	buildStatus.currentBuild = currentBuild
	buildStatus.nextBuild = nil
	q.mutex.Unlock()

	num := currentBuild.numFolded()
	metrics.BuildQueueEntries.With(map[string]string{
		metrics.LabelBuildQueueName: q.name,
		metrics.LabelBuildState:     metrics.BuildStateWaiting,
	}).Sub(float64(num))

	buildStatus.builder.BuildsDequeued(num, false)

	return currentBuild, buildStatus
}

func (q *BuildQueue) needToBuildAgain(uuid string) bool {
	q.mutex.Lock()
	defer q.mutex.Unlock()

	buildStatus, ok := q.buildStatus[uuid]
	var nextBuild *build
	if ok {
		nextBuild = buildStatus.nextBuild

		// If no next build is scheduled, the builder can be
		// removed from the build status entirely
		if nextBuild == nil {
			delete(q.buildStatus, uuid)
		}
	}

	return nextBuild != nil
}

func (q *BuildQueue) runWorker() {
	for b := range q.workerBuildQueue {
		uuid := b.GetUUID()

		currentBuild, buildStatus := q.nominateBuild(uuid)
		if currentBuild == nil {
			return
		}

		q.regularBuilds.waitForBuildCondition(q)
		err := q.build(b)
		q.regularBuilds.finish(q, buildStatus)

		currentBuild.reportStatus(q, err == nil)

		// If another build for the same builder is scheduled, queue it
		if q.needToBuildAgain(uuid) {
			q.workerBuildQueue <- b
		}

		select {
		case <-q.stopWorker:
			return
		default:
		}
	}
}

// checkBuildGuarantees reports errors when build conditions are currently not
// being respected. This function is used for unit testing.
func (q *BuildQueue) checkBuildGuarantees() error {
	q.mutex.Lock()
	defer q.mutex.Unlock()

	buildCount := map[string]int{}

	for _, status := range q.buildStatus {
		if build := status.currentBuild; build != nil {
			buildCount[build.uuid]++
		}
	}

	switch {
	case q.exclusiveBuilds.running > 1:
		return fmt.Errorf("More than one exclusive build is running")
	case q.exclusiveBuilds.running > 0 && q.regularBuilds.running > 0:
		return fmt.Errorf("Exclusive build is running in parallel with regular build")
	default:
		for uuid, count := range buildCount {
			if count > 1 {
				return fmt.Errorf("UUID %s is being built in parallel", uuid)
			}
		}
	}

	return nil
}
