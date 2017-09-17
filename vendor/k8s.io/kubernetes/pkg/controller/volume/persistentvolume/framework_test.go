/*
Copyright 2016 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package persistentvolume

import (
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang/glog"

	"k8s.io/api/core/v1"
	storage "k8s.io/api/storage/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/diff"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/informers"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	storagelisters "k8s.io/client-go/listers/storage/v1"
	core "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/kubernetes/pkg/api/testapi"
	"k8s.io/kubernetes/pkg/controller"
	vol "k8s.io/kubernetes/pkg/volume"
)

// This is a unit test framework for persistent volume controller.
// It fills the controller with test claims/volumes and can simulate these
// scenarios:
// 1) Call syncClaim/syncVolume once.
// 2) Call syncClaim/syncVolume several times (both simulating "claim/volume
//    modified" events and periodic sync), until the controller settles down and
//    does not modify anything.
// 3) Simulate almost real API server/etcd and call add/update/delete
//    volume/claim.
// In all these scenarios, when the test finishes, the framework can compare
// resulting claims/volumes with list of expected claims/volumes and report
// differences.

// controllerTest contains a single controller test input.
// Each test has initial set of volumes and claims that are filled into the
// controller before the test starts. The test then contains a reference to
// function to call as the actual test. Available functions are:
//   - testSyncClaim - calls syncClaim on the first claim in initialClaims.
//   - testSyncClaimError - calls syncClaim on the first claim in initialClaims
//                          and expects an error to be returned.
//   - testSyncVolume - calls syncVolume on the first volume in initialVolumes.
//   - any custom function for specialized tests.
// The test then contains list of volumes/claims that are expected at the end
// of the test and list of generated events.
type controllerTest struct {
	// Name of the test, for logging
	name string
	// Initial content of controller volume cache.
	initialVolumes []*v1.PersistentVolume
	// Expected content of controller volume cache at the end of the test.
	expectedVolumes []*v1.PersistentVolume
	// Initial content of controller claim cache.
	initialClaims []*v1.PersistentVolumeClaim
	// Expected content of controller claim cache at the end of the test.
	expectedClaims []*v1.PersistentVolumeClaim
	// Expected events - any event with prefix will pass, we don't check full
	// event message.
	expectedEvents []string
	// Errors to produce on matching action
	errors []reactorError
	// Function to call as the test.
	test testCall
}

type testCall func(ctrl *PersistentVolumeController, reactor *volumeReactor, test controllerTest) error

const testNamespace = "default"
const mockPluginName = "kubernetes.io/mock-volume"

var versionConflictError = errors.New("VersionError")
var novolumes []*v1.PersistentVolume
var noclaims []*v1.PersistentVolumeClaim
var noevents = []string{}
var noerrors = []reactorError{}

// volumeReactor is a core.Reactor that simulates etcd and API server. It
// stores:
// - Latest version of claims volumes saved by the controller.
// - Queue of all saves (to simulate "volume/claim updated" events). This queue
//   contains all intermediate state of an object - e.g. a claim.VolumeName
//   is updated first and claim.Phase second. This queue will then contain both
//   updates as separate entries.
// - Number of changes since the last call to volumeReactor.syncAll().
// - Optionally, volume and claim fake watchers which should be the same ones
//   used by the controller. Any time an event function like deleteVolumeEvent
//   is called to simulate an event, the reactor's stores are updated and the
//   controller is sent the event via the fake watcher.
// - Optionally, list of error that should be returned by reactor, simulating
//   etcd / API server failures. These errors are evaluated in order and every
//   error is returned only once. I.e. when the reactor finds matching
//   reactorError, it return appropriate error and removes the reactorError from
//   the list.
type volumeReactor struct {
	volumes              map[string]*v1.PersistentVolume
	claims               map[string]*v1.PersistentVolumeClaim
	changedObjects       []interface{}
	changedSinceLastSync int
	ctrl                 *PersistentVolumeController
	fakeVolumeWatch      *watch.FakeWatcher
	fakeClaimWatch       *watch.FakeWatcher
	lock                 sync.Mutex
	errors               []reactorError
}

// reactorError is an error that is returned by test reactor (=simulated
// etcd+/API server) when an action performed by the reactor matches given verb
// ("get", "update", "create", "delete" or "*"") on given resource
// ("persistentvolumes", "persistentvolumeclaims" or "*").
type reactorError struct {
	verb     string
	resource string
	error    error
}

// React is a callback called by fake kubeClient from the controller.
// In other words, every claim/volume change performed by the controller ends
// here.
// This callback checks versions of the updated objects and refuse those that
// are too old (simulating real etcd).
// All updated objects are stored locally to keep track of object versions and
// to evaluate test results.
// All updated objects are also inserted into changedObjects queue and
// optionally sent back to the controller via its watchers.
func (r *volumeReactor) React(action core.Action) (handled bool, ret runtime.Object, err error) {
	r.lock.Lock()
	defer r.lock.Unlock()

	glog.V(4).Infof("reactor got operation %q on %q", action.GetVerb(), action.GetResource())

	// Inject error when requested
	err = r.injectReactError(action)
	if err != nil {
		return true, nil, err
	}

	// Test did not request to inject an error, continue simulating API server.
	switch {
	case action.Matches("create", "persistentvolumes"):
		obj := action.(core.UpdateAction).GetObject()
		volume := obj.(*v1.PersistentVolume)

		// check the volume does not exist
		_, found := r.volumes[volume.Name]
		if found {
			return true, nil, fmt.Errorf("Cannot create volume %s: volume already exists", volume.Name)
		}

		// Store the updated object to appropriate places.
		r.volumes[volume.Name] = volume
		r.changedObjects = append(r.changedObjects, volume)
		r.changedSinceLastSync++
		glog.V(4).Infof("created volume %s", volume.Name)
		return true, volume, nil

	case action.Matches("update", "persistentvolumes"):
		obj := action.(core.UpdateAction).GetObject()
		volume := obj.(*v1.PersistentVolume)

		// Check and bump object version
		storedVolume, found := r.volumes[volume.Name]
		if found {
			storedVer, _ := strconv.Atoi(storedVolume.ResourceVersion)
			requestedVer, _ := strconv.Atoi(volume.ResourceVersion)
			if storedVer != requestedVer {
				return true, obj, versionConflictError
			}
			volume.ResourceVersion = strconv.Itoa(storedVer + 1)
		} else {
			return true, nil, fmt.Errorf("Cannot update volume %s: volume not found", volume.Name)
		}

		// Store the updated object to appropriate places.
		r.volumes[volume.Name] = volume
		r.changedObjects = append(r.changedObjects, volume)
		r.changedSinceLastSync++
		glog.V(4).Infof("saved updated volume %s", volume.Name)
		return true, volume, nil

	case action.Matches("update", "persistentvolumeclaims"):
		obj := action.(core.UpdateAction).GetObject()
		claim := obj.(*v1.PersistentVolumeClaim)

		// Check and bump object version
		storedClaim, found := r.claims[claim.Name]
		if found {
			storedVer, _ := strconv.Atoi(storedClaim.ResourceVersion)
			requestedVer, _ := strconv.Atoi(claim.ResourceVersion)
			if storedVer != requestedVer {
				return true, obj, versionConflictError
			}
			claim.ResourceVersion = strconv.Itoa(storedVer + 1)
		} else {
			return true, nil, fmt.Errorf("Cannot update claim %s: claim not found", claim.Name)
		}

		// Store the updated object to appropriate places.
		r.claims[claim.Name] = claim
		r.changedObjects = append(r.changedObjects, claim)
		r.changedSinceLastSync++
		glog.V(4).Infof("saved updated claim %s", claim.Name)
		return true, claim, nil

	case action.Matches("get", "persistentvolumes"):
		name := action.(core.GetAction).GetName()
		volume, found := r.volumes[name]
		if found {
			glog.V(4).Infof("GetVolume: found %s", volume.Name)
			return true, volume, nil
		} else {
			glog.V(4).Infof("GetVolume: volume %s not found", name)
			return true, nil, fmt.Errorf("Cannot find volume %s", name)
		}

	case action.Matches("delete", "persistentvolumes"):
		name := action.(core.DeleteAction).GetName()
		glog.V(4).Infof("deleted volume %s", name)
		_, found := r.volumes[name]
		if found {
			delete(r.volumes, name)
			r.changedSinceLastSync++
			return true, nil, nil
		} else {
			return true, nil, fmt.Errorf("Cannot delete volume %s: not found", name)
		}

	case action.Matches("delete", "persistentvolumeclaims"):
		name := action.(core.DeleteAction).GetName()
		glog.V(4).Infof("deleted claim %s", name)
		_, found := r.volumes[name]
		if found {
			delete(r.claims, name)
			r.changedSinceLastSync++
			return true, nil, nil
		} else {
			return true, nil, fmt.Errorf("Cannot delete claim %s: not found", name)
		}
	}

	return false, nil, nil
}

// injectReactError returns an error when the test requested given action to
// fail. nil is returned otherwise.
func (r *volumeReactor) injectReactError(action core.Action) error {
	if len(r.errors) == 0 {
		// No more errors to inject, everything should succeed.
		return nil
	}

	for i, expected := range r.errors {
		glog.V(4).Infof("trying to match %q %q with %q %q", expected.verb, expected.resource, action.GetVerb(), action.GetResource())
		if action.Matches(expected.verb, expected.resource) {
			// That's the action we're waiting for, remove it from injectedErrors
			r.errors = append(r.errors[:i], r.errors[i+1:]...)
			glog.V(4).Infof("reactor found matching error at index %d: %q %q, returning %v", i, expected.verb, expected.resource, expected.error)
			return expected.error
		}
	}
	return nil
}

// checkVolumes compares all expectedVolumes with set of volumes at the end of
// the test and reports differences.
func (r *volumeReactor) checkVolumes(expectedVolumes []*v1.PersistentVolume) error {
	r.lock.Lock()
	defer r.lock.Unlock()

	expectedMap := make(map[string]*v1.PersistentVolume)
	gotMap := make(map[string]*v1.PersistentVolume)
	// Clear any ResourceVersion from both sets
	for _, v := range expectedVolumes {
		v.ResourceVersion = ""
		expectedMap[v.Name] = v
	}
	for _, v := range r.volumes {
		// We must clone the volume because of golang race check - it was
		// written by the controller without any locks on it.
		v := v.DeepCopy()
		v.ResourceVersion = ""
		if v.Spec.ClaimRef != nil {
			v.Spec.ClaimRef.ResourceVersion = ""
		}
		gotMap[v.Name] = v
	}
	if !reflect.DeepEqual(expectedMap, gotMap) {
		// Print ugly but useful diff of expected and received objects for
		// easier debugging.
		return fmt.Errorf("Volume check failed [A-expected, B-got]: %s", diff.ObjectDiff(expectedMap, gotMap))
	}
	return nil
}

// checkClaims compares all expectedClaims with set of claims at the end of the
// test and reports differences.
func (r *volumeReactor) checkClaims(expectedClaims []*v1.PersistentVolumeClaim) error {
	r.lock.Lock()
	defer r.lock.Unlock()

	expectedMap := make(map[string]*v1.PersistentVolumeClaim)
	gotMap := make(map[string]*v1.PersistentVolumeClaim)
	for _, c := range expectedClaims {
		c.ResourceVersion = ""
		expectedMap[c.Name] = c
	}
	for _, c := range r.claims {
		// We must clone the claim because of golang race check - it was
		// written by the controller without any locks on it.
		c = c.DeepCopy()
		c.ResourceVersion = ""
		gotMap[c.Name] = c
	}
	if !reflect.DeepEqual(expectedMap, gotMap) {
		// Print ugly but useful diff of expected and received objects for
		// easier debugging.
		return fmt.Errorf("Claim check failed [A-expected, B-got result]: %s", diff.ObjectDiff(expectedMap, gotMap))
	}
	return nil
}

// checkEvents compares all expectedEvents with events generated during the test
// and reports differences.
func checkEvents(t *testing.T, expectedEvents []string, ctrl *PersistentVolumeController) error {
	var err error

	// Read recorded events - wait up to 1 minute to get all the expected ones
	// (just in case some goroutines are slower with writing)
	timer := time.NewTimer(time.Minute)
	defer timer.Stop()

	fakeRecorder := ctrl.eventRecorder.(*record.FakeRecorder)
	gotEvents := []string{}
	finished := false
	for len(gotEvents) < len(expectedEvents) && !finished {
		select {
		case event, ok := <-fakeRecorder.Events:
			if ok {
				glog.V(5).Infof("event recorder got event %s", event)
				gotEvents = append(gotEvents, event)
			} else {
				glog.V(5).Infof("event recorder finished")
				finished = true
			}
		case _, _ = <-timer.C:
			glog.V(5).Infof("event recorder timeout")
			finished = true
		}
	}

	// Evaluate the events
	for i, expected := range expectedEvents {
		if len(gotEvents) <= i {
			t.Errorf("Event %q not emitted", expected)
			err = fmt.Errorf("Events do not match")
			continue
		}
		received := gotEvents[i]
		if !strings.HasPrefix(received, expected) {
			t.Errorf("Unexpected event received, expected %q, got %q", expected, received)
			err = fmt.Errorf("Events do not match")
		}
	}
	for i := len(expectedEvents); i < len(gotEvents); i++ {
		t.Errorf("Unexpected event received: %q", gotEvents[i])
		err = fmt.Errorf("Events do not match")
	}
	return err
}

// popChange returns one recorded updated object, either *v1.PersistentVolume
// or *v1.PersistentVolumeClaim. Returns nil when there are no changes.
func (r *volumeReactor) popChange() interface{} {
	r.lock.Lock()
	defer r.lock.Unlock()

	if len(r.changedObjects) == 0 {
		return nil
	}

	// For debugging purposes, print the queue
	for _, obj := range r.changedObjects {
		switch obj.(type) {
		case *v1.PersistentVolume:
			vol, _ := obj.(*v1.PersistentVolume)
			glog.V(4).Infof("reactor queue: %s", vol.Name)
		case *v1.PersistentVolumeClaim:
			claim, _ := obj.(*v1.PersistentVolumeClaim)
			glog.V(4).Infof("reactor queue: %s", claim.Name)
		}
	}

	// Pop the first item from the queue and return it
	obj := r.changedObjects[0]
	r.changedObjects = r.changedObjects[1:]
	return obj
}

// syncAll simulates the controller periodic sync of volumes and claim. It
// simply adds all these objects to the internal queue of updates. This method
// should be used when the test manually calls syncClaim/syncVolume. Test that
// use real controller loop (ctrl.Run()) will get periodic sync automatically.
func (r *volumeReactor) syncAll() {
	r.lock.Lock()
	defer r.lock.Unlock()

	for _, c := range r.claims {
		r.changedObjects = append(r.changedObjects, c)
	}
	for _, v := range r.volumes {
		r.changedObjects = append(r.changedObjects, v)
	}
	r.changedSinceLastSync = 0
}

func (r *volumeReactor) getChangeCount() int {
	r.lock.Lock()
	defer r.lock.Unlock()
	return r.changedSinceLastSync
}

// waitForIdle waits until all tests, controllers and other goroutines do their
// job and no new actions are registered for 10 milliseconds.
func (r *volumeReactor) waitForIdle() {
	r.ctrl.runningOperations.WaitForCompletion()
	// Check every 10ms if the controller does something and stop if it's
	// idle.
	oldChanges := -1
	for {
		time.Sleep(10 * time.Millisecond)
		changes := r.getChangeCount()
		if changes == oldChanges {
			// No changes for last 10ms -> controller must be idle.
			break
		}
		oldChanges = changes
	}
}

// waitTest waits until all tests, controllers and other goroutines do their
// job and list of current volumes/claims is equal to list of expected
// volumes/claims (with ~10 second timeout).
func (r *volumeReactor) waitTest(test controllerTest) error {
	// start with 10 ms, multiply by 2 each step, 10 steps = 10.23 seconds
	backoff := wait.Backoff{
		Duration: 10 * time.Millisecond,
		Jitter:   0,
		Factor:   2,
		Steps:    10,
	}
	err := wait.ExponentialBackoff(backoff, func() (done bool, err error) {
		// Finish all operations that are in progress
		r.ctrl.runningOperations.WaitForCompletion()

		// Return 'true' if the reactor reached the expected state
		err1 := r.checkClaims(test.expectedClaims)
		err2 := r.checkVolumes(test.expectedVolumes)
		if err1 == nil && err2 == nil {
			return true, nil
		}
		return false, nil
	})
	return err
}

// deleteVolumeEvent simulates that a volume has been deleted in etcd and
// the controller receives 'volume deleted' event.
func (r *volumeReactor) deleteVolumeEvent(volume *v1.PersistentVolume) {
	r.lock.Lock()
	defer r.lock.Unlock()

	// Remove the volume from list of resulting volumes.
	delete(r.volumes, volume.Name)

	// Generate deletion event. Cloned volume is needed to prevent races (and we
	// would get a clone from etcd too).
	if r.fakeVolumeWatch != nil {
		r.fakeVolumeWatch.Delete(volume.DeepCopy())
	}
}

// deleteClaimEvent simulates that a claim has been deleted in etcd and the
// controller receives 'claim deleted' event.
func (r *volumeReactor) deleteClaimEvent(claim *v1.PersistentVolumeClaim) {
	r.lock.Lock()
	defer r.lock.Unlock()

	// Remove the claim from list of resulting claims.
	delete(r.claims, claim.Name)

	// Generate deletion event. Cloned volume is needed to prevent races (and we
	// would get a clone from etcd too).
	if r.fakeClaimWatch != nil {
		r.fakeClaimWatch.Delete(claim.DeepCopy())
	}
}

// addVolumeEvent simulates that a volume has been added in etcd and the
// controller receives 'volume added' event.
func (r *volumeReactor) addVolumeEvent(volume *v1.PersistentVolume) {
	r.lock.Lock()
	defer r.lock.Unlock()

	r.volumes[volume.Name] = volume
	// Generate event. No cloning is needed, this claim is not stored in the
	// controller cache yet.
	if r.fakeVolumeWatch != nil {
		r.fakeVolumeWatch.Add(volume)
	}
}

// modifyVolumeEvent simulates that a volume has been modified in etcd and the
// controller receives 'volume modified' event.
func (r *volumeReactor) modifyVolumeEvent(volume *v1.PersistentVolume) {
	r.lock.Lock()
	defer r.lock.Unlock()

	r.volumes[volume.Name] = volume
	// Generate deletion event. Cloned volume is needed to prevent races (and we
	// would get a clone from etcd too).
	if r.fakeVolumeWatch != nil {
		r.fakeVolumeWatch.Modify(volume.DeepCopy())
	}
}

// addClaimEvent simulates that a claim has been deleted in etcd and the
// controller receives 'claim added' event.
func (r *volumeReactor) addClaimEvent(claim *v1.PersistentVolumeClaim) {
	r.lock.Lock()
	defer r.lock.Unlock()

	r.claims[claim.Name] = claim
	// Generate event. No cloning is needed, this claim is not stored in the
	// controller cache yet.
	if r.fakeClaimWatch != nil {
		r.fakeClaimWatch.Add(claim)
	}
}

func newVolumeReactor(client *fake.Clientset, ctrl *PersistentVolumeController, fakeVolumeWatch, fakeClaimWatch *watch.FakeWatcher, errors []reactorError) *volumeReactor {
	reactor := &volumeReactor{
		volumes:         make(map[string]*v1.PersistentVolume),
		claims:          make(map[string]*v1.PersistentVolumeClaim),
		ctrl:            ctrl,
		fakeVolumeWatch: fakeVolumeWatch,
		fakeClaimWatch:  fakeClaimWatch,
		errors:          errors,
	}
	client.AddReactor("create", "persistentvolumes", reactor.React)
	client.AddReactor("update", "persistentvolumes", reactor.React)
	client.AddReactor("update", "persistentvolumeclaims", reactor.React)
	client.AddReactor("get", "persistentvolumes", reactor.React)
	client.AddReactor("delete", "persistentvolumes", reactor.React)
	client.AddReactor("delete", "persistentvolumeclaims", reactor.React)

	return reactor
}
func alwaysReady() bool { return true }

func newTestController(kubeClient clientset.Interface, informerFactory informers.SharedInformerFactory, enableDynamicProvisioning bool) (*PersistentVolumeController, error) {
	if informerFactory == nil {
		informerFactory = informers.NewSharedInformerFactory(kubeClient, controller.NoResyncPeriodFunc())
	}
	params := ControllerParameters{
		KubeClient:                kubeClient,
		SyncPeriod:                5 * time.Second,
		VolumePlugins:             []vol.VolumePlugin{},
		VolumeInformer:            informerFactory.Core().V1().PersistentVolumes(),
		ClaimInformer:             informerFactory.Core().V1().PersistentVolumeClaims(),
		ClassInformer:             informerFactory.Storage().V1().StorageClasses(),
		EventRecorder:             record.NewFakeRecorder(1000),
		EnableDynamicProvisioning: enableDynamicProvisioning,
	}
	ctrl, err := NewController(params)
	if err != nil {
		return nil, fmt.Errorf("failed to construct persistentvolume controller: %v", err)
	}
	ctrl.volumeListerSynced = alwaysReady
	ctrl.claimListerSynced = alwaysReady
	ctrl.classListerSynced = alwaysReady
	// Speed up the test
	ctrl.createProvisionedPVInterval = 5 * time.Millisecond
	return ctrl, nil
}

// newVolume returns a new volume with given attributes
func newVolume(name, capacity, boundToClaimUID, boundToClaimName string, phase v1.PersistentVolumePhase, reclaimPolicy v1.PersistentVolumeReclaimPolicy, class string, annotations ...string) *v1.PersistentVolume {
	volume := v1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{
			Name:            name,
			ResourceVersion: "1",
		},
		Spec: v1.PersistentVolumeSpec{
			Capacity: v1.ResourceList{
				v1.ResourceName(v1.ResourceStorage): resource.MustParse(capacity),
			},
			PersistentVolumeSource: v1.PersistentVolumeSource{
				GCEPersistentDisk: &v1.GCEPersistentDiskVolumeSource{},
			},
			AccessModes:                   []v1.PersistentVolumeAccessMode{v1.ReadWriteOnce, v1.ReadOnlyMany},
			PersistentVolumeReclaimPolicy: reclaimPolicy,
			StorageClassName:              class,
		},
		Status: v1.PersistentVolumeStatus{
			Phase: phase,
		},
	}

	if boundToClaimName != "" {
		volume.Spec.ClaimRef = &v1.ObjectReference{
			Kind:       "PersistentVolumeClaim",
			APIVersion: "v1",
			UID:        types.UID(boundToClaimUID),
			Namespace:  testNamespace,
			Name:       boundToClaimName,
		}
	}

	if len(annotations) > 0 {
		volume.Annotations = make(map[string]string)
		for _, a := range annotations {
			switch a {
			case annDynamicallyProvisioned:
				volume.Annotations[a] = mockPluginName
			default:
				volume.Annotations[a] = "yes"
			}
		}
	}

	return &volume
}

// withLabels applies the given labels to the first volume in the array and
// returns the array.  Meant to be used to compose volumes specified inline in
// a test.
func withLabels(labels map[string]string, volumes []*v1.PersistentVolume) []*v1.PersistentVolume {
	volumes[0].Labels = labels
	return volumes
}

// withLabelSelector sets the label selector of the first claim in the array
// to be MatchLabels of the given label set and returns the array.  Meant
// to be used to compose claims specified inline in a test.
func withLabelSelector(labels map[string]string, claims []*v1.PersistentVolumeClaim) []*v1.PersistentVolumeClaim {
	claims[0].Spec.Selector = &metav1.LabelSelector{
		MatchLabels: labels,
	}

	return claims
}

// withExpectedCapacity sets the claim.Spec.Capacity of the first claim in the
// array to given value and returns the array.  Meant to be used to compose
// claims specified inline in a test.
func withExpectedCapacity(capacity string, claims []*v1.PersistentVolumeClaim) []*v1.PersistentVolumeClaim {
	claims[0].Status.Capacity = v1.ResourceList{
		v1.ResourceName(v1.ResourceStorage): resource.MustParse(capacity),
	}

	return claims
}

// withMessage saves given message into volume.Status.Message of the first
// volume in the array and returns the array.  Meant to be used to compose
// volumes specified inline in a test.
func withMessage(message string, volumes []*v1.PersistentVolume) []*v1.PersistentVolume {
	volumes[0].Status.Message = message
	return volumes
}

// newVolumeArray returns array with a single volume that would be returned by
// newVolume() with the same parameters.
func newVolumeArray(name, capacity, boundToClaimUID, boundToClaimName string, phase v1.PersistentVolumePhase, reclaimPolicy v1.PersistentVolumeReclaimPolicy, class string, annotations ...string) []*v1.PersistentVolume {
	return []*v1.PersistentVolume{
		newVolume(name, capacity, boundToClaimUID, boundToClaimName, phase, reclaimPolicy, class, annotations...),
	}
}

// newClaim returns a new claim with given attributes
func newClaim(name, claimUID, capacity, boundToVolume string, phase v1.PersistentVolumeClaimPhase, class *string, annotations ...string) *v1.PersistentVolumeClaim {
	claim := v1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:            name,
			Namespace:       testNamespace,
			UID:             types.UID(claimUID),
			ResourceVersion: "1",
		},
		Spec: v1.PersistentVolumeClaimSpec{
			AccessModes: []v1.PersistentVolumeAccessMode{v1.ReadWriteOnce, v1.ReadOnlyMany},
			Resources: v1.ResourceRequirements{
				Requests: v1.ResourceList{
					v1.ResourceName(v1.ResourceStorage): resource.MustParse(capacity),
				},
			},
			VolumeName:       boundToVolume,
			StorageClassName: class,
		},
		Status: v1.PersistentVolumeClaimStatus{
			Phase: phase,
		},
	}
	// Make sure ref.GetReference(claim) works
	claim.ObjectMeta.SelfLink = testapi.Default.SelfLink("pvc", name)

	if len(annotations) > 0 {
		claim.Annotations = make(map[string]string)
		for _, a := range annotations {
			switch a {
			case annStorageProvisioner:
				claim.Annotations[a] = mockPluginName
			default:
				claim.Annotations[a] = "yes"
			}
		}
	}

	// Bound claims must have proper Status.
	if phase == v1.ClaimBound {
		claim.Status.AccessModes = claim.Spec.AccessModes
		// For most of the tests it's enough to copy claim's requested capacity,
		// individual tests can adjust it using withExpectedCapacity()
		claim.Status.Capacity = claim.Spec.Resources.Requests
	}

	return &claim
}

// newClaimArray returns array with a single claim that would be returned by
// newClaim() with the same parameters.
func newClaimArray(name, claimUID, capacity, boundToVolume string, phase v1.PersistentVolumeClaimPhase, class *string, annotations ...string) []*v1.PersistentVolumeClaim {
	return []*v1.PersistentVolumeClaim{
		newClaim(name, claimUID, capacity, boundToVolume, phase, class, annotations...),
	}
}

// claimWithAnnotation saves given annotation into given claims.
// Meant to be used to compose claims specified inline in a test.
func claimWithAnnotation(name, value string, claims []*v1.PersistentVolumeClaim) []*v1.PersistentVolumeClaim {
	if claims[0].Annotations == nil {
		claims[0].Annotations = map[string]string{name: value}
	} else {
		claims[0].Annotations[name] = value
	}
	return claims
}

func testSyncClaim(ctrl *PersistentVolumeController, reactor *volumeReactor, test controllerTest) error {
	return ctrl.syncClaim(test.initialClaims[0])
}

func testSyncClaimError(ctrl *PersistentVolumeController, reactor *volumeReactor, test controllerTest) error {
	err := ctrl.syncClaim(test.initialClaims[0])

	if err != nil {
		return nil
	}
	return fmt.Errorf("syncClaim succeeded when failure was expected")
}

func testSyncVolume(ctrl *PersistentVolumeController, reactor *volumeReactor, test controllerTest) error {
	return ctrl.syncVolume(test.initialVolumes[0])
}

type operationType string

const operationDelete = "Delete"
const operationRecycle = "Recycle"

var (
	classGold                    string = "gold"
	classSilver                  string = "silver"
	classEmpty                   string = ""
	classNonExisting             string = "non-existing"
	classExternal                string = "external"
	classUnknownInternal         string = "unknown-internal"
	classUnsupportedMountOptions string = "unsupported-mountoptions"
	classLarge                   string = "large"
)

// wrapTestWithPluginCalls returns a testCall that:
// - configures controller with a volume plugin that implements recycler,
//   deleter and provisioner. The plugin retunrs provided errors when a volume
//   is deleted, recycled or provisioned.
// - calls given testCall
func wrapTestWithPluginCalls(expectedRecycleCalls, expectedDeleteCalls []error, expectedProvisionCalls []provisionCall, toWrap testCall) testCall {
	return func(ctrl *PersistentVolumeController, reactor *volumeReactor, test controllerTest) error {
		plugin := &mockVolumePlugin{
			recycleCalls:   expectedRecycleCalls,
			deleteCalls:    expectedDeleteCalls,
			provisionCalls: expectedProvisionCalls,
		}
		ctrl.volumePluginMgr.InitPlugins([]vol.VolumePlugin{plugin}, nil /* prober */, ctrl)
		return toWrap(ctrl, reactor, test)
	}
}

// wrapTestWithReclaimCalls returns a testCall that:
// - configures controller with recycler or deleter which will return provided
//   errors when a volume is deleted or recycled
// - calls given testCall
func wrapTestWithReclaimCalls(operation operationType, expectedOperationCalls []error, toWrap testCall) testCall {
	if operation == operationDelete {
		return wrapTestWithPluginCalls(nil, expectedOperationCalls, nil, toWrap)
	} else {
		return wrapTestWithPluginCalls(expectedOperationCalls, nil, nil, toWrap)
	}
}

// wrapTestWithProvisionCalls returns a testCall that:
// - configures controller with a provisioner which will return provided errors
//   when a claim is provisioned
// - calls given testCall
func wrapTestWithProvisionCalls(expectedProvisionCalls []provisionCall, toWrap testCall) testCall {
	return wrapTestWithPluginCalls(nil, nil, expectedProvisionCalls, toWrap)
}

// wrapTestWithInjectedOperation returns a testCall that:
// - starts the controller and lets it run original testCall until
//   scheduleOperation() call. It blocks the controller there and calls the
//   injected function to simulate that something is happening when the
//   controller waits for the operation lock. Controller is then resumed and we
//   check how it behaves.
func wrapTestWithInjectedOperation(toWrap testCall, injectBeforeOperation func(ctrl *PersistentVolumeController, reactor *volumeReactor)) testCall {

	return func(ctrl *PersistentVolumeController, reactor *volumeReactor, test controllerTest) error {
		// Inject a hook before async operation starts
		ctrl.preOperationHook = func(operationName string) {
			// Inside the hook, run the function to inject
			glog.V(4).Infof("reactor: scheduleOperation reached, injecting call")
			injectBeforeOperation(ctrl, reactor)
		}

		// Run the tested function (typically syncClaim/syncVolume) in a
		// separate goroutine.
		var testError error
		var testFinished int32

		go func() {
			testError = toWrap(ctrl, reactor, test)
			// Let the "main" test function know that syncVolume has finished.
			atomic.StoreInt32(&testFinished, 1)
		}()

		// Wait for the controller to finish the test function.
		for atomic.LoadInt32(&testFinished) == 0 {
			time.Sleep(time.Millisecond * 10)
		}

		return testError
	}
}

func evaluateTestResults(ctrl *PersistentVolumeController, reactor *volumeReactor, test controllerTest, t *testing.T) {
	// Evaluate results
	if err := reactor.checkClaims(test.expectedClaims); err != nil {
		t.Errorf("Test %q: %v", test.name, err)

	}
	if err := reactor.checkVolumes(test.expectedVolumes); err != nil {
		t.Errorf("Test %q: %v", test.name, err)
	}

	if err := checkEvents(t, test.expectedEvents, ctrl); err != nil {
		t.Errorf("Test %q: %v", test.name, err)
	}
}

// Test single call to syncClaim and syncVolume methods.
// For all tests:
// 1. Fill in the controller with initial data
// 2. Call the tested function (syncClaim/syncVolume) via
//    controllerTest.testCall *once*.
// 3. Compare resulting volumes and claims with expected volumes and claims.
func runSyncTests(t *testing.T, tests []controllerTest, storageClasses []*storage.StorageClass) {
	for _, test := range tests {
		glog.V(4).Infof("starting test %q", test.name)

		// Initialize the controller
		client := &fake.Clientset{}
		ctrl, err := newTestController(client, nil, true)
		if err != nil {
			t.Fatalf("Test %q construct persistent volume failed: %v", test.name, err)
		}
		reactor := newVolumeReactor(client, ctrl, nil, nil, test.errors)
		for _, claim := range test.initialClaims {
			ctrl.claims.Add(claim)
			reactor.claims[claim.Name] = claim
		}
		for _, volume := range test.initialVolumes {
			ctrl.volumes.store.Add(volume)
			reactor.volumes[volume.Name] = volume
		}

		// Inject classes into controller via a custom lister.
		indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
		for _, class := range storageClasses {
			indexer.Add(class)
		}
		ctrl.classLister = storagelisters.NewStorageClassLister(indexer)

		// Run the tested functions
		err = test.test(ctrl, reactor, test)
		if err != nil {
			t.Errorf("Test %q failed: %v", test.name, err)
		}

		// Wait for the target state
		err = reactor.waitTest(test)
		if err != nil {
			t.Errorf("Test %q failed: %v", test.name, err)
		}

		evaluateTestResults(ctrl, reactor, test, t)
	}
}

// Test multiple calls to syncClaim/syncVolume and periodic sync of all
// volume/claims. For all tests, the test follows this pattern:
// 0. Load the controller with initial data.
// 1. Call controllerTest.testCall() once as in TestSync()
// 2. For all volumes/claims changed by previous syncVolume/syncClaim calls,
//    call appropriate syncVolume/syncClaim (simulating "volume/claim changed"
//    events). Go to 2. if these calls change anything.
// 3. When all changes are processed and no new changes were made, call
//    syncVolume/syncClaim on all volumes/claims (simulating "periodic sync").
// 4. If some changes were done by step 3., go to 2. (simulation of
//    "volume/claim updated" events, eventually performing step 3. again)
// 5. When 3. does not do any changes, finish the tests and compare final set
//    of volumes/claims with expected claims/volumes and report differences.
// Some limit of calls in enforced to prevent endless loops.
func runMultisyncTests(t *testing.T, tests []controllerTest, storageClasses []*storage.StorageClass, defaultStorageClass string) {
	for _, test := range tests {
		glog.V(4).Infof("starting multisync test %q", test.name)

		// Initialize the controller
		client := &fake.Clientset{}
		ctrl, err := newTestController(client, nil, true)
		if err != nil {
			t.Fatalf("Test %q construct persistent volume failed: %v", test.name, err)
		}

		// Inject classes into controller via a custom lister.
		indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
		for _, class := range storageClasses {
			indexer.Add(class)
		}
		ctrl.classLister = storagelisters.NewStorageClassLister(indexer)

		reactor := newVolumeReactor(client, ctrl, nil, nil, test.errors)
		for _, claim := range test.initialClaims {
			ctrl.claims.Add(claim)
			reactor.claims[claim.Name] = claim
		}
		for _, volume := range test.initialVolumes {
			ctrl.volumes.store.Add(volume)
			reactor.volumes[volume.Name] = volume
		}

		// Run the tested function
		err = test.test(ctrl, reactor, test)
		if err != nil {
			t.Errorf("Test %q failed: %v", test.name, err)
		}

		// Simulate any "changed" events and "periodical sync" until we reach a
		// stable state.
		firstSync := true
		counter := 0
		for {
			counter++
			glog.V(4).Infof("test %q: iteration %d", test.name, counter)

			if counter > 100 {
				t.Errorf("Test %q failed: too many iterations", test.name)
				break
			}

			// Wait for all goroutines to finish
			reactor.waitForIdle()

			obj := reactor.popChange()
			if obj == nil {
				// Nothing was changed, should we exit?
				if firstSync || reactor.changedSinceLastSync > 0 {
					// There were some changes after the last "periodic sync".
					// Simulate "periodic sync" of everything (until it produces
					// no changes).
					firstSync = false
					glog.V(4).Infof("test %q: simulating periodical sync of all claims and volumes", test.name)
					reactor.syncAll()
				} else {
					// Last sync did not produce any updates, the test reached
					// stable state -> finish.
					break
				}
			}
			// waiting here cools down exponential backoff
			time.Sleep(600 * time.Millisecond)

			// There were some changes, process them
			switch obj.(type) {
			case *v1.PersistentVolumeClaim:
				claim := obj.(*v1.PersistentVolumeClaim)
				// Simulate "claim updated" event
				ctrl.claims.Update(claim)
				err = ctrl.syncClaim(claim)
				if err != nil {
					if err == versionConflictError {
						// Ignore version errors
						glog.V(4).Infof("test intentionaly ignores version error.")
					} else {
						t.Errorf("Error calling syncClaim: %v", err)
						// Finish the loop on the first error
						break
					}
				}
				// Process generated changes
				continue
			case *v1.PersistentVolume:
				volume := obj.(*v1.PersistentVolume)
				// Simulate "volume updated" event
				ctrl.volumes.store.Update(volume)
				err = ctrl.syncVolume(volume)
				if err != nil {
					if err == versionConflictError {
						// Ignore version errors
						glog.V(4).Infof("test intentionaly ignores version error.")
					} else {
						t.Errorf("Error calling syncVolume: %v", err)
						// Finish the loop on the first error
						break
					}
				}
				// Process generated changes
				continue
			}
		}
		evaluateTestResults(ctrl, reactor, test, t)
		glog.V(4).Infof("test %q finished after %d iterations", test.name, counter)
	}
}

// Dummy volume plugin for provisioning, deletion and recycling. It contains
// lists of expected return values to simulate errors.
type mockVolumePlugin struct {
	provisionCalls       []provisionCall
	provisionCallCounter int
	deleteCalls          []error
	deleteCallCounter    int
	recycleCalls         []error
	recycleCallCounter   int
	provisionOptions     vol.VolumeOptions
}

type provisionCall struct {
	expectedParameters map[string]string
	ret                error
}

var _ vol.VolumePlugin = &mockVolumePlugin{}
var _ vol.RecyclableVolumePlugin = &mockVolumePlugin{}
var _ vol.DeletableVolumePlugin = &mockVolumePlugin{}
var _ vol.ProvisionableVolumePlugin = &mockVolumePlugin{}

func (plugin *mockVolumePlugin) Init(host vol.VolumeHost) error {
	return nil
}

func (plugin *mockVolumePlugin) GetPluginName() string {
	return mockPluginName
}

func (plugin *mockVolumePlugin) GetVolumeName(spec *vol.Spec) (string, error) {
	return spec.Name(), nil
}

func (plugin *mockVolumePlugin) CanSupport(spec *vol.Spec) bool {
	return true
}

func (plugin *mockVolumePlugin) RequiresRemount() bool {
	return false
}

func (plugin *mockVolumePlugin) SupportsMountOption() bool {
	return false
}

func (plugin *mockVolumePlugin) SupportsBulkVolumeVerification() bool {
	return false
}

func (plugin *mockVolumePlugin) ConstructVolumeSpec(volumeName, mountPath string) (*vol.Spec, error) {
	return nil, nil
}

func (plugin *mockVolumePlugin) NewMounter(spec *vol.Spec, podRef *v1.Pod, opts vol.VolumeOptions) (vol.Mounter, error) {
	return nil, fmt.Errorf("Mounter is not supported by this plugin")
}

func (plugin *mockVolumePlugin) NewUnmounter(name string, podUID types.UID) (vol.Unmounter, error) {
	return nil, fmt.Errorf("Unmounter is not supported by this plugin")
}

// Provisioner interfaces

func (plugin *mockVolumePlugin) NewProvisioner(options vol.VolumeOptions) (vol.Provisioner, error) {
	if len(plugin.provisionCalls) > 0 {
		// mockVolumePlugin directly implements Provisioner interface
		glog.V(4).Infof("mock plugin NewProvisioner called, returning mock provisioner")
		plugin.provisionOptions = options
		return plugin, nil
	} else {
		return nil, fmt.Errorf("Mock plugin error: no provisionCalls configured")
	}
}

func (plugin *mockVolumePlugin) Provision() (*v1.PersistentVolume, error) {
	if len(plugin.provisionCalls) <= plugin.provisionCallCounter {
		return nil, fmt.Errorf("Mock plugin error: unexpected provisioner call %d", plugin.provisionCallCounter)
	}

	var pv *v1.PersistentVolume
	call := plugin.provisionCalls[plugin.provisionCallCounter]
	if !reflect.DeepEqual(call.expectedParameters, plugin.provisionOptions.Parameters) {
		glog.Errorf("invalid provisioner call, expected options: %+v, got: %+v", call.expectedParameters, plugin.provisionOptions.Parameters)
		return nil, fmt.Errorf("Mock plugin error: invalid provisioner call")
	}
	if call.ret == nil {
		// Create a fake PV with known GCE volume (to match expected volume)
		capacity := plugin.provisionOptions.PVC.Spec.Resources.Requests[v1.ResourceName(v1.ResourceStorage)]
		accessModes := plugin.provisionOptions.PVC.Spec.AccessModes
		pv = &v1.PersistentVolume{
			ObjectMeta: metav1.ObjectMeta{
				Name: plugin.provisionOptions.PVName,
			},
			Spec: v1.PersistentVolumeSpec{
				Capacity: v1.ResourceList{
					v1.ResourceName(v1.ResourceStorage): capacity,
				},
				AccessModes:                   accessModes,
				PersistentVolumeReclaimPolicy: plugin.provisionOptions.PersistentVolumeReclaimPolicy,
				PersistentVolumeSource: v1.PersistentVolumeSource{
					GCEPersistentDisk: &v1.GCEPersistentDiskVolumeSource{},
				},
			},
		}
	}

	plugin.provisionCallCounter++
	glog.V(4).Infof("mock plugin Provision call nr. %d, returning %v: %v", plugin.provisionCallCounter, pv, call.ret)
	return pv, call.ret
}

// Deleter interfaces

func (plugin *mockVolumePlugin) NewDeleter(spec *vol.Spec) (vol.Deleter, error) {
	if len(plugin.deleteCalls) > 0 {
		// mockVolumePlugin directly implements Deleter interface
		glog.V(4).Infof("mock plugin NewDeleter called, returning mock deleter")
		return plugin, nil
	} else {
		return nil, fmt.Errorf("Mock plugin error: no deleteCalls configured")
	}
}

func (plugin *mockVolumePlugin) Delete() error {
	if len(plugin.deleteCalls) <= plugin.deleteCallCounter {
		return fmt.Errorf("Mock plugin error: unexpected deleter call %d", plugin.deleteCallCounter)
	}
	ret := plugin.deleteCalls[plugin.deleteCallCounter]
	plugin.deleteCallCounter++
	glog.V(4).Infof("mock plugin Delete call nr. %d, returning %v", plugin.deleteCallCounter, ret)
	return ret
}

// Volume interfaces

func (plugin *mockVolumePlugin) GetPath() string {
	return ""
}

func (plugin *mockVolumePlugin) GetMetrics() (*vol.Metrics, error) {
	return nil, nil
}

// Recycler interfaces

func (plugin *mockVolumePlugin) Recycle(pvName string, spec *vol.Spec, eventRecorder vol.RecycleEventRecorder) error {
	if len(plugin.recycleCalls) == 0 {
		return fmt.Errorf("Mock plugin error: no recycleCalls configured")
	}

	if len(plugin.recycleCalls) <= plugin.recycleCallCounter {
		return fmt.Errorf("Mock plugin error: unexpected recycle call %d", plugin.recycleCallCounter)
	}
	ret := plugin.recycleCalls[plugin.recycleCallCounter]
	plugin.recycleCallCounter++
	glog.V(4).Infof("mock plugin Recycle call nr. %d, returning %v", plugin.recycleCallCounter, ret)
	return ret
}
