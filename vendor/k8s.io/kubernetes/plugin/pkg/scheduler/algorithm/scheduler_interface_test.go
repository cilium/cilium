/*
Copyright 2014 The Kubernetes Authors.

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

package algorithm

import (
	"testing"

	"k8s.io/api/core/v1"
)

// Some functions used by multiple scheduler tests.

type schedulerTester struct {
	t          *testing.T
	scheduler  ScheduleAlgorithm
	nodeLister NodeLister
}

// Call if you know exactly where pod should get scheduled.
func (st *schedulerTester) expectSchedule(pod *v1.Pod, expected string) {
	actual, err := st.scheduler.Schedule(pod, st.nodeLister)
	if err != nil {
		st.t.Errorf("Unexpected error %v\nTried to schedule: %#v", err, pod)
		return
	}
	if actual != expected {
		st.t.Errorf("Unexpected scheduling value: %v, expected %v", actual, expected)
	}
}

// Call if you can't predict where pod will be scheduled.
func (st *schedulerTester) expectSuccess(pod *v1.Pod) {
	_, err := st.scheduler.Schedule(pod, st.nodeLister)
	if err != nil {
		st.t.Errorf("Unexpected error %v\nTried to schedule: %#v", err, pod)
		return
	}
}

// Call if pod should *not* schedule.
func (st *schedulerTester) expectFailure(pod *v1.Pod) {
	_, err := st.scheduler.Schedule(pod, st.nodeLister)
	if err == nil {
		st.t.Error("Unexpected non-error")
	}
}
