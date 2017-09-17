/*
Copyright 2017 The Kubernetes Authors.

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

package lifecycle

import (
	"k8s.io/api/core/v1"
	"k8s.io/kubernetes/plugin/pkg/scheduler/algorithm"
)

// AdmissionFailureHandlerStub is an AdmissionFailureHandler that does not perform any handling of admission failure.
// It simply passes the failure on.
type AdmissionFailureHandlerStub struct{}

var _ AdmissionFailureHandler = &AdmissionFailureHandlerStub{}

func NewAdmissionFailureHandlerStub() *AdmissionFailureHandlerStub {
	return &AdmissionFailureHandlerStub{}
}

func (n *AdmissionFailureHandlerStub) HandleAdmissionFailure(pod *v1.Pod, failureReasons []algorithm.PredicateFailureReason) (bool, []algorithm.PredicateFailureReason, error) {
	return false, failureReasons, nil
}
