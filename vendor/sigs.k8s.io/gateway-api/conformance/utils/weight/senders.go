/*
Copyright 2025 The Kubernetes Authors.

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

package weight

// FunctionBasedSender implements RequestSender using a function
type FunctionBasedSender struct {
	sendFunc func() (string, error)
}

func (s *FunctionBasedSender) SendRequest() (string, error) {
	return s.sendFunc()
}

// NewFunctionBasedSender creates a RequestSender from a function
func NewFunctionBasedSender(sendFunc func() (string, error)) RequestSender {
	return &FunctionBasedSender{sendFunc: sendFunc}
}

// BatchFunctionBasedSender implements BatchRequestSender using a function
type BatchFunctionBasedSender struct {
	sendBatchFunc func(count int) ([]string, error)
}

func (s *BatchFunctionBasedSender) SendBatchRequest(count int) ([]string, error) {
	return s.sendBatchFunc(count)
}

// NewBatchFunctionBasedSender creates a BatchRequestSender from a function
func NewBatchFunctionBasedSender(sendBatchFunc func(count int) ([]string, error)) BatchRequestSender {
	return &BatchFunctionBasedSender{sendBatchFunc: sendBatchFunc}
}
