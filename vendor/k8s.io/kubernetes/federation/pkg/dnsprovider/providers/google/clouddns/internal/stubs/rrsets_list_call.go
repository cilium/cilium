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

package stubs

import (
	"context"

	"google.golang.org/api/googleapi"
	"k8s.io/kubernetes/federation/pkg/dnsprovider/providers/google/clouddns/internal/interfaces"
)

// Compile time check for interface adherence
var _ interfaces.ResourceRecordSetsListCall = &ResourceRecordSetsListCall{}

type ResourceRecordSetsListCall struct {
	Response_ *ResourceRecordSetsListResponse
	Err_      error
	Name_     string
	Type_     string
}

func (call *ResourceRecordSetsListCall) Do(opts ...googleapi.CallOption) (interfaces.ResourceRecordSetsListResponse, error) {
	return call.Response_, call.Err_
}

func (call *ResourceRecordSetsListCall) Pages(ctx context.Context, f func(interfaces.ResourceRecordSetsListResponse) error) error {
	return f(call.Response_)
}

func (call *ResourceRecordSetsListCall) Name(name string) interfaces.ResourceRecordSetsListCall {
	call.Name_ = name
	return call
}

func (call *ResourceRecordSetsListCall) Type(type_ string) interfaces.ResourceRecordSetsListCall {
	call.Type_ = type_
	return call
}
