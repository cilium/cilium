/*
Copyright (c) 2017 VMware, Inc. All Rights Reserved.

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

package object

import (
	"context"
	"reflect"

	"github.com/vmware/govmomi/vim25/soap"
	"github.com/vmware/govmomi/vim25/types"
)

func init() {
	types.Add("ArrayOfVirtualDiskInfo", reflect.TypeOf((*arrayOfVirtualDiskInfo)(nil)).Elem())

	types.Add("VirtualDiskInfo", reflect.TypeOf((*VirtualDiskInfo)(nil)).Elem())
}

type arrayOfVirtualDiskInfo struct {
	VirtualDiskInfo []VirtualDiskInfo `xml:"VirtualDiskInfo,omitempty"`
}

type queryVirtualDiskInfoTaskRequest struct {
	This           types.ManagedObjectReference  `xml:"_this"`
	Name           string                        `xml:"name"`
	Datacenter     *types.ManagedObjectReference `xml:"datacenter,omitempty"`
	IncludeParents bool                          `xml:"includeParents"`
}

type queryVirtualDiskInfoTaskResponse struct {
	Returnval types.ManagedObjectReference `xml:"returnval"`
}

type queryVirtualDiskInfoTaskBody struct {
	Req *queryVirtualDiskInfoTaskRequest  `xml:"urn:internalvim25 QueryVirtualDiskInfo_Task,omitempty"`
	Res *queryVirtualDiskInfoTaskResponse `xml:"urn:vim25 QueryVirtualDiskInfo_TaskResponse,omitempty"`
	Err *soap.Fault                       `xml:"http://schemas.xmlsoap.org/soap/envelope/ Fault,omitempty"`
}

func (b *queryVirtualDiskInfoTaskBody) Fault() *soap.Fault { return b.Err }

func queryVirtualDiskInfoTask(ctx context.Context, r soap.RoundTripper, req *queryVirtualDiskInfoTaskRequest) (*queryVirtualDiskInfoTaskResponse, error) {
	var reqBody, resBody queryVirtualDiskInfoTaskBody

	reqBody.Req = req

	if err := r.RoundTrip(ctx, &reqBody, &resBody); err != nil {
		return nil, err
	}

	return resBody.Res, nil
}

type VirtualDiskInfo struct {
	Name     string `xml:"unit>name"`
	DiskType string `xml:"diskType"`
	Parent   string `xml:"parent,omitempty"`
}

func (m VirtualDiskManager) QueryVirtualDiskInfo(ctx context.Context, name string, dc *Datacenter, includeParents bool) ([]VirtualDiskInfo, error) {
	req := queryVirtualDiskInfoTaskRequest{
		This:           m.Reference(),
		Name:           name,
		IncludeParents: includeParents,
	}

	if dc != nil {
		ref := dc.Reference()
		req.Datacenter = &ref
	}

	res, err := queryVirtualDiskInfoTask(ctx, m.Client(), &req)
	if err != nil {
		return nil, err
	}

	info, err := NewTask(m.Client(), res.Returnval).WaitForResult(ctx, nil)
	if err != nil {
		return nil, err
	}

	return info.Result.(arrayOfVirtualDiskInfo).VirtualDiskInfo, nil
}
