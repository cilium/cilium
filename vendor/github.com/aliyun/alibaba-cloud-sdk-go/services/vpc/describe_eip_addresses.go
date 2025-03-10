package vpc

//Licensed under the Apache License, Version 2.0 (the "License");
//you may not use this file except in compliance with the License.
//You may obtain a copy of the License at
//
//http://www.apache.org/licenses/LICENSE-2.0
//
//Unless required by applicable law or agreed to in writing, software
//distributed under the License is distributed on an "AS IS" BASIS,
//WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//See the License for the specific language governing permissions and
//limitations under the License.
//
// Code generated by Alibaba Cloud SDK Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

import (
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/responses"
)

// DescribeEipAddresses invokes the vpc.DescribeEipAddresses API synchronously
func (client *Client) DescribeEipAddresses(request *DescribeEipAddressesRequest) (response *DescribeEipAddressesResponse, err error) {
	response = CreateDescribeEipAddressesResponse()
	err = client.DoAction(request, response)
	return
}

// DescribeEipAddressesWithChan invokes the vpc.DescribeEipAddresses API asynchronously
func (client *Client) DescribeEipAddressesWithChan(request *DescribeEipAddressesRequest) (<-chan *DescribeEipAddressesResponse, <-chan error) {
	responseChan := make(chan *DescribeEipAddressesResponse, 1)
	errChan := make(chan error, 1)
	err := client.AddAsyncTask(func() {
		defer close(responseChan)
		defer close(errChan)
		response, err := client.DescribeEipAddresses(request)
		if err != nil {
			errChan <- err
		} else {
			responseChan <- response
		}
	})
	if err != nil {
		errChan <- err
		close(responseChan)
		close(errChan)
	}
	return responseChan, errChan
}

// DescribeEipAddressesWithCallback invokes the vpc.DescribeEipAddresses API asynchronously
func (client *Client) DescribeEipAddressesWithCallback(request *DescribeEipAddressesRequest, callback func(response *DescribeEipAddressesResponse, err error)) <-chan int {
	result := make(chan int, 1)
	err := client.AddAsyncTask(func() {
		var response *DescribeEipAddressesResponse
		var err error
		defer close(result)
		response, err = client.DescribeEipAddresses(request)
		callback(response, err)
		result <- 1
	})
	if err != nil {
		defer close(result)
		callback(nil, err)
		result <- 0
	}
	return result
}

// DescribeEipAddressesRequest is the request struct for api DescribeEipAddresses
type DescribeEipAddressesRequest struct {
	*requests.RpcRequest
	ResourceOwnerId           requests.Integer           `position:"Query" name:"ResourceOwnerId"`
	PublicIpAddressPoolId     string                     `position:"Query" name:"PublicIpAddressPoolId"`
	Filter2Value              string                     `position:"Query" name:"Filter.2.Value"`
	ISP                       string                     `position:"Query" name:"ISP"`
	EipName                   string                     `position:"Query" name:"EipName"`
	EipAddress                string                     `position:"Query" name:"EipAddress"`
	ResourceGroupId           string                     `position:"Query" name:"ResourceGroupId"`
	LockReason                string                     `position:"Query" name:"LockReason"`
	Filter1Key                string                     `position:"Query" name:"Filter.1.Key"`
	Tag                       *[]DescribeEipAddressesTag `position:"Query" name:"Tag"  type:"Repeated"`
	SegmentInstanceId         string                     `position:"Query" name:"SegmentInstanceId"`
	DryRun                    requests.Boolean           `position:"Query" name:"DryRun"`
	Filter1Value              string                     `position:"Query" name:"Filter.1.Value"`
	OwnerId                   requests.Integer           `position:"Query" name:"OwnerId"`
	Status                    string                     `position:"Query" name:"Status"`
	SecurityProtectionEnabled requests.Boolean           `position:"Query" name:"SecurityProtectionEnabled"`
	ServiceManaged            requests.Boolean           `position:"Query" name:"ServiceManaged"`
	AllocationId              string                     `position:"Query" name:"AllocationId"`
	IncludeReservationData    requests.Boolean           `position:"Query" name:"IncludeReservationData"`
	PageNumber                requests.Integer           `position:"Query" name:"PageNumber"`
	AssociatedInstanceType    string                     `position:"Query" name:"AssociatedInstanceType"`
	PageSize                  requests.Integer           `position:"Query" name:"PageSize"`
	BandwidthPackageId        string                     `position:"Query" name:"BandwidthPackageId"`
	ResourceOwnerAccount      string                     `position:"Query" name:"ResourceOwnerAccount"`
	OwnerAccount              string                     `position:"Query" name:"OwnerAccount"`
	Filter2Key                string                     `position:"Query" name:"Filter.2.Key"`
	ChargeType                string                     `position:"Query" name:"ChargeType"`
	AssociatedInstanceId      string                     `position:"Query" name:"AssociatedInstanceId"`
}

// DescribeEipAddressesTag is a repeated param struct in DescribeEipAddressesRequest
type DescribeEipAddressesTag struct {
	Value string `name:"Value"`
	Key   string `name:"Key"`
}

// DescribeEipAddressesResponse is the response struct for api DescribeEipAddresses
type DescribeEipAddressesResponse struct {
	*responses.BaseResponse
	PageSize     int          `json:"PageSize" xml:"PageSize"`
	RequestId    string       `json:"RequestId" xml:"RequestId"`
	PageNumber   int          `json:"PageNumber" xml:"PageNumber"`
	TotalCount   int          `json:"TotalCount" xml:"TotalCount"`
	EipAddresses EipAddresses `json:"EipAddresses" xml:"EipAddresses"`
}

// CreateDescribeEipAddressesRequest creates a request to invoke DescribeEipAddresses API
func CreateDescribeEipAddressesRequest() (request *DescribeEipAddressesRequest) {
	request = &DescribeEipAddressesRequest{
		RpcRequest: &requests.RpcRequest{},
	}
	request.InitWithApiInfo("Vpc", "2016-04-28", "DescribeEipAddresses", "vpc", "openAPI")
	request.Method = requests.POST
	return
}

// CreateDescribeEipAddressesResponse creates a response to parse from DescribeEipAddresses response
func CreateDescribeEipAddressesResponse() (response *DescribeEipAddressesResponse) {
	response = &DescribeEipAddressesResponse{
		BaseResponse: &responses.BaseResponse{},
	}
	return
}
