package ec2metadata

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/awserr"
)

// getToken uses the duration to return a token for EC2 metadata service,
// or an error if the request failed.
func (c *Client) getToken(ctx context.Context, duration time.Duration) (tokenOutput, error) {
	op := &aws.Operation{
		Name:       "GetToken",
		HTTPMethod: "PUT",
		HTTPPath:   "/api/token",
	}

	var output tokenOutput
	req := c.NewRequest(op, nil, &output)
	req.SetContext(ctx)
	// remove the fetch token handler from the request handlers to avoid infinite recursion
	req.Handlers.Sign.RemoveByName(fetchTokenHandlerName)

	// Swap the unmarshalMetadataHandler with unmarshalTokenHandler on this request.
	req.Handlers.Unmarshal.Swap(unmarshalMetadataHandlerName, unmarshalTokenHandler)

	ttl := strconv.FormatInt(int64(duration/time.Second), 10)
	req.HTTPRequest.Header.Set(ttlHeader, ttl)

	err := req.Send()

	// Errors with bad request status should be returned.
	if err != nil {
		err = awserr.NewRequestFailure(
			awserr.New(req.HTTPResponse.Status, http.StatusText(req.HTTPResponse.StatusCode), err),
			req.HTTPResponse.StatusCode, req.RequestID)
	}

	return output, err
}

// GetMetadata uses the path provided to request information from the EC2
// instance metadata service. The content will be returned as a string, or
// error if the request failed.
func (c *Client) GetMetadata(ctx context.Context, p string) (string, error) {
	op := &aws.Operation{
		Name:       "GetMetadata",
		HTTPMethod: "GET",
		HTTPPath:   suffixPath("/meta-data", p),
	}

	output := &metadataOutput{}
	req := c.NewRequest(op, nil, output)
	req.SetContext(ctx)
	return output.Content, req.Send()
}

// GetUserData returns the userdata that was configured for the service. If
// there is no user-data setup for the EC2 instance a "NotFoundError" error
// code will be returned.
func (c *Client) GetUserData(ctx context.Context) (string, error) {
	op := &aws.Operation{
		Name:       "GetUserData",
		HTTPMethod: "GET",
		HTTPPath:   "/user-data",
	}

	output := &metadataOutput{}
	req := c.NewRequest(op, nil, output)
	req.SetContext(ctx)
	return output.Content, req.Send()
}

// GetDynamicData uses the path provided to request information from the EC2
// instance metadata service for dynamic data. The content will be returned
// as a string, or error if the request failed.
func (c *Client) GetDynamicData(ctx context.Context, p string) (string, error) {
	op := &aws.Operation{
		Name:       "GetDynamicData",
		HTTPMethod: "GET",
		HTTPPath:   suffixPath("/dynamic", p),
	}

	output := &metadataOutput{}
	req := c.NewRequest(op, nil, output)
	req.SetContext(ctx)
	return output.Content, req.Send()
}

// GetInstanceIdentityDocument retrieves an identity document describing an
// instance. Error is returned if the request fails or is unable to parse
// the response.
func (c *Client) GetInstanceIdentityDocument(ctx context.Context) (EC2InstanceIdentityDocument, error) {
	resp, err := c.GetDynamicData(ctx, "instance-identity/document")
	if err != nil {
		return EC2InstanceIdentityDocument{},
			awserr.New("EC2MetadataRequestError",
				"failed to get EC2 instance identity document", err)
	}

	doc := EC2InstanceIdentityDocument{}
	if err := json.NewDecoder(strings.NewReader(resp)).Decode(&doc); err != nil {
		return EC2InstanceIdentityDocument{},
			awserr.New("SerializationError",
				"failed to decode EC2 instance identity document", err)
	}

	return doc, nil
}

// IAMInfo retrieves IAM info from the metadata API
func (c *Client) IAMInfo(ctx context.Context) (EC2IAMInfo, error) {
	resp, err := c.GetMetadata(ctx, "iam/info")
	if err != nil {
		return EC2IAMInfo{},
			awserr.New("EC2MetadataRequestError",
				"failed to get EC2 IAM info", err)
	}

	info := EC2IAMInfo{}
	if err := json.NewDecoder(strings.NewReader(resp)).Decode(&info); err != nil {
		return EC2IAMInfo{},
			awserr.New("SerializationError",
				"failed to decode EC2 IAM info", err)
	}

	if info.Code != "Success" {
		errMsg := fmt.Sprintf("failed to get EC2 IAM Info (%s)", info.Code)
		return EC2IAMInfo{},
			awserr.New("EC2MetadataError", errMsg, nil)
	}

	return info, nil
}

// Region returns the region the instance is running in.
func (c *Client) Region(ctx context.Context) (string, error) {
	ec2InstanceIdentityDocument, err := c.GetInstanceIdentityDocument(ctx)
	if err != nil {
		return "", err
	}
	// extract region from the ec2InstanceIdentityDocument
	region := ec2InstanceIdentityDocument.Region
	if len(region) == 0 {
		return "", awserr.New("EC2MetadataError", "invalid region received for ec2metadata instance", nil)
	}
	// returns region
	return region, nil
}

// Available returns if the application has access to the EC2 Instance Metadata
// service.  Can be used to determine if application is running within an EC2
// Instance and the metadata service is available.
func (c *Client) Available(ctx context.Context) bool {
	if _, err := c.GetMetadata(ctx, "instance-id"); err != nil {
		return false
	}

	return true
}

// An EC2IAMInfo provides the shape for unmarshaling
// an IAM info from the metadata API
type EC2IAMInfo struct {
	Code               string
	LastUpdated        time.Time
	InstanceProfileArn string
	InstanceProfileID  string
}

// An EC2InstanceIdentityDocument provides the shape for unmarshaling
// an instance identity document
type EC2InstanceIdentityDocument struct {
	DevpayProductCodes      []string  `json:"devpayProductCodes"`
	MarketplaceProductCodes []string  `json:"marketplaceProductCodes"`
	AvailabilityZone        string    `json:"availabilityZone"`
	PrivateIP               string    `json:"privateIp"`
	Version                 string    `json:"version"`
	Region                  string    `json:"region"`
	InstanceID              string    `json:"instanceId"`
	BillingProducts         []string  `json:"billingProducts"`
	InstanceType            string    `json:"instanceType"`
	AccountID               string    `json:"accountId"`
	PendingTime             time.Time `json:"pendingTime"`
	ImageID                 string    `json:"imageId"`
	KernelID                string    `json:"kernelId"`
	RamdiskID               string    `json:"ramdiskId"`
	Architecture            string    `json:"architecture"`
}

func suffixPath(base, add string) string {
	reqPath := path.Join(base, add)
	if len(add) != 0 && add[len(add)-1] == '/' {
		reqPath += "/"
	}
	return reqPath
}
