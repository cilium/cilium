package ec2imds

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/awslabs/smithy-go"
	smithyio "github.com/awslabs/smithy-go/io"
	"github.com/awslabs/smithy-go/middleware"
	smithyhttp "github.com/awslabs/smithy-go/transport/http"
)

const getInstanceIdentityDocumentPath = getDynamicDataPath + "/instance-identity/document"

// GetInstanceIdentityDocument retrieves an identity document describing an
// instance. Error is returned if the request fails or is unable to parse
// the response.
func (c *Client) GetInstanceIdentityDocument(
	ctx context.Context, params *GetInstanceIdentityDocumentInput, optFns ...func(*Options),
) (
	*GetInstanceIdentityDocumentOutput, error,
) {
	if params == nil {
		params = &GetInstanceIdentityDocumentInput{}
	}

	result, metadata, err := c.invokeOperation(ctx, "GetInstanceIdentityDocument", params, optFns,
		addGetInstanceIdentityDocumentMiddleware,
	)
	if err != nil {
		return nil, err
	}

	out := result.(*GetInstanceIdentityDocumentOutput)
	out.ResultMetadata = metadata
	return out, nil
}

// GetInstanceIdentityDocumentInput provides the input parameters for
// GetInstanceIdentityDocument operation.
type GetInstanceIdentityDocumentInput struct{}

// GetInstanceIdentityDocumentOutput provides the output parameters for
// GetInstanceIdentityDocument operation.
type GetInstanceIdentityDocumentOutput struct {
	InstanceIdentityDocument

	ResultMetadata middleware.Metadata
}

func addGetInstanceIdentityDocumentMiddleware(stack *middleware.Stack, options Options) error {
	return addAPIRequestMiddleware(stack,
		options,
		buildGetInstanceIdentityDocumentPath,
		buildGetInstanceIdentityDocumentOutput,
	)
}

func buildGetInstanceIdentityDocumentPath(params interface{}) (string, error) {
	return getInstanceIdentityDocumentPath, nil
}

func buildGetInstanceIdentityDocumentOutput(resp *smithyhttp.Response) (interface{}, error) {
	defer resp.Body.Close()

	var buff [1024]byte
	ringBuffer := smithyio.NewRingBuffer(buff[:])
	body := io.TeeReader(resp.Body, ringBuffer)

	output := &GetInstanceIdentityDocumentOutput{}
	if err := json.NewDecoder(body).Decode(&output.InstanceIdentityDocument); err != nil {
		return nil, &smithy.DeserializationError{
			Err:      fmt.Errorf("failed to decode instance identity document, %w", err),
			Snapshot: ringBuffer.Bytes(),
		}
	}

	return output, nil
}

// InstanceIdentityDocument provides the shape for unmarshaling
// an instance identity document
type InstanceIdentityDocument struct {
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
