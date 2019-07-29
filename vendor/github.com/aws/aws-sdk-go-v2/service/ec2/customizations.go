package ec2

import (
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/internal/awsutil"
)

const (
	// customRetryerMaxNumRetries sets max number of retries
	customRetryerMaxNumRetries = 3

	// customRetryerMinRetryDelay sets min retry delay
	customRetryerMinRetryDelay = 1 * time.Second

	// customRetryerMaxRetryDelay sets max retry delay
	customRetryerMaxRetryDelay = 8 * time.Second
)

// setRetryerConfig overrides the default Retryer values
func setRetryerConfig(d *aws.DefaultRetryer) {
	d.NumMaxRetries = customRetryerMaxNumRetries
	d.MinRetryDelay = customRetryerMinRetryDelay
	d.MinThrottleDelay = customRetryerMinRetryDelay
	d.MaxRetryDelay = customRetryerMaxRetryDelay
	d.MaxThrottleDelay = customRetryerMaxRetryDelay
}

func init() {
	initRequest = func(c *Client, r *aws.Request) {
		if r.Operation.Name == opCopySnapshot { // fill the PresignedURL parameter
			r.Handlers.Build.PushFront(fillPresignedURL)
		}
		if c.Config.Retryer == nil && (r.Operation.Name == opModifyNetworkInterfaceAttribute || r.Operation.Name == opAssignPrivateIpAddresses) {
			r.Retryer = aws.NewDefaultRetryer(setRetryerConfig)
		}
	}
}

func fillPresignedURL(r *aws.Request) {
	if !r.ParamsFilled() {
		return
	}

	origParams := r.Params.(*CopySnapshotInput)

	// Stop if PresignedURL/DestinationRegion is set
	if origParams.PresignedUrl != nil || origParams.DestinationRegion != nil {
		return
	}

	origParams.DestinationRegion = aws.String(r.Config.Region)
	newParams := awsutil.CopyOf(r.Params).(*CopySnapshotInput)

	// Create a new request based on the existing request. We will use this to
	// presign the CopySnapshot request against the source region.
	cfgCp := r.Config.Copy()
	cfgCp.EndpointResolver = nil
	cfgCp.Region = aws.StringValue(origParams.SourceRegion)

	metadata := r.Metadata
	resolved, err := r.Config.EndpointResolver.ResolveEndpoint(metadata.EndpointsID, cfgCp.Region)
	if err != nil {
		r.Error = err
		return
	}

	cfgCp.EndpointResolver = aws.ResolveWithEndpoint(resolved)
	metadata.Endpoint = resolved.URL
	metadata.SigningRegion = resolved.SigningRegion

	// Presign a CopySnapshot request with modified params
	req := aws.New(cfgCp, metadata, r.Handlers, r.Retryer, r.Operation, newParams, r.Data)
	url, err := req.Presign(5 * time.Minute) // 5 minutes should be enough.
	if err != nil {                          // bubble error back up to original request
		r.Error = err
		return
	}

	// We have our URL, set it on params
	origParams.PresignedUrl = &url
}
