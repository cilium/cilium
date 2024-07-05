// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoints

import (
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"

	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "aws-endpoints")
)

func Resolver(service, region string) (aws.Endpoint, error) {
	if ep := operatorOption.Config.EC2APIEndpoint; len(ep) > 0 && service == ec2.ServiceID {
		log.Debugf("Using custom API endpoint %s for service %s in region %s", ep, service, region)
		// See https://docs.aws.amazon.com/sdk-for-go/v2/api/aws/endpoints/#hdr-Using_Custom_Endpoints
		return aws.Endpoint{
			URL: "https://" + ep,
		}, nil
	}

	return aws.Endpoint{}, &aws.EndpointNotFoundError{}
}
