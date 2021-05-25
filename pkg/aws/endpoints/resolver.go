// Copyright 2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package endpoints

import (
	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/aws/aws-sdk-go-v2/aws"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "aws-endpoints")
)

func Resolver(service, region string) (aws.Endpoint, error) {
	if ep := operatorOption.Config.EC2APIEndpoint; len(ep) > 0 && service == "ec2" {
		log.Debugf("Using custom API endpoint %s for service %s in region %s", ep, service, region)
		// See https://docs.aws.amazon.com/sdk-for-go/v2/api/aws/endpoints/#hdr-Using_Custom_Endpoints
		return aws.Endpoint{
			URL: "https://" + ep,
		}, nil
	}

	return aws.Endpoint{}, &aws.EndpointNotFoundError{}
}
