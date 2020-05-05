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

// +build azure

package api

import (
	"context"
	"fmt"

	"github.com/cilium/cilium/pkg/api/metrics/mock"

	"gopkg.in/check.v1"
)

// How to run these tests:
//
// 1. Modify testSubscription and testResourceGroup
// 2. Create a service principal
//      az ad sp create-for-rbac -n cilium-unit-test
//      {
//        "appId": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
//        "displayName": "cilium-unit-test",
//        "name": "http://cilium-unit-test",
//        "password": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
//        "tenant": "cccccccc-cccc-cccc-cccc-cccccccccccc"
//      }
// 3. Set
//      AZURE_SUBSCRIPTION_ID=$(az account show --query id | tr -d \")
//      AZURE_CLIENT_ID=aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
//      AZURE_CLIENT_SECRET=bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb
//      AZURE_TENANT_ID=cccccccc-cccc-cccc-cccc-cccccccccccc
//      AZURE_NODE_RESOURCE_GROUP=$(az aks show -n $CLUSTER_NAME -g $RESOURCE_GROUP | jq -r .nodeResourceGroup)

type ApiInteractionSuite struct{}

var (
	_ = check.Suite(&ApiInteractionSuite{})

	testSubscription  = "fd182b79-36cb-4a4e-b567-e568d63f9f62"
	testResourceGroup = "MC_aks-test_aks-test_westeurope"
)

func (a *ApiInteractionSuite) TestRateLimit(c *check.C) {
	client, err := NewClient(testSubscription, testResourceGroup, mock.NewMockMetrics(), 10.0, 4)
	c.Assert(err, check.IsNil)

	instances, err := client.GetInstances(context.Background())
	c.Assert(err, check.IsNil)
	fmt.Printf("%+v\n", instances)
}
