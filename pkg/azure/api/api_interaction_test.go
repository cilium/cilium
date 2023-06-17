// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build azure

package api

import (
	"context"
	"fmt"

	check "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/api/metrics/mock"
)

// How to run these tests:
//
// 1. Modify testSubscription and testResourceGroup
// 2. Set
//      AZURE_SUBSCRIPTION_ID=$(az account show --query "id" --output tsv)
//      AZURE_NODE_RESOURCE_GROUP=$(az aks show --resource-group ${RESOURCE_GROUP} --name ${CLUSTER_NAME} --query "nodeResourceGroup" --output tsv)
// 			AZURE_SERVICE_PRINCIPAL=$(az ad sp create-for-rbac --scopes /subscriptions/${AZURE_SUBSCRIPTION_ID}/resourceGroups/${AZURE_NODE_RESOURCE_GROUP} --role Contributor --output json --only-show-errors)
//      AZURE_TENANT_ID=$(echo ${AZURE_SERVICE_PRINCIPAL} | jq -r '.tenant')
//      AZURE_CLIENT_ID=$(echo ${AZURE_SERVICE_PRINCIPAL} | jq -r '.appId')
//      AZURE_CLIENT_SECRET=$(echo ${AZURE_SERVICE_PRINCIPAL} | jq -r '.password')

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
