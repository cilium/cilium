#!/usr/bin/env bash

# This script updates all vendored cloud provider SDK Go modules to their latest
# version.
#
# These dependencies are not updated automatically by dependabot like
# other Go dependencies due to the frequency of thes updates requiring developer
# time for review and also the frequent need to rebase these PRs (see
# https://github.com/cilium/cilium/pull/18067). Instead, we manually update the
# dependencies all at once on a monthly basis using this script.

set -e
set -o pipefail

for mod in \
	github.com/Azure/azure-sdk-for-go/sdk/azcore \
	github.com/Azure/azure-sdk-for-go/sdk/azidentity \
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v6 \
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v6 \
	github.com/aliyun/alibaba-cloud-sdk-go \
	github.com/aws/aws-sdk-go-v2 \
	github.com/aws/aws-sdk-go-v2/config \
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds \
	github.com/aws/aws-sdk-go-v2/service/ec2 \
	github.com/aws/smithy-go
do
	go get $mod@latest
done
go mod tidy
go mod vendor
