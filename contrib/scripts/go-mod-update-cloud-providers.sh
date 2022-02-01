#!/bin/bash

set -e
set -o pipefail

for mod in \
	github.com/Azure/azure-sdk-for-go \
	github.com/Azure/go-autorest/autorest \
	github.com/Azure/go-autorest/autorest/adal \
	github.com/Azure/go-autorest/autorest/azure/auth \
	github.com/Azure/go-autorest/autorest/to \
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
