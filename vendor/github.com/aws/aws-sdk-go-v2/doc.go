/*
Package sdk is the official AWS SDK v2 for the Go programming language.

aws-sdk-go-v2 is the Developer Preview for the v2 of the AWS SDK for the Go
programming language. Look for additional documentation and examples to be
added.

Getting started

The best way to get started working with the SDK is to use `go get` to add the
SDK to your Go Workspace manually.

	go get github.com/aws/aws-sdk-go-v2

You could also use [Dep] to add the SDK to your application's dependencies.
Using [Dep] will simplify your update story and help your application keep
pinned to specific version of the SDK

	dep ensure --add github.com/aws/aws-sdk-go-v2

### Hello AWS

This example shows how you can use the v2 SDK to make an API request using the
SDK's Amazon DynamoDB client.

	package main

	import (
		"github.com/aws/aws-sdk-go-v2/aws"
		"github.com/aws/aws-sdk-go-v2/aws/endpoints"
		"github.com/aws/aws-sdk-go-v2/aws/external"
		"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	)

	func main() {
		// Using the SDK's default configuration, loading additional config
		// and credentials values from the environment variables, shared
		// credentials, and shared configuration files
		cfg, err := external.LoadDefaultAWSConfig()
		if err != nil {
			panic("unable to load SDK config, " + err.Error())
		}

		// Set the AWS Region that the service clients should use
		cfg.Region = endpoints.UsWest2RegionID

		// Using the Config value, create the DynamoDB client
		svc := dynamodb.New(cfg)

		// Build the request with its input parameters
		req := svc.DescribeTableRequest(&dynamodb.DescribeTableInput{
			TableName: aws.String("myTable"),
		})

		// Send the request, and get the response or error back
		resp, err := req.Send()
		if err != nil {
			panic("failed to describe table, "+err.Error())
		}

		fmt.Println("Response", resp)
	}

*/
package sdk
