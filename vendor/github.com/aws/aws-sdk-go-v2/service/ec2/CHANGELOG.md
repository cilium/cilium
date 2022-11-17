# v1.51.1 (2022-08-01)

* **Dependency Update**: Updated to the latest SDK module versions

# v1.51.0 (2022-07-29)

* **Feature**: Documentation updates for Amazon EC2.

# v1.50.1 (2022-07-28)

* **Documentation**: Documentation updates for VM Import/Export.

# v1.50.0 (2022-07-22)

* **Feature**: Added support for EC2 M1 Mac instances. For more information, please visit aws.amazon.com/mac.

# v1.49.1 (2022-07-18)

* **Documentation**: Documentation updates for Amazon EC2.

# v1.49.0 (2022-07-14)

* **Feature**: This release adds flow logs for Transit Gateway to  allow customers to gain deeper visibility and insights into network traffic through their Transit Gateways.

# v1.48.0 (2022-07-11)

* **Feature**: Build, manage, and monitor a unified global network that connects resources running across your cloud and on-premises environments using the AWS Cloud WAN APIs.

# v1.47.2 (2022-07-05)

* **Dependency Update**: Updated to the latest SDK module versions

# v1.47.1 (2022-06-29)

* **Dependency Update**: Updated to the latest SDK module versions

# v1.47.0 (2022-06-28)

* **Feature**: This release adds a new spread placement group to EC2 Placement Groups: host level spread, which spread instances between physical hosts, available to Outpost customers only. CreatePlacementGroup and DescribePlacementGroups APIs were updated with a new parameter: SpreadLevel to support this feature.

# v1.46.0 (2022-06-21)

* **Feature**: This release adds support for Private IP VPNs, a new feature allowing S2S VPN connections to use private ip addresses as the tunnel outside ip address over Direct Connect as transport.

# v1.45.1 (2022-06-07)

* **Dependency Update**: Updated to the latest SDK module versions

# v1.45.0 (2022-05-26)

* **Feature**: C7g instances, powered by the latest generation AWS Graviton3 processors, provide the best price performance in Amazon EC2 for compute-intensive workloads.

# v1.44.0 (2022-05-24)

* **Feature**: Stop Protection feature enables customers to protect their instances from accidental stop actions.

# v1.43.1 (2022-05-17)

* **Dependency Update**: Updated to the latest SDK module versions

# v1.43.0 (2022-05-12)

* **Feature**: This release introduces a target type Gateway Load Balancer Endpoint for mirrored traffic. Customers can now specify GatewayLoadBalancerEndpoint option during the creation of a traffic mirror target.

# v1.42.0 (2022-05-11)

* **Feature**: This release updates AWS PrivateLink APIs to support IPv6 for PrivateLink Services and Endpoints of type 'Interface'.

# v1.41.0 (2022-05-10)

* **Feature**: Added support for using NitroTPM and UEFI Secure Boot on EC2 instances.

# v1.40.0 (2022-05-06)

* **Feature**: Add new state values for IPAMs, IPAM Scopes, and IPAM Pools.

# v1.39.0 (2022-05-05)

* **Feature**: Amazon EC2 I4i instances are powered by 3rd generation Intel Xeon Scalable processors and feature up to 30 TB of local AWS Nitro SSD storage

# v1.38.0 (2022-05-03)

* **Feature**: Adds support for allocating Dedicated Hosts on AWS  Outposts. The AllocateHosts API now accepts an OutpostArn request  parameter, and the DescribeHosts API now includes an OutpostArn response parameter.

# v1.37.0 (2022-04-28)

* **Feature**: This release adds support to query the public key and creation date of EC2 Key Pairs. Additionally, the format (pem or ppk) of a key pair can be specified when creating a new key pair.

# v1.36.1 (2022-04-25)

* **Dependency Update**: Updated to the latest SDK module versions

# v1.36.0 (2022-04-22)

* **Feature**: Adds support for waiters that automatically poll for a deleted NAT Gateway until it reaches the deleted state.

# v1.35.1 (2022-04-14)

* **Documentation**: Documentation updates for Amazon EC2.

# v1.35.0 (2022-04-12)

* **Feature**: X2idn and X2iedn instances are powered by 3rd generation Intel Xeon Scalable processors with an all-core turbo frequency up to 3.5 GHzAmazon EC2. C6a instances are powered by 3rd generation AMD EPYC processors.

# v1.34.0 (2022-03-30)

* **Feature**: This release simplifies the auto-recovery configuration process enabling customers to set the recovery behavior to disabled or default
* **Dependency Update**: Updated to the latest SDK module versions

# v1.33.0 (2022-03-25)

* **Feature**: This is release adds support for Amazon VPC Reachability Analyzer to analyze path through a Transit Gateway.

# v1.32.2 (2022-03-24)

* **Dependency Update**: Updated to the latest SDK module versions

# v1.32.1 (2022-03-23)

* **Dependency Update**: Updated to the latest SDK module versions

# v1.32.0 (2022-03-15)

* **Feature**: Adds the Cascade parameter to the DeleteIpam API. Customers can use this parameter to automatically delete their IPAM, including non-default scopes, pools, cidrs, and allocations. There mustn't be any pools provisioned in the default public scope to use this parameter.

# v1.31.0 (2022-03-08)

* **Feature**: Updated `github.com/aws/smithy-go` to latest version
* **Feature**: Updated service client model to latest release.
* **Dependency Update**: Updated to the latest SDK module versions

# v1.30.0 (2022-02-24)

* **Feature**: API client updated
* **Feature**: Adds RetryMaxAttempts and RetryMod to API client Options. This allows the API clients' default Retryer to be configured from the shared configuration files or environment variables. Adding a new Retry mode of `Adaptive`. `Adaptive` retry mode is an experimental mode, adding client rate limiting when throttles reponses are received from an API. See [retry.AdaptiveMode](https://pkg.go.dev/github.com/aws/aws-sdk-go-v2/aws/retry#AdaptiveMode) for more details, and configuration options.
* **Feature**: Updated `github.com/aws/smithy-go` to latest version
* **Dependency Update**: Updated to the latest SDK module versions

# v1.29.0 (2022-01-28)

* **Feature**: Updated to latest API model.

# v1.28.0 (2022-01-14)

* **Feature**: Updated API models
* **Feature**: Updated `github.com/aws/smithy-go` to latest version
* **Dependency Update**: Updated to the latest SDK module versions

# v1.27.0 (2022-01-07)

* **Feature**: API client updated
* **Feature**: Updated `github.com/aws/smithy-go` to latest version
* **Dependency Update**: Updated to the latest SDK module versions

# v1.26.0 (2021-12-21)

* **Feature**: API Paginators now support specifying the initial starting token, and support stopping on empty string tokens.
* **Feature**: API client updated
* **Feature**: Updated to latest service endpoints

# v1.25.0 (2021-12-02)

* **Feature**: API client updated
* **Bug Fix**: Fixes a bug that prevented aws.EndpointResolverWithOptions from being used by the service client. ([#1514](https://github.com/aws/aws-sdk-go-v2/pull/1514))
* **Dependency Update**: Updated to the latest SDK module versions

# v1.24.0 (2021-11-30)

* **Feature**: API client updated

# v1.23.0 (2021-11-19)

* **Feature**: API client updated
* **Dependency Update**: Updated to the latest SDK module versions

# v1.22.0 (2021-11-12)

* **Feature**: Service clients now support custom endpoints that have an initial URI path defined.
* **Feature**: Updated service to latest API model.
* **Feature**: Waiters now have a `WaitForOutput` method, which can be used to retrieve the output of the successful wait operation. Thank you to [Andrew Haines](https://github.com/haines) for contributing this feature.

# v1.21.0 (2021-11-06)

* **Feature**: The SDK now supports configuration of FIPS and DualStack endpoints using environment variables, shared configuration, or programmatically.
* **Feature**: Updated `github.com/aws/smithy-go` to latest version
* **Feature**: Updated service to latest API model.
* **Dependency Update**: Updated to the latest SDK module versions

# v1.20.0 (2021-10-21)

* **Feature**: API client updated
* **Feature**: Updated  to latest version
* **Dependency Update**: Updated to the latest SDK module versions

# v1.19.0 (2021-10-11)

* **Feature**: API client updated
* **Dependency Update**: Updated to the latest SDK module versions

# v1.18.0 (2021-09-24)

* **Feature**: API client updated

# v1.17.0 (2021-09-17)

* **Feature**: Updated API client and endpoints to latest revision.
* **Dependency Update**: Updated to the latest SDK module versions

# v1.16.0 (2021-09-02)

* **Feature**: API client updated

# v1.15.0 (2021-08-27)

* **Feature**: Updated API model to latest revision.
* **Feature**: Updated `github.com/aws/smithy-go` to latest version
* **Dependency Update**: Updated to the latest SDK module versions

# v1.14.0 (2021-08-19)

* **Feature**: API client updated
* **Dependency Update**: Updated to the latest SDK module versions

# v1.13.0 (2021-08-04)

* **Feature**: Updated to latest API model.
* **Dependency Update**: Updated `github.com/aws/smithy-go` to latest version.
* **Dependency Update**: Updated to the latest SDK module versions

# v1.12.0 (2021-07-15)

* **Feature**: Updated service model to latest version.
* **Dependency Update**: Updated `github.com/aws/smithy-go` to latest version
* **Dependency Update**: Updated to the latest SDK module versions

# v1.11.0 (2021-07-01)

* **Feature**: API client updated

# v1.10.0 (2021-06-25)

* **Feature**: API client updated
* **Feature**: Updated `github.com/aws/smithy-go` to latest version
* **Dependency Update**: Updated to the latest SDK module versions

# v1.9.0 (2021-06-04)

* **Feature**: Updated service client to latest API model.

# v1.8.0 (2021-05-25)

* **Feature**: API client updated

# v1.7.1 (2021-05-20)

* **Dependency Update**: Updated to the latest SDK module versions

# v1.7.0 (2021-05-14)

* **Feature**: Constant has been added to modules to enable runtime version inspection for reporting.
* **Feature**: Updated to latest service API model.
* **Dependency Update**: Updated to the latest SDK module versions

