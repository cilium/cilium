# v1.114.0 (2023-08-21)

* **Feature**: The DeleteKeyPair API has been updated to return the keyPairId when an existing key pair is deleted.
* **Dependency Update**: Updated to the latest SDK module versions

# v1.113.1 (2023-08-18)

* **Dependency Update**: Updated to the latest SDK module versions

# v1.113.0 (2023-08-17)

* **Feature**: Adds support for SubnetConfigurations to allow users to select their own IPv4 and IPv6 addresses for Interface VPC endpoints
* **Dependency Update**: Updated to the latest SDK module versions

# v1.112.0 (2023-08-15)

* **Feature**: Documentation updates for Elastic Compute Cloud (EC2).

# v1.111.0 (2023-08-11)

* **Feature**: Amazon EC2 P5 instances, powered by the latest NVIDIA H100 Tensor Core GPUs, deliver the highest performance in EC2 for deep learning (DL) and HPC applications. M7i-flex and M7i instances are next-generation general purpose instances powered by custom 4th Generation Intel Xeon Scalable processors.

# v1.110.1 (2023-08-07)

* **Dependency Update**: Updated to the latest SDK module versions

# v1.110.0 (2023-08-03)

* **Feature**: This release adds new parameter isPrimaryIPv6 to  allow assigning an IPv6 address as a primary IPv6 address to a network interface which cannot be changed to give equivalent functionality available for network interfaces with primary IPv4 address.

# v1.109.1 (2023-08-01)

* No change notes available for this release.

# v1.109.0 (2023-07-31)

* **Feature**: Adds support for smithy-modeled endpoint resolution. A new rules-based endpoint resolution will be added to the SDK which will supercede and deprecate existing endpoint resolution. Specifically, EndpointResolver will be deprecated while BaseEndpoint and EndpointResolverV2 will take its place. For more information, please see the Endpoints section in our Developer Guide.
* **Dependency Update**: Updated to the latest SDK module versions

# v1.108.1 (2023-07-28)

* **Dependency Update**: Updated to the latest SDK module versions

# v1.108.0 (2023-07-27)

* **Feature**: SDK and documentation updates for Amazon Elastic Block Store APIs

# v1.107.0 (2023-07-25)

* **Feature**: This release adds an instance's peak and baseline network bandwidth as well as the memory sizes of an instance's inference accelerators to DescribeInstanceTypes.

# v1.106.0 (2023-07-24)

* **Feature**: Add "disabled" enum value to SpotInstanceState.

# v1.105.1 (2023-07-19)

* **Documentation**: Amazon EC2 documentation updates.

# v1.105.0 (2023-07-17)

* **Feature**: Add Nitro TPM support on DescribeInstanceTypes

# v1.104.0 (2023-07-13)

* **Feature**: This release adds support for the C7gn and Hpc7g instances. C7gn instances are powered by AWS Graviton3 processors and the fifth-generation AWS Nitro Cards. Hpc7g instances are powered by AWS Graviton 3E processors and provide up to 200 Gbps network bandwidth.
* **Dependency Update**: Updated to the latest SDK module versions

# v1.103.0 (2023-07-06)

* **Feature**: Add Nitro Enclaves support on DescribeInstanceTypes

# v1.102.0 (2023-06-20)

* **Feature**: Adds support for targeting Dedicated Host allocations by assetIds in AWS Outposts

# v1.101.0 (2023-06-19)

* **Feature**: API changes to AWS Verified Access to include data from trust providers in logs

# v1.100.1 (2023-06-15)

* No change notes available for this release.

# v1.100.0 (2023-06-13)

* **Feature**: This release introduces a new feature, EC2 Instance Connect Endpoint, that enables you to connect to a resource over TCP, without requiring the resource to have a public IPv4 address.
* **Dependency Update**: Updated to the latest SDK module versions

# v1.99.0 (2023-06-05)

* **Feature**: Making InstanceTagAttribute as the required parameter for the DeregisterInstanceEventNotificationAttributes and RegisterInstanceEventNotificationAttributes APIs.

# v1.98.0 (2023-05-18)

* **Feature**: Add support for i4g.large, i4g.xlarge, i4g.2xlarge, i4g.4xlarge, i4g.8xlarge and i4g.16xlarge instances powered by AWS Graviton2 processors that deliver up to 15% better compute performance than our other storage-optimized instances.

# v1.97.0 (2023-05-05)

* **Feature**: This release adds support the inf2 and trn1n instances. inf2 instances are purpose built for deep learning inference while trn1n instances are powered by AWS Trainium accelerators and they build on the capabilities of Trainium-powered trn1 instances.

# v1.96.1 (2023-05-04)

* No change notes available for this release.

# v1.96.0 (2023-05-03)

* **Feature**: Adds an SDK paginator for GetNetworkInsightsAccessScopeAnalysisFindings

# v1.95.0 (2023-04-27)

* **Feature**: This release adds support for AMD SEV-SNP on EC2 instances.

# v1.94.0 (2023-04-24)

* **Feature**: API changes to AWS Verified Access related to identity providers' information.
* **Dependency Update**: Updated to the latest SDK module versions

# v1.93.2 (2023-04-10)

* No change notes available for this release.

# v1.93.1 (2023-04-07)

* **Dependency Update**: Updated to the latest SDK module versions

# v1.93.0 (2023-04-04)

* **Feature**: C6in, M6in, M6idn, R6in and R6idn bare metal instances are powered by 3rd Generation Intel Xeon Scalable processors and offer up to 200 Gbps of network bandwidth.

# v1.92.1 (2023-03-31)

* **Documentation**: Documentation updates for EC2 On Demand Capacity Reservations

# v1.92.0 (2023-03-30)

* **Feature**: This release adds support for Tunnel Endpoint Lifecycle control, a new feature that provides Site-to-Site VPN customers with better visibility and control of their VPN tunnel maintenance updates.

# v1.91.0 (2023-03-21)

* **Feature**: This release adds support for AWS Network Firewall, AWS PrivateLink, and Gateway Load Balancers to Amazon VPC Reachability Analyzer, and it makes the path destination optional as long as a destination address in the filter at source is provided.
* **Dependency Update**: Updated to the latest SDK module versions

# v1.90.0 (2023-03-14)

* **Feature**: This release adds a new DnsOptions key (PrivateDnsOnlyForInboundResolverEndpoint) to CreateVpcEndpoint and ModifyVpcEndpoint APIs.

# v1.89.1 (2023-03-10)

* **Dependency Update**: Updated to the latest SDK module versions

# v1.89.0 (2023-03-08)

* **Feature**: Introducing Amazon EC2 C7g, M7g and R7g instances, powered by the latest generation AWS Graviton3 processors and deliver up to 25% better performance over Graviton2-based instances.

# v1.88.0 (2023-03-03)

* **Feature**: This release adds support for a new boot mode for EC2 instances called 'UEFI Preferred'.

# v1.87.0 (2023-02-28)

* **Feature**: This release allows IMDS support to be set to v2-only on an existing AMI, so that all future instances launched from that AMI will use IMDSv2 by default.

# v1.86.1 (2023-02-20)

* **Dependency Update**: Updated to the latest SDK module versions

# v1.86.0 (2023-02-14)

* **Feature**: With this release customers can turn host maintenance on or off when allocating or modifying a supported dedicated host. Host maintenance is turned on by default for supported hosts.

# v1.85.0 (2023-02-10)

* **Feature**: Adds support for waiters that automatically poll for an imported snapshot until it reaches the completed state.

# v1.84.1 (2023-02-03)

* **Dependency Update**: Updated to the latest SDK module versions
* **Dependency Update**: Upgrade smithy to 1.27.2 and correct empty query list serialization.

# v1.84.0 (2023-02-02)

* **Feature**: Documentation updates for EC2.

# v1.83.0 (2023-01-31)

* **Feature**: This launch allows customers to associate up to 8 IP addresses to their NAT Gateways to increase the limit on concurrent connections to a single destination by eight times from 55K to 440K.

# v1.82.0 (2023-01-30)

* **Feature**: We add Prefix Lists as a new route destination option for LocalGatewayRoutes. This will allow customers to create routes to Prefix Lists. Prefix List routes will allow customers to group individual CIDR routes with the same target into a single route.

# v1.81.0 (2023-01-25)

* **Feature**: This release adds new functionality that allows customers to provision IPv6 CIDR blocks through Amazon VPC IP Address Manager (IPAM) as well as allowing customers to utilize IPAM Resource Discovery APIs.

# v1.80.1 (2023-01-23)

* No change notes available for this release.

# v1.80.0 (2023-01-20)

* **Feature**: C6in, M6in, M6idn, R6in and R6idn instances are powered by 3rd Generation Intel Xeon Scalable processors (code named Ice Lake) with an all-core turbo frequency of 3.5 GHz.

# v1.79.0 (2023-01-19)

* **Feature**: Adds SSM Parameter Resource Aliasing support to EC2 Launch Templates. Launch Templates can now store parameter aliases in place of AMI Resource IDs. CreateLaunchTemplateVersion and DescribeLaunchTemplateVersions now support a convenience flag, ResolveAlias, to return the resolved parameter value.

# v1.78.0 (2023-01-13)

* **Feature**: Documentation updates for EC2.

# v1.77.0 (2022-12-20)

* **Feature**: Adds support for pagination in the EC2 DescribeImages API.

# v1.76.1 (2022-12-15)

* **Dependency Update**: Updated to the latest SDK module versions

# v1.76.0 (2022-12-12)

* **Feature**: This release updates DescribeFpgaImages to show supported instance types of AFIs in its response.

# v1.75.0 (2022-12-05)

* **Feature**: Documentation updates for EC2.

# v1.74.1 (2022-12-02)

* **Dependency Update**: Updated to the latest SDK module versions

# v1.74.0 (2022-11-29.2)

* **Feature**: This release adds support for AWS Verified Access and the Hpc6id Amazon EC2 compute optimized instance type, which features 3rd generation Intel Xeon Scalable processors.

# v1.73.0 (2022-11-29)

* **Feature**: Introduces ENA Express, which uses AWS SRD and dynamic routing to increase throughput and minimize latency, adds support for trust relationships between Reachability Analyzer and AWS Organizations to enable cross-account analysis, and adds support for Infrastructure Performance metric subscriptions.

# v1.72.1 (2022-11-22)

* No change notes available for this release.

# v1.72.0 (2022-11-18)

* **Feature**: This release adds support for copying an Amazon Machine Image's tags when copying an AMI.

# v1.71.0 (2022-11-17)

* **Feature**: This release adds a new optional parameter "privateIpAddress" for the CreateNatGateway API. PrivateIPAddress will allow customers to select a custom Private IPv4 address instead of having it be auto-assigned.

# v1.70.1 (2022-11-16)

* No change notes available for this release.

# v1.70.0 (2022-11-10)

* **Feature**: This release adds a new price capacity optimized allocation strategy for Spot Instances to help customers optimize provisioning of Spot Instances via EC2 Auto Scaling, EC2 Fleet, and Spot Fleet. It allocates Spot Instances based on both spare capacity availability and Spot Instance price.

# v1.69.0 (2022-11-09)

* **Feature**: Amazon EC2 Trn1 instances, powered by AWS Trainium chips, are purpose built for high-performance deep learning training. u-24tb1.112xlarge and u-18tb1.112xlarge High Memory instances are purpose-built to run large in-memory databases.

# v1.68.0 (2022-11-08)

* **Feature**: This release enables sharing of EC2 Placement Groups across accounts and within AWS Organizations using Resource Access Manager

# v1.67.0 (2022-11-07)

* **Feature**: This release adds support for two new attributes for attribute-based instance type selection - NetworkBandwidthGbps and AllowedInstanceTypes.

# v1.66.0 (2022-11-04)

* **Feature**: This release adds API support for the recipient of an AMI account share to remove shared AMI launch permissions.

# v1.65.0 (2022-10-31)

* **Feature**: Elastic IP transfer is a new Amazon VPC feature that allows you to transfer your Elastic IP addresses from one AWS Account to another.

# v1.64.0 (2022-10-27)

* **Feature**: Feature supports the replacement of instance root volume using an updated AMI without requiring customers to stop their instance.

# v1.63.3 (2022-10-24)

* **Dependency Update**: Updated to the latest SDK module versions

# v1.63.2 (2022-10-21)

* **Dependency Update**: Updated to the latest SDK module versions

# v1.63.1 (2022-10-06)

* No change notes available for this release.

# v1.63.0 (2022-10-04)

* **Feature**: Added EnableNetworkAddressUsageMetrics flag for ModifyVpcAttribute, DescribeVpcAttribute APIs.

# v1.62.0 (2022-10-03)

* **Feature**: Adding an imdsSupport attribute to EC2 AMIs

# v1.61.0 (2022-09-29)

* **Feature**: u-3tb1 instances are powered by Intel Xeon Platinum 8176M (Skylake) processors and are purpose-built to run large in-memory databases.

# v1.60.0 (2022-09-23)

* **Feature**: Letting external AWS customers provide ImageId as a Launch Template override in FleetLaunchTemplateOverridesRequest

# v1.59.0 (2022-09-22)

* **Feature**: Documentation updates for Amazon EC2.

# v1.58.0 (2022-09-20)

* **Feature**: This release adds support for blocked paths to Amazon VPC Reachability Analyzer.
* **Dependency Update**: Updated to the latest SDK module versions

# v1.57.0 (2022-09-19)

* **Feature**: This release adds CapacityAllocations field to DescribeCapacityReservations

# v1.56.0 (2022-09-15)

* **Feature**: This feature allows customers to create tags for vpc-endpoint-connections and vpc-endpoint-service-permissions.

# v1.55.0 (2022-09-14)

* **Feature**: Documentation updates for Amazon EC2.
* **Feature**: This release adds support to send VPC Flow Logs to kinesis-data-firehose as new destination type
* **Feature**: This update introduces API operations to manage and create local gateway route tables, CoIP pools, and VIF group associations.
* **Feature**: Two new features for local gateway route tables: support for static routes targeting Elastic Network Interfaces and direct VPC routing.
* **Dependency Update**: Updated to the latest SDK module versions

# v1.54.4 (2022-09-02)

* **Dependency Update**: Updated to the latest SDK module versions

# v1.54.3 (2022-08-31)

* **Dependency Update**: Updated to the latest SDK module versions

# v1.54.2 (2022-08-30)

* No change notes available for this release.

# v1.54.1 (2022-08-29)

* **Dependency Update**: Updated to the latest SDK module versions

# v1.54.0 (2022-08-22)

* **Feature**: R6a instances are powered by 3rd generation AMD EPYC (Milan) processors delivering all-core turbo frequency of 3.6 GHz. C6id, M6id, and R6id instances are powered by 3rd generation Intel Xeon Scalable processor (Ice Lake) delivering all-core turbo frequency of 3.5 GHz.

# v1.53.0 (2022-08-18)

* **Feature**: This release adds support for VPN log options , a new feature allowing S2S VPN connections to send IKE activity logs to CloudWatch Logs

# v1.52.1 (2022-08-11)

* **Dependency Update**: Updated to the latest SDK module versions

# v1.52.0 (2022-08-10)

* **Feature**: This release adds support for excluding specific data (non-root) volumes from multi-volume snapshot sets created from instances.

# v1.51.3 (2022-08-09)

* **Dependency Update**: Updated to the latest SDK module versions

# v1.51.2 (2022-08-08)

* **Dependency Update**: Updated to the latest SDK module versions

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

