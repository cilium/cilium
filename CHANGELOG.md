# Changelog

## v1.11.0-rc3

Summary of Changes
------------------

**Bugfixes:**
* `cluster-pool-ipv4-cidr` and `cluster-pool-ipv6-cidr` options now accept string slices and not just string (#17780, @cndoit18)
* Additional FQDN selector identity tracking fixes (#17788, @joestringer)
* bpf: exclude pod's reply traffic from egress gateway logic (#17869, @jibi)
* Fix bug where the agents would silently skip all IPv6 masquerading due to an incorrect configuration. (#17906, @pchaigno)
* Fixes an issue which can cause traffic to be dropped when running Cilium in ENI mode due to the presence of iptables rules left over by the AWS VPC CNI plugin. Notable features that could be impacted include the egress gateway functionality. (#17845, @bmcustodio)
* Operator gc incluster identities only (#17589, @ArthurChiao)

**Misc Changes:**
* Add few values in CiliumEndpointPropagation metric bucket. (#17957, @krishgobinath)
* build(deps): bump github.com/aliyun/alibaba-cloud-sdk-go from 1.61.1331 to 1.61.1333 (#17937, @dependabot[bot])
* build(deps): bump github.com/aliyun/alibaba-cloud-sdk-go from 1.61.1333 to 1.61.1334 (#17950, @dependabot[bot])
* build(deps): bump github.com/aws/aws-sdk-go-v2 from 1.11.0 to 1.11.1 (#17946, @dependabot[bot])
* build(deps): bump github.com/aws/aws-sdk-go-v2/feature/ec2/imds from 1.8.0 to 1.8.1 (#17951, @dependabot[bot])
* build(deps): bump github.com/Azure/azure-sdk-for-go from 59.2.0+incompatible to 59.3.0+incompatible (#17938, @dependabot[bot])
* build(deps): bump github.com/docker/docker from 20.10.10+incompatible to 20.10.11+incompatible (#17936, @dependabot[bot])
* datapath: allow specifying cilium_host routes metric (#17544, @Frankkkkk)
* Prepare for release v1.11.0-rc2 (#17934, @aanm)
* Remove duplicate CiliumNode watcher (#17873, @aanm)
