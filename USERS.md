Who is using Cilium?
====================

Sharing experiences and learning from other users is essential. We are
frequently asked who is using a particular feature of Cilium so people can get in
contact with other users to share experiences and best practices. People
also often want to know if product/platform X has integrated Cilium.
While the [Cilium Slack community](https://cilium.herokuapp.com/) allows
users to get in touch, it can be challenging to find this information quickly.

The following is a directory of adopters to help identify users of individual
features. The users themselves directly maintain the list.

Adding yourself as a user
-------------------------

If you are using Cilium or it is integrated into your product, service, or
platform, please consider adding yourself as a user with a quick
description of your use case by opening a pull request to this file and adding
a section describing your usage of Cilium. If you are open to others contacting
you about your use of Cilium on Slack, add your Slack nickname as well.

    N: Name of user (company or individual)
    D: Description
    U: Usage of features
    L: Link with further information (optional)
    Q: Contacts available for questions (optional)

Example entry:

    * N: Cilium Example User Inc.
      D: Cilium Example User Inc. is using Cilium for scientific purposes
      U: ENI networking, DNS policies, ClusterMesh
      Q: @slacknick1, @slacknick2

Requirements to be listed
-------------------------

 * You must represent the user listed. Do *NOT* add entries on behalf of
   other users.
 * There is no minimum deployment size but we request to list permanent
   deployments only, i.e., no demo or trial deployments. Commercial or
   production use is not required. A well-done home lab setup can be equally
   interesting as a large-scale commercial deployment.

Users (Alphabetically)
----------------------

    * N: AccuKnox
      D: AccuKnox uses Cilium for network visibility and network policy enforcement.
      U: L3/L4/L7 policy enforcement using Identity, External/VM Workloads, Network Visibility using Hubble
      L: https://www.accuknox.com/spifee-identity-for-cilium-presentation-at-kubecon-2021, https://www.accuknox.com/cilium
      Q: @nyrahul

    * N: Acoss
      D: Acoss is using cilium as their main CNI plugin (self hosted k8s, On-premises)
      U: CiliumNetworkPolicy, Hubble, BPF NodePort, Direct routing
      L: @JrCs

    * N: Adobe, Inc.
      D: Adobe's Project Ethos uses Cilium for multi-tenant, multi-cloud clusters
      U: L3/L4/L7 policies
      L: https://youtu.be/39FLsSc2P-Y

    * N: Alibaba Cloud
      D: Alibaba Cloud is using Cilium together with Terway CNI as the high-performance ENI dataplane
      U: Networking, NetworkPolicy, Services, IPVLAN
      L: https://www.alibabacloud.com/blog/how-does-alibaba-cloud-build-high-performance-cloud-native-pod-networks-in-production-environments_596590

    * N: Amazon Web Services (AWS)
      D: AWS uses Cilium as the default CNI for EKS Anywhere
      U: Networking, NetworkPolicy, Services
      L: https://isovalent.com/blog/post/2021-09-aws-eks-anywhere-chooses-cilium

    * N: APPUiO by VSHN
      D: VSHN uses Cilium for multi-tenant networking on APPUiO Cloud and as an add-on to APPUiO Managed, both on Red Hat OpenShift and Cloud Kubernetes.
      U: CNI, Networking, NetworkPolicy, Hubble, IPAM, Kubernetes services
      L: https://products.docs.vshn.ch/products/appuio/managed/addon_cilium.html and https://www.appuio.cloud

    * N: ArangoDB Oasis
      D: ArangoDB Oasis is using Cilium in to separate database deployments in our multi-tenant cloud environment
      U: Networking, CiliumNetworkPolicy(cluster & local), Hubble, IPAM
      L: https://cloud.arangodb.com
      Q: @ewoutp @Robert-Stam

    * N: Ascend.io
      D: Ascend.io is using Cilium as a consistent CNI for our Data Automation Platform on GKE, EKS, and AKS.
      U: Transparent Encryption, Overlay Networking, Cluster Mesh, Egress Gateway, Network Policy, Hubble
      L: https://www.ascend.io/
      Q: @Joe Stevens

    * N: Ayedo
      D: Ayedo builds and operates cloud-native container platforms based on Kubernetes
      U: Hubble for Visibility, Cilium as Mesh between Services
      L: https://www.ayedo.de/

    * N: ByteDance
      D: ByteDance is using Cilium as CNI plug-in for self-hosted Kubernetes.
      U: CNI, Networking
      L: @Jiang Wang

    * N: Canonical
      D: Canonical's Kubernetes distribution microk8s uses Cilium as CNI plugin
      U: Networking, NetworkPolicy, and Kubernetes services
      L: https://microk8s.io/

    * N: Capital One
      D: Capital One uses Cilium as its standard CNI for all Kubernetes environments
      U: CNI, CiliumClusterWideNetworkpolicy, CiliumNetworkPolicy, Hubble, network visibility
      L: https://www.youtube.com/watch?v=hwOpCKBaJ-w

    * N: CENGN - Centre of Excellence in Next Generation Networks
      D: CENGN is using Cilium in multiple clusters including production and development clusters (self-hosted k8s, On-premises)
      U: L3/L4/L7 network policies, Monitoring via Prometheus metrics & Hubble
      L: https://www.youtube.com/watch?v=yXm7yZE2rk4
      Q: @rmaika @mohahmed13

    * N: Cistec
      D: Cistec is a clinical information system provider and uses Cilium as the CNI plugin.
      U: Networking and network policy
      L: https://www.cistec.com/
      
    * N: Civo
      D: Civo is offering Cilium as the CNI option for Civo users to choose it for their Civo Kubernetes clusters.
      U: Networking and network policy
      L: https://www.civo.com/kubernetes

    * N: ClickHouse
      D: ClickHouse uses Cilium as CNI for AWS Kubernetes environments
      U: CiliumNetworkPolicy, Hubble, ClusterMesh
      L: https://clickhouse.com

    * N: Cognite
      D: Cognite is an industrial DataOps provider and uses Cilium as the CNI plugin
      Q: @Robert Collins

    * N: CONNY
      D: CONNY is legaltech platform to improve access to justice for individuals
      U: Networking, NetworkPolicy, Services
      Q: @ant31
      L: https://conny.de
      
    * N: Cosmonic
      D: Cilium is the CNI for Cosmonic's Nomad based PaaS
      U: Networking, NetworkPolicy, Transparent Encryption
      L: https://cilium.io/blog/2023/01/18/cosmonic-user-story/

    * N: Crane
      D: Crane uses Cilium as the default CNI
      U: Networking, NetworkPolicy, Services
      L: https://github.com/slzcc/crane
      Q: @slzcc

    * N: Daimler Truck AG 
      D: The CSG RuntimeDepartment of DaimlerTruck is maintaining an AKS k8s cluster as a shared resource for DevOps crews and is using Cilium as the default CNI (BYOCNI).
      U: Networking, NetworkPolicy and Monitoring
      L: https://daimlertruck.com
      Q: @brandshaide

    * N: DaoCloud - spiderpool & merbridge
      D: spiderpool is using Cilium as their main CNI plugin for overlay and merbridge is using  Cilium eBPF library to speed up your Service Mesh
      U: CNI, Service load-balancing, cluster mesh
      L: https://github.com/spidernet-io/spiderpool, https://github.com/merbridge/merbridge
      Q: @weizhoublue, @kebe7jun

    * N: Datadog
      D: Datadog is using Cilium in AWS (self-hosted k8s)
      U: ENI Networking, Service load-balancing, Encryption
      Q: @lbernail, @roboll

    * N: Deckhouse
      D: Deckhouse Kubernetes Platform is using Cilium as a one of the supported CNIs.
      U: Networking, Security, Hubble UI for network visibility
      L: https://github.com/deckhouse/deckhouse

    * N: DigitalOcean
      D: DigitalOcean is using Cilium as the CNI for Digital Ocean's managed Kubernetes Services (DOKS)
      U: Networking and network policy
      L: https://github.com/digitalocean/DOKS

    * N: Edgeless Systems
      D: Edgeless Systems is using Cilium as the CNI for Edgeless System's Confidential Kubernetes Distribution (Constellation)
      U: Networking (CNI), Transparent Encryption (WG), 
      L: https://docs.edgeless.systems/constellation/architecture/networking
      Q: @m1ghtym0
 
    * N: Elastic Path
      D: Elastic Path is using Cilium in their CloudOps for Kubernetes production clusters
      U: CNI
      L: https://documentation.elasticpath.com/cloudops-kubernetes/docs/index.html
      Q: @Neil Seward

    * N: Equinix
      D: Equinix Metal is using Cilium for production and non-production environments on bare metal
      U: CNI, CiliumClusterWideNetworkpolicy, CiliumNetworkPolicy, BGP advertisements, Hubble, network visibility
      L: https://metal.equinix.com/
      Q: @matoszz

    * N: Exoscale
      D: Exoscale is offering Cilium as a CNI option on its managed Kubernetes service named SKS (Scalable Kubernetes Service)
      U: CNI, Networking
      L: https://www.exoscale.com/sks/
      Q: @Antoine

    * N: finleap connect
      D: finleap connect is using Cilium in their production clusters (self-hosted, bare-metal, private cloud)
      U: CNI, NetworkPolicies
      Q: @chue

    * N: Form3
      D: Form3 is using Cilium in their production clusters (self-hosted, bare-metal, private cloud)
      U: Service load-balancing, Encryption, CNI, NetworkPolicies
      Q: @kevholditch-f3, samo-f3, ewilde-form3

    * N: FRSCA - Factory for Repeatable Secure Creation of Artifacts
      D: FRSCA is utilizing tetragon integrated with Tekton to create runtime attestation to attest artifact and builder attributes
      U: Runtime observability
      L: https://github.com/buildsec/frsca
      Q: @Parth Patel

    * N: F5 Inc
      D: F5 helps customers with Cilium VXLAN tunnel integration with BIG-IP
      U: Networking
      L: https://github.com/f5devcentral/f5-ci-docs/blob/master/docs/cilium/cilium-bigip-info.rst
      Q: @vincentmli

    * N: Giant Swarm
      D: Giant Swarm is using Cilium in their Cluster API based managed Kubernetes service (AWS, Azure, GCP, OpenStack, VMware Cloud Director and VMware vSphere) as CNI
      U: Networking
      L: https://www.giantswarm.io/

    * N: GitLab
      D: GitLab is using Cilium to implement network policies inside Auto DevOps deployed clusters for customers using k8s
      U: Network policies
      L: https://docs.gitlab.com/ee/user/clusters/applications.html#install-cilium-using-gitlab-ci
      Q: @ap4y @whaber

    * N: Google
      D: Google is using Cilium in Anthos and Google Kubernetes Engine (GKE) as Dataplane V2
      U: Networking, network policy, and network visibility
      L: https://cloud.google.com/blog/products/containers-kubernetes/bringing-ebpf-and-cilium-to-google-kubernetes-engine

    * N: IKEA IT AB
      D: IKEA IT AB is using Cilium for production and non-production environments (self-hosted, bare-metal, private cloud)
      U: Networking, CiliumclusterWideNetworkPolicy, CiliumNetworkPolicy, kube-proxy replacement, Hubble, Direct routing, egress gateway, hubble-otel, Multi Nic XDP, BGP advertisements, Bandwidth Manager, Service Load Balancing, Cluster Mesh
      L: https://www.ingka.com/

    * N: Immerok
      D: Immerok uses Cilium for cross-cluster communication and network isolation; Immerok Cloud is a serverless platform for the full power of [Apache Flink](https://flink.apache.org) at any scale.
      U: Networking, network policy, observability, cluster mesh, kube-proxy replacement, security, CNI
      L: https://immerok.io
      Q: @austince, @dmvk

    * N: Infomaniak
      D: Infomaniak is using Cilium in their production clusters (self-hosted, bare-metal and openstack)
      U: Networking, CiliumNetworkPolicy, BPF NodePort, Direct routing, kube-proxy replacement
      L: https://www.infomaniak.com/en
      Q: @reneluria

    * N: innoQ Schweiz GmbH
      D: As a consulting company we added Cilium to a couple of our customers infrastructure
      U: Networking, CiliumNetworkPolicy at L7, kube-proxy replacement, encryption
      L: https://www.cloud-migration.ch/
      Q: @fakod 
      
     * N: Isovalent
       D: Cilium is the platform that powers Isovalent’s enterprise networking, observability, and security solutions
       U: Networking, network policy, observability, cluster mesh, kube-proxy replacement, security, egress gateway, service load balancing, CNI
       L: https://isovalent.com/product/
       Q: @BillMulligan

    * N: JUMO
      D: JUMO is using Cilium as their CNI plugin for all of their AWS-hosted EKS clusters
      U: Networking, network policy, network visibility, cluster mesh
      Q: @Matthieu ANTOINE, @Carlos Castro, @Joao Coutinho (Slack)

    * N: Kilo
      D: Cilium is a supported CNI for Kilo. When used together, Cilium + Kilo create a full mesh via WireGuard for Kubernetes in edge environments.
      U: CNI, Networking, Hubble, kube-proxy replacement, network policy
      L: https://kilo.squat.ai/
      Q: @squat, @arpagon

    * N: kOps
      D: kOps is using Cilium as one of the supported CNIs
      U: Networking, Hubble, Encryption, kube-proxy replacement
      L: kops.sigs.k8s.io/
      Q: @olemarkus

    * N: Kryptos Logic
      D: Kryptos is a cyber security company that is using Kubernetes on-prem in which Cilium is our CNI of choice.
      U: Networking, Observability, kube-proxy replacement

    * N: kubeasz
      D: kubeasz, a certified kubernetes installer, is using Cilium as a one of the supported CNIs.
      U: Networking, network policy, Hubble for network visibility
      L: https://github.com/easzlab/kubeasz

    * N: Kube-OVN
      D: Kube-OVN uses Cilium to enhance service performance, security and monitoring.
      U: CNI-Chaining, Hubble, kube-proxy replacement
      L: https://github.com/kubeovn/kube-ovn/blob/master/docs/IntegrateCiliumIntoKubeOVN.md
      Q: @oilbeater
      
    * N: Kube-Hetzner
      D: Kube-Hetzner is a open-source Terraform project that uses Cilium as an possible CNI in its cluster deployment on Hetzner Cloud.
      U: Networking, Hubble, kube-proxy replacement
      L: https://github.com/kube-hetzner/terraform-hcloud-kube-hetzner#cni
      Q: @MysticalTech

    * N: Kubermatic
      D: Kubermatic Kubernetes Platform is using Cilium as a one of the supported CNIs.
      U: Networking, network policy, Hubble for network visibility
      L: https://github.com/kubermatic/kubermatic

    * N: KubeSphere - KubeKey
      D: KubeKey is an open-source lightweight tool for deploying Kubernetes clusters and addons efficiently. It uses Cilium as one of the supported CNIs.
      U: Networking, Security, Hubble UI for network visibility
      L: https://github.com/kubesphere/kubekey
      Q: @FeynmanZhou

    * N: K8e - Simple Kubernetes Distribution
      D: Kubernetes Easy (k8e) is a lightweight, Extensible, Enterprise Kubernetes distribution. It uses Cilium as default CNI network.
      U: Networking, network policy, Hubble for network visibility
      L: https://github.com/xiaods/k8e
      Q: @xds2000

    * N: Liquid Reply
      D: Liquid Reply is a professional service provider and utilizes Cilium on suitable projects and implementations.
      U: Networking, network policy, Hubble for network visibility, Security
      L: http://liquidreply.com
      Q: @mkorbi

    * N: Magic Leap
      D: Magic Leap is using Hubble plugged to GKE Dataplane v2 clusters
      U: Hubble
      Q: @romachalm

    * N: Melenion Inc
      D: Melenion is using Cilium as the CNI for its on-premise production clusters
      U: Service Load Balancing, Hubble
      Q: @edude03

    * N: Meltwater
      D: Meltwater is using Cilium in AWS on self-hosted multi-tenant k8s clusters as the CNI plugin
      U: ENI Networking, Encryption, Monitoring via Prometheus metrics & Hubble
      Q: @recollir, @dezmodue
      
    * N: Mobilab
      D: Mobilab uses Cilium as the CNI for its internal cloud
      U: CNI
      L: https://mobilabsolutions.com/2019/01/why-we-switched-to-cilium/

    * N: MyFitnessPal
      D: MyFitnessPal trusts Cilium with high volume user traffic in AWS on self-hosted k8s clusters as the CNI plugin and in GKE with Dataplane V2
      U: Networking (CNI, Maglev, kube-proxy replacement, local redirect policy),  Observability (Network metrics with Hubble, DNS proxy, service maps, policy troubleshooting) and Security (Network Policy)
      L: https://www.myfitnesspal.com

    * N: Mux, Inc.
      D: Mux deploys Cilium on self-hosted k8s clusters (Cluster API) in GCP and AWS to run its video streaming/analytics platforms.
      U: Pod networking (CNI, IPAM, Host-reachable Services), Hubble, Cluster-mesh. TBD: Network Policy, Transparent Encryption (WG), Host Firewall.
      L: https://mux.com
      Q: @dilyevsky

    * N: New York Times (the)
      D: The New York Times is using Cilium on EKS to build multi-region multi-tenant shared clusters
      U: Networking (CNI, EKS IPAM, Maglev, kube-proxy replacement, Direct Routing),  Observability (Network metrics with Hubble, policy troubleshooting) and Security (Network Policy)
      L: https://www.nytimes.com/, https://youtu.be/9FDpMNvPrCw
      Q: @abebars

    * N: Nexxiot
      D: Nexxiot is an IoT SaaS provider using Cilium as the main CNI plugin on AWS EKS clusters
      U: Networking (IPAM, CNI), Security (Network Policies), Visibility (hubble)
      L: https://nexxiot.com

    * N: Nine Internet Solutions AG
      D: Nine uses Cilium on all Nine Kubernetes Engine clusters
      U: CNI, network policy, kube-proxy replacement, host firewall
      L: https://www.nine.ch/en/kubernetes

    * N: Northflank
      D: Northflank is a PaaS and uses Cilium as the main CNI plugin across GCP, Azure, AWS and bare-metal
      U: Networking, network policy, hubble, packet monitoring and network visibility
      L: https://northflank.com
      Q: @NorthflankWill, @Champgoblem

    * N: Overstock Inc.
      D: Overstock is using Cilium as the main CNI plugin on bare-metal clusters (self hosted k8s).
      U: Networking, network policy, hubble, observability

    * N: Palantir Technologies Inc.
      D: Palantir is using Cilium as their main CNI plugin in AWS (self hosted k8s).
      U: ENI networking, L3/L4 policies, FQDN based policy, FQDN filtering
      Q: ungureanuvladvictor
    
    * N: Palark GmbH
      D: Palark uses Cilium for networking in its Kubernetes platform provided to numerous customers as a part of its DevOps as a Service offering.
      U: CNI, Networking, Network policy, Security, Hubble UI
      L: https://blog.palark.com/why-cilium-for-kubernetes-networking/
      Q: @shurup

    * N: Plaid Inc
      D: Plaid is using Cilium as their CNI plugin in self-hosted Kubernetes on AWS.
      U: CNI, network policies
      L: [https://plaid.com](https://plaid.com/contact/)
      Q: @diversario @jandersen-plaid

    * N: PlanetScale
      D: PlanetScale is using Cilium as the CNI for its serverless database platform.
      U: Networking (CNI, IPAM, kube-proxy replacement, native routing), Network Security, Cluster Mesh, Load Balancing
      L: https://planetscale.com/
      Q: @dctrwatson

    * N: Polar Signals
      D: Polar Signals uses Cilium as the CNI on its GKE dataplane v2 based clusters.
      U: Networking
      L: https://polarsignals.com
      Q: @polarsignals @brancz

    * N: Polverio
      D: Polverio KubeLift is a single-node Kubernetes distribution optimized for Azure, using Cilium as the CNI.
      U: CNI, IPAM
      L: https://polverio.com
      Q: @polverio @stuartpreston

    * N: Poseidon Laboratories
      D: Poseidon's Typhoon Kubernetes distro uses Cilium as the default CNI and its used internally
      U: Networking, policies, service load balancing
      L: https://github.com/poseidon/typhoon/
      Q: @dghubble @typhoon8s

    * N: PostFinance AG
      D: PostFinance is using Cilium as their CNI for all mission critical, on premise k8s clusters
      U: Networking, network policies, kube-proxy replacement
      L: https://github.com/postfinance

    * N: Proton AG
      D: Proton is using Cilium as their CNI for all their Kubernetes clusters
      U: Networking, network policies, host firewall, kube-proxy replacement, Hubble
      L: https://proton.me/
      Q: @j4m3s @MrFreezeex

    * N: Radio France
      D: Radio France is using Cilium in their production clusters (self-hosted k8s with kops on AWS)
      U: Mainly Service load-balancing
      Q: @francoisj

    * N: Rancher Labs, now part of SUSE
      D: Rancher Labs certified Kubernetes distribution RKE2 can be deployed with Cilium.
      U: Networking and network policy
      L: https://github.com/rancher/rke and https://github.com/rancher/rke2

    * N: Rapyuta Robotics.
      D: Rapyuta is using cilium as their main CNI plugin. (self hosted k8s)
      U: CiliumNetworkPolicy, Hubble, Service Load Balancing.
      Q: @Gowtham
      
    * N: Rafay Systems
      D: Rafay's Kubernetes Operations Platform uses Cilium for centralized network visibility and network policy enforcement
      U: NetworkPolicy, Visibility via Prometheus metrics & Hubble
      L: https://rafay.co/platform/network-policy-manager/
      Q: @cloudnativeboy @mohanatreya

    * N: Robinhood Markets
      D: Robinhood uses Cilium for Kubernetes overlay networking in an environment where we run tests for backend services
      U: CNI, Overlay networking
      Q: @Madhu CS

    * N: SAP
      D: SAP uses Cilium for multiple internal scenarios. For examples for self-hosted Kubernetes scenarios on AWS with SAP Concur and for managed Kubernetes clusters provided with Gardener Project across AWS, Azure, GCP, and OpenStack.
      U: CNI , Overlay Network, Network Policies
      L: https://www.concur.com, https://gardener.cloud/, https://github.com/gardener/gardener-extension-networking-cilium
      Q: @dragan (SAP Concur), @docktofuture & @ScheererJ (Gardener)

    * N: Sapian
      D: Sapian uses Cilium as the default CNI in our product DialBox Cloud; DialBox cloud is an Edge Kubernetes cluster using [kilo](https://github.com/squat/kilo) for WireGuard mesh connectivity inter-nodes. Therefore, Cilium is crucial for low latency in real-time communications environments.
      U: CNI, Network Policies, Hubble, kube-proxy replacement
      L: https://sapian.com.co, https://arpagon.co/blog/k8s-edge
      Q: @arpagon

    * N: Seznam.cz
      D: Seznam.cz uses Cilium in multiple scenarios in on-prem DCs. At first as L4LB which loadbalances external traffic into k8s+openstack clusters then as CNI in multiple k8s and openstack clusters which are all connected in a clustermesh to enforce NetworkPolicies across pods/VMs.
      U: L4LB, L3/4 CNPs+CCNPs, KPR, Hubble, HostPolicy, Direct-routing, IPv4+IPv6, ClusterMesh
      Q: @oblazek

    * N: Simple
      D: Simple uses cilium as default CNI in Kubernetes clusters (AWS EKS) for both development and production environments.
      U: CNI, Network Policies, Hubble
      L: https://simple.life
      Q: @sergeyshevch

    * N: Scaleway
      D: Scaleway uses Cilium as the default CNI for Kubernetes Kapsule
      U: Networking, NetworkPolicy, Services
      L: @jtherin @remyleone
      
    * N: Schuberg Philis
      D: Schuberg Philis uses Cilium as CNI for mission critical kubernetes clusters we run for our customers. 
      U: CNI (instead of amazon-vpc-cni-k8s), DefaultDeny(Zero Trust), Hubble, CiliumNetworkPolicy, CiliumClusterwideNetworkPolicy, EKS
      L: https://schubergphilis.com/en
      Q: @stimmerman @shoekstra @mbaumann
      
    * N: SIGHUP
      D: SIGHUP integrated Cilium as a supported CNI for KFD (Kubernetes Fury Distribution), our enterprise-grade OSS reference architecture 
      U: Available supported CNI
      L: https://sighup.io, https://github.com/sighupio/fury-kubernetes-networking
      Q: @jnardiello @nutellino

    * N: SmileDirectClub
      D: SmileDirectClub is using Cilium in manufacturing clusters (self-hosted on vSphere and AWS EC2)
      U: CNI
      Q: @joey, @onur.gokkocabas

    * N: Snapp
      D: Snapp is using Cilium in production for its on premise openshift clusters
      U: CNI, Network Policies, Hubble
      Q: @m-yosefpor

    * N: Solo.io
      D: Cilium is part of Gloo Application Networking platform, with a “batteries included but swappable” manner
      U: CNI, Network Policies
      Q: @linsun
      
    * N: S&P Global
      D: S&P Global uses Cilium as their multi-cloud CNI
      U: CNI
      L: https://www.youtube.com/watch?v=6CZ_SSTqb4g

    * N: Sphere Knowledge
      D: Sphere Knowledge is using Cilium in AWS (self-hosted k8s & EKS)
      U: ENI Networking, Network policies, Service load-balancing, Hubble
      Q: @mvisonneau
      
    * N: Spherity 
      D: Spherity  is using Cilium on AWS EKS 
      U: CNI/ENI Networking, Network policies, Hubble
      Q: @solidnerd

    * N: Sportradar
      D: Sportradar is using Cilium as their main CNI plugin in AWS (using kops)
      U: L3/L4 policies, Hubble, BPF NodePort, CiliumClusterwideNetworkPolicy
      Q: @Eric Bailey, @Ole Markus

    * N: Sproutfi
      D: Sproutfi uses Cilium as the CNI on its GKE based clusters
      U: Service Load Balancing, Hubble, Datadog Integration for Prometheus metrics
      Q: @edude03

    * N: SuperOrbital
      D: As a Kubernetes-focused consulting firm, we have implemented Cilium on customer engagements
      U: CNI, CiliumNetworkPolicy at L7, Hubble
      L: https://superorbital.io/
      Q: @jmcshane

    * N: Talos
      D: Cilium is one of the supported CNI's in Talos
      U: Networking, NetworkPolicy, Hubble, BPF NodePort
      L: https://github.com/talos-systems/talos
      Q: @frezbo, @smira, @Ulexus

    * N: Tencent Cloud
      D: Tencent Cloud container team designed the TKE hybrid cloud container network solution with Cilium as the cluster network base
      U: Networking, CNI
      L: https://segmentfault.com/a/1190000040298428/en

    * N: teuto.net Netzdienste GmbH
      D: teuto.net is using cilium for their managed k8s service, t8s
      U: CNI, CiliumNetworkPolicy, Hubble, Encryption, ...
      L: https://teuto.net/managed-kubernetes
      Q: @cwrau

    * N: T-Systems International
      D: TSI uses Cilium for it's Open Sovereign Cloud product, including as a CNI for Gardener-based Kubernetes clusters and bare-metal infrastructure managed by OnMetal.
      U: CNI, overlay network, NetworkPolicies
      Q: @ManuStoessel

    * N: uSwitch
      D: uSwitch is using Cilium in AWS for all their production clusters (self hosted k8s)
      U: ClusterMesh, CNI-Chaining (with amazon-vpc-cni-k8s)
      Q: @jirving

    * N: United Cloud
      D: United Cloud is using Cilium for all non-production and production clusters (on-premises)
      U: CNI, Hubble, CiliumNetworkPolicy, CiliumClusterwideNetworkPolicy, ClusterMesh, Encryption
      L: https://united.cloud
      Q: @boris

    * N: Utmost Software, Inc
      D: Utmost is using Cilium in all tiers of its Kubernetes ecosystem to implement zero trust
      U: CNI, DefaultDeny(Zero Trust), Hubble, CiliumNetworkPolicy, CiliumClusterwideNetworkPolicy
      L: https://blog.utmost.co/zero-trust-security-at-utmost
      Q: @andrewholt

    * N: Trip.com
      D: Trip.com is using Cilium in their production clusters (self-hosted k8s, On-premises and AWS)
      U: ENI Networking, Service load-balancing, Direct routing (via Bird)
      L: https://ctripcloud.github.io/cilium/network/2020/01/19/trip-first-step-towards-cloud-native-networking.html
      Q: @ArthurChiao

    * N: Tailor Brands
      D: Tailor Brands is using Cilium in their production, staging, and development clusters (AWS EKS)
      U: CNI (instead of amazon-vpc-cni-k8s), Hubble, Datadog Integration for Prometheus metrics
      Q: @liorrozen
      
    * N: ungleich
      D: ungleich is using Cilium as part of IPv6-only Kubernetes deployments.
      U: CNI, IPv6 only networking, BGP, eBPF
      Q: @Nico Schottelius, @nico:ungleich.ch (Matrix)

    * N: Wildlife Studios
      D: Wildlife Studios is using Cilium in AWS for all their game production clusters (self hosted k8s)
      U: ClusterMesh, Global Service Load Balancing.
      Q: @Oki @luanguimaraesla

    * N: Yahoo!
      D: Yahoo is using Cilium for L4 North-South Load Balancing for Kubernetes Services
      L: https://www.youtube.com/watch?v=-C86fBMcp5Q
