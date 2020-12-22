Who is using Cilium?
====================

Sharing experiences and learning from other users is essential. We are
frequently asked who is using a particular feature of Cilium to get in
contact with other users to share experiences and best-practices. While the
[Cilium Slack community](https://cilium.herokuapp.com/) allows users to
get in touch, it can be challenging to find users of a particular feature
quickly.

The following is a directory of users to help identify users of individual
features. The users themselves directly maintain the list.

Adding yourself as a user
-------------------------

If you are using Cilium, please consider adding yourself as a user with a quick
description of your use case by opening a pull request to this file and adding
a section describing your usage of Cilium. If you are open to others contacting
you about your use of Cilium on Slack, add your Slack nick as well.

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

    * N: Canonical
      D: Canonical's Kubernetes distribution microk8s uses Cilium as CNI plugin
      U: Networking, NetworkPolicy, and Kubernetes services
      L: https://microk8s.io/

    * N: CENGN - Centre of Excellence in Next Generation Networks
      D: CENGN is using Cilium in multiple clusters including production and development clusters (self-hosted k8s, On-premises)
      U: L3/L4/L7 network policies, Monitoring via Prometheus metrics & Hubble
      L: https://www.youtube.com/watch?v=yXm7yZE2rk4
      Q: @rmaika @mohahmed13

    * N: Datadog
      D: Datadog is using Cilium in AWS (self-hosted k8s)
      U: ENI Networking, Service load-balancing, Encryption
      Q: @lbernail, @roboll

    * N: DigitalOcean
      D: DigitalOcean is using Cilium as the CNI for Digital Ocean's managed Kubernetes Services (DOKS)
      U: Networking and network policy
      L: https://github.com/digitalocean/DOKS

    * N: finleap connect
      D: finleap connect is using Cilium in their production clusters (self-hosted, bare-metal, private cloud)
      U: CNI, NetworkPolicies
      Q: @chue

    * N: GitLab
      D: GitLab is using Cilium to implement network policies inside Auto DevOps deployed clusters for customers using k8s
      U: Network policies
      L: https://docs.gitlab.com/ee/user/clusters/applications.html#install-cilium-using-gitlab-ci
      Q: @ap4y @whaber

    * N: Google
      D: Google is using Cilium in Anthos and Google Kubernetes Engine (GKE) as Dataplane V2
      U: Networking, network policy, and network visibility
      L: https://cloud.google.com/blog/products/containers-kubernetes/bringing-ebpf-and-cilium-to-google-kubernetes-engine
     
    * N: Palantir Technologies Inc.
      D: Palantir is using Cilium as their main CNI plugin in AWS (self hosted k8s).
      U: ENI networking, L3/L4 policies, FQDN based policy, FQDN filtering
      Q: ungureanuvladvictor
      
    * N: Radio France
      D: Radio France is using Cilium in their production clusters (self-hosted k8s with kops on AWS)
      U: Mainly Service load-balancing
      Q: @francoisj

    * N: Rapyuta Robotics.
      D: Rapyuta is using cilium as their main CNI plugin. (self hosted k8s)
      U: CiliumNetworkPolicy, Hubble, Service Load Balancing.
      Q: @Gowtham

    * N: SAP Concur
      D: SAP Concur is using Cilium in production clusters (self-hosted k8s on AWS)
      U: CNI
      Q: @dale

    * N: SmileDirectClub
      D: SmileDirectClub is using Cilium in manufacturing clusters (self-hosted on vSphere and AWS EC2)
      U: CNI
      Q: @joey, @onur.gokkocabas

    * N: Sphere Knowledge
      D: Sphere Knowledge is using Cilium in AWS (self-hosted k8s & EKS)
      U: ENI Networking, Network policies, Service load-balancing, Hubble
      Q: @mvisonneau

    * N: Sportradar
      D: Sportradar is using Cilium as their main CNI plugin in AWS (using kops)
      U: L3/L4 policies, Hubble, BPF NodePort, CiliumClusterwideNetworkPolicy
      Q: @Eric Bailey, @Ole Markus

    * N: uSwitch
      D: uSwitch is using Cilium in AWS for all their production clusters (self hosted k8s)
      U: ClusterMesh, CNI-Chaining (with amazon-vpc-cni-k8s)
      Q: @jirving

    * N: Trip.com
      D: Trip.com is using Cilium in their production clusters (self-hosted k8s, On-premises and AWS)
      U: ENI Networking, Service load-balancing, Direct routing (via Bird)
      L: https://ctripcloud.github.io/cilium/network/2020/01/19/trip-first-step-towards-cloud-native-networking.html
      Q: @ArthurChiao

    * N: Wildlife Studios
      D: Wildlife Studios is using Cilium in AWS for all their game production clusters (self hosted k8s)
      U: ClusterMesh, Global Service Load Balancing.
      Q: @Oki @luanguimaraesla
