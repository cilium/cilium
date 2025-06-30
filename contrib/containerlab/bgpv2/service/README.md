Service Announcements
=====================

Cilium BGP control plane can advertise virtual IPs ( VIPs ) of services. These are /32 or /128 exact match routes of cluster IP, external IP or load-balancer ingress IP.

This lab is split into three parts

- BGP peering and advertisement ( `make apply-bgp` )
- Cluster IP and external IP advertisement ( `make apply-service` )
- Load balancer IP advertisement ( `make apply-lb` )

BGP Resources
-------------

Omitting instance and peering resources, those are similar to other labs.

**BGP Advertisements**

In below example, there are three advertisements. One Pod CIDR and two service advertisements.

- Pod CIDR : This will allow us to advertise node Pod CIDR with BGP community attribute of '65000:99'.
- Service ( match label : "bgp=blue" ) : The advertisement will have BGP community attribute of '65000:100'.
- Service ( match label : "bgp=red" ) : The advertisement will have BGP community attribute of '65000:200'.

In 'Service' advertisement type, we have to define service.addresses list, which can be [ ClusterIP, externalIP or LoadBalancerIP ].

```yaml
  advertisements:
    - advertisementType: "PodCIDR"
      attributes:
        communities:
          standard: [ "65000:99" ]
    - advertisementType: "Service"
      service:
        addresses:
          - ClusterIP
          - ExternalIP
          - LoadBalancerIP
      selector:
        matchExpressions:
          - { key: bgp, operator: In, values: [ blue ] }
      attributes:
        communities:
          standard: [ "65000:100" ]
    - advertisementType: "Service"
      service:
        addresses:
          - ClusterIP
          - ExternalIP
          - LoadBalancerIP
      selector:
        matchExpressions:
          - { key: bgp, operator: In, values: [ red ] }
      attributes:
        communities:
          standard: [ "65000:200" ]

```

Verification
------------

### Services

```
NAMESPACE↑          NAME                 TYPE             CLUSTER-IP          EXTERNAL-IP            PORTS             AGE 
tenant-blue         service-blue         NodePort         10.2.51.216         192.168.100.10         1234►31394        66s 
tenant-red          service-red          NodePort         10.2.13.151         192.168.200.10         1236►31012        65s 
```

Below is the routing table of connected router. Let's go over the routes

- 10.1.0.0/24 and 10.1.1.0/24 are pod CIDR routes. Each is coming from respective cilium node ( control-plane, worker).
- 10.2.51.216/32 is cluster IP of blue service. We define `internalTrafficPolicy=Local` for it, so we receive this route only from node which has the backend for this service.
- 10.2.13.151/32 is cluster IP of red service. Since internal traffic policy is not set ( default iTP=Cluster ), we receive this route from both cilium nodes.
- 192.168.100.10/32 and 192.168.200.10/32 are external IPs, they follow similar pattern ( relying on `externalTrafficPolicy` configuration).

```
docker exec -it clab-bgpv2-cplane-dev-service-router0 vtysh -c 'sh bgp ipv4'
BGP table version is 8, local router ID is 10.0.0.1, vrf id 0
Default local pref 100, local AS 65000
Status codes:  s suppressed, d damped, h history, * valid, > best, = multipath,
               i internal, r RIB-failure, S Stale, R Removed
Nexthop codes: @NNN nexthop's vrf id, < announce-nh-self
Origin codes:  i - IGP, e - EGP, ? - incomplete
RPKI validation codes: V valid, I invalid, N Not found

   Network          Next Hop            Metric LocPrf Weight Path
*> 10.1.0.0/24      fd00:10:0:1::2                         0 65001 i
*> 10.1.1.0/24      fd00:10:0:2::2                         0 65001 i
*= 10.2.13.151/32   fd00:10:0:2::2                         0 65001 i
*>                  fd00:10:0:1::2                         0 65001 i
*> 10.2.51.216/32   fd00:10:0:2::2                         0 65001 i
*> 192.168.100.10/32
                    fd00:10:0:2::2                         0 65001 i
*= 192.168.200.10/32
                    fd00:10:0:2::2                         0 65001 i
*>                  fd00:10:0:1::2                         0 65001 i

Displayed  6 routes and 8 total paths
```

Following output shows BGP attributes for various advertisement types.

**PodCIDR**

BGP community attribute for pod cidr prefixes is 65000:99.

```
 docker exec -it clab-bgpv2-cplane-dev-service-router0 vtysh -c 'sh bgp ipv4 10.1.1.0'
BGP routing table entry for 10.1.1.0/24, version 4
Paths: (1 available, best #1, table default)
  Advertised to non peer-group peers:
  fd00:10:0:1::2 fd00:10:0:2::2
  65001
    fd00:10:0:2::2 from fd00:10:0:2::2 (10.0.2.2)
      Origin IGP, valid, external, best (First path received)
      Community: 65000:99
      Last update: Thu May 16 18:21:57 2024
```

**Blue Service**

This service is configured with internalTrafficPolicy=Local. We see single route with BGP community set to 65000:100.

```
docker exec -it clab-bgpv2-cplane-dev-service-router0 vtysh -c 'sh bgp ipv4 10.2.51.216/32'
BGP routing table entry for 10.2.51.216/32, version 7
Paths: (1 available, best #1, table default)
  Advertised to non peer-group peers:
  fd00:10:0:1::2 fd00:10:0:2::2
  65001
    fd00:10:0:2::2 from fd00:10:0:2::2 (10.0.2.2)
      Origin IGP, valid, external, best (First path received)
      Community: 65000:100
      Last update: Thu May 16 18:21:57 2024
```

**Red Service**

This service is configured with internalTrafficPolicy=Cluster. We see multipath route with BGP community set to 65000:200 from both peers.

```
docker exec -it clab-bgpv2-cplane-dev-service-router0 vtysh -c 'sh bgp ipv4 10.2.13.151/32 '
BGP routing table entry for 10.2.13.151/32, version 5
Paths: (2 available, best #2, table default)
  Advertised to non peer-group peers:
  fd00:10:0:1::2 fd00:10:0:2::2
  65001
    fd00:10:0:2::2 from fd00:10:0:2::2 (10.0.2.2)
      Origin IGP, valid, external, multipath
      Community: 65000:200
      Last update: Thu May 16 18:21:57 2024
  65001
    fd00:10:0:1::2 from fd00:10:0:1::2 (10.0.1.2)
      Origin IGP, valid, external, multipath, best (Older Path)
      Community: 65000:200
      Last update: Thu May 16 18:21:55 2024
```

### Load Balancer

Load balancer services are configured similarly.

```
NAMESPACE↑         NAME                   TYPE                CLUSTER-IP         EXTERNAL-IP       PORTS             AGE  
tenant-blue        lb-service-blue        LoadBalancer        10.2.165.65        20.0.10.1         1234►32398        2m17s
tenant-red         lb-service-red         LoadBalancer        10.2.97.3          20.1.10.1         1236►30547        2m17s
```

tenant-blue is configured with externalTrafficPolicy=Local, but we do not have any endpoint associated with this service. So we do not see  20.0.10.1/32 route advertised.

```
docker exec -it clab-bgpv2-cplane-dev-service-router0 vtysh -c 'sh bgp ipv4 20.0.10.1/32'
% Network not in table
```

tenant-red is configured with externalTrafficPolicy=Cluster, we see 20.1.10.1/32 prefix being advertised regardless of endpoint state.

```
docker exec -it clab-bgpv2-cplane-dev-service-router0 vtysh -c 'sh bgp ipv4 20.1.10.1/32'
BGP routing table entry for 20.1.10.1/32, version 11
Paths: (2 available, best #1, table default)
  Advertised to non peer-group peers:
  fd00:10:0:1::2 fd00:10:0:2::2
  65001
    fd00:10:0:1::2 from fd00:10:0:1::2 (10.0.1.2)
      Origin IGP, valid, external, multipath, best (Router ID)
      Community: 65000:200
      Last update: Thu May 16 18:37:28 2024
  65001
    fd00:10:0:2::2 from fd00:10:0:2::2 (10.0.2.2)
      Origin IGP, valid, external, multipath
      Community: 65000:200
      Last update: Thu May 16 18:37:28 2024
```
