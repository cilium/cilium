Cilium Pod IP Pool
==================

Cilium BGP control plane can advertise pod IP pools defined in CiliumPodIPPool. Pod IP Pool allocations are dynamic, and node specific prefix will be announced when prefix is allocated to the node.

CiliumPodIPPool Resources
-------------------------
In this example, pool have larger /16 CIDR block and it will allocate /24 prefix from this block to each node. Similarly, IPv6 CIDR blocks are defined.

Default Pool
```yaml
  ipv4:
    cidrs:
      - 10.100.0.0/16
    maskSize: 24
```

Red Pool
```yaml
  ipv4:
    cidrs:
      - 10.200.0.0/16
    maskSize: 24
```

BGP Resources
-------------

**BGP Instance**

Single BGP peer is defined in the BGP cluster configuration. This will be applied to both Control-Plane and Worker nodes ( matching on node selector label ).

```yaml
  - name: "65001"
    localASN: 65001
    peers:
    - name: "65000"
      peerASN: 65000
      peerAddress: fd00:10::1
      peerConfigRef:
        name: "cilium-peer"
```

**BGP Peer Configuration**

Peer configuration defines IPv4/IPv6 unicast AFI/SAFI. Both address families have advertisements setting with label selector. 

In below example, both v4 and v6 families have advertisement label selector of "advertise=pod-ip-pool". 

```yaml
  families:
    - afi: ipv4
      safi: unicast
      advertisements:
        matchLabels:
          advertise: "pod-ip-pool"
    - afi: ipv6
      safi: unicast
      advertisements:
        matchLabels:
          advertise: "pod-ip-pool"
```

**BGP Advertisement**

BGP Advertisement resource has two different pool settings. One for blue pool and another for red, both are used to advertise prefix from respective
pools but with different BGP attributes.

```yaml
  advertisements:
    - advertisementType: "CiliumPodIPPool"
      selector:
        matchLabels:
          pool: "blue"
      attributes:
        communities:
          standard: [ "65000:100" ]
    - advertisementType: "CiliumPodIPPool"
      selector:
        matchLabels:
          pool: "red"
      attributes:
        communities:
          standard: [ "65000:200" ]
```

Verification
------------

**BGP Advertisement**

```
root@bgpv2-cplane-dev-pod-ip-pool-worker:/home/cilium# cilium bgp routes advertised ipv4 unicast
VRouter   Peer         Prefix          NextHop          Age     Attrs
65001     fd00:10::1   10.100.1.0/24   fd00:10:0:2::2   4m14s   [{Origin: i} {AsPath: 65001} {Communities: 65000:100} {MpReach(ipv4-unicast): {Nexthop: fd00:10:0:2::2, NLRIs: [10.100.1.0/24]}}]
65001     fd00:10::1   10.200.0.0/24   fd00:10:0:2::2   3m57s   [{Origin: i} {AsPath: 65001} {Communities: 65000:200} {MpReach(ipv4-unicast): {Nexthop: fd00:10:0:2::2, NLRIs: [10.200.0.0/24]}}]

root@bgpv2-cplane-dev-pod-ip-pool-worker:/home/cilium# cilium bgp routes advertised ipv6 unicast
VRouter   Peer         Prefix              NextHop          Age     Attrs
65001     fd00:10::1   fd00:100:1:1::/64   fd00:10:0:2::2   4m43s   [{Origin: i} {AsPath: 65001} {Communities: 65000:100} {MpReach(ipv6-unicast): {Nexthop: fd00:10:0:2::2, NLRIs: [fd00:100:1:1::/64]}}]
65001     fd00:10::1   fd00:200:1:2::/64   fd00:10:0:2::2   4m11s   [{Origin: i} {AsPath: 65001} {Communities: 65000:200} {MpReach(ipv6-unicast): {Nexthop: fd00:10:0:2::2, NLRIs: [fd00:200:1:2::/64]}}]
```

**Router0**

```
docker exec -it clab-bgpv2-cplane-dev-pod-ip-pool-router0 vtysh -c 'sh bgp ipv4'
BGP table version is 4, local router ID is 10.0.0.1, vrf id 0
Default local pref 100, local AS 65000
Status codes:  s suppressed, d damped, h history, * valid, > best, = multipath,
               i internal, r RIB-failure, S Stale, R Removed
Nexthop codes: @NNN nexthop's vrf id, < announce-nh-self
Origin codes:  i - IGP, e - EGP, ? - incomplete
RPKI validation codes: V valid, I invalid, N Not found

   Network          Next Hop            Metric LocPrf Weight Path
*> 10.100.0.0/24    fd00:10:0:1::2                         0 65001 i
*> 10.100.1.0/24    fd00:10:0:2::2                         0 65001 i
*> 10.200.0.0/24    fd00:10:0:2::2                         0 65001 i
*> 10.200.1.0/24    fd00:10:0:1::2                         0 65001 i

Displayed  4 routes and 4 total paths

docker exec -it clab-bgpv2-cplane-dev-pod-ip-pool-router0 vtysh -c 'sh bgp ipv4 10.100.0.0'
BGP routing table entry for 10.100.0.0/24, version 1
Paths: (1 available, best #1, table default)
  Advertised to non peer-group peers:
  fd00:10:0:1::2 fd00:10:0:2::2
  65001
    fd00:10:0:1::2 from fd00:10:0:1::2 (10.0.1.2)
      Origin IGP, valid, external, best (First path received)
      Community: 65000:100
      Last update: Fri Jun 28 15:55:08 2024

docker exec -it clab-bgpv2-cplane-dev-pod-ip-pool-router0 vtysh -c 'sh bgp ipv4 10.200.0.0'
BGP routing table entry for 10.200.0.0/24, version 3
Paths: (1 available, best #1, table default)
  Advertised to non peer-group peers:
  fd00:10:0:1::2 fd00:10:0:2::2
  65001
    fd00:10:0:2::2 from fd00:10:0:2::2 (10.0.2.2)
      Origin IGP, valid, external, best (First path received)
      Community: 65000:200
      Last update: Fri Jun 28 15:54:59 2024
```