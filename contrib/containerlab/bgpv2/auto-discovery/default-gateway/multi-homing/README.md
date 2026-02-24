Multi-homing BGP with Default Gateway Auto Discovery
====================================================

Multi-homing BGP means Cilium node is peering with two upstream routers over different links.

Common design requirements

- Node is connected to two different top-of-rack switches for redundancy.
- Separation of east-west and north-south traffic via different links on the node. This may require different advertisements to each peer.

BGP Resources
-------------

**BGP instance configuration**

In the below example, we define two eBGP peers without peer address. Peer address will be auto discovered using default gateway
for each address family. It will create bgp session per peer configured so each address family will have one bgp session  , both of which have identical peering configuration defined in
CiliumBGPPeerConfig resource with name `cilium-peer`.

```yaml
  bgpInstances:
  - name: "65001"
    localASN: 65001
    peers:
    - name: "ipv6-65000"
      peerASN: 65000
      autoDiscovery:
        mode: "DefaultGateway"
        defaultGateway:
          addressFamily: ipv6
      peerConfigRef:
        name: "cilium-peer"
```
**BGP peer configuration**
Peer configuration contains various peering settings like transport, authentication and AFI/SAFI configurations.
```yaml
  families:
    - afi: ipv4
      safi: unicast
      advertisements:
        matchLabels:
          advertise: "pod-cidr"
    - afi: ipv6
      safi: unicast
      advertisements:
        matchLabels:
          advertise: "pod-cidr"
```
In the above example, both IPv4 and IPv6 address families are enabled and for each address family we advertise CiliumBGPAdvertisement resource
which matches the label "advertise=pod-cidr".
**BGP advertisement**
Snippet of 'PodCIDR' advertisement is defined below. BGP control plane will advertise pod cidr prefix
```yaml
    - advertisementType: "PodCIDR"
```
**BGP node configuration override**
In below example, router ID is configured manually for each node. Name of the CiliumBGPNodeConfigOverride resource matches the node name on which this 
configuration will be applied.
```yaml
---
apiVersion: cilium.io/v2alpha1
kind: CiliumBGPNodeConfigOverride
metadata:
  name: bgpv2-cplane-dev-multi-homing-control-plane
spec:
  bgpInstances:
    - name: "65001"
      routerID: "1.2.3.4"

---
apiVersion: cilium.io/v2alpha1
kind: CiliumBGPNodeConfigOverride
metadata:
  name: bgpv2-cplane-dev-multi-homing-worker
spec:
  bgpInstances:
    - name: "65001"
      routerID: "5.6.7.8"
```
Verification
------------
**BGP Peering**
```
root@bgpv2-cplane-dev-mh-worker:/home/cilium# cilium bgp peers
Local AS   Peer AS   Peer Address         Session       Uptime   Family         Received   Advertised
65001      65000     fd00:11:0:2::1:179   established   21m55s   ipv4/unicast   2          2    
                                                                 ipv6/unicast   2          2 

```

**BGP Routes**

```
root@bgpv2-cplane-dev-mh-worker:/home/cilium# cilium bgp routes advertised ipv4 unicast
VRouter   Peer             Prefix        NextHop          Age      Attrs
65001     fd00:11:0:2::1   10.1.1.0/24   fd00:11:0:2::2   22m18s   [{Origin: i} {AsPath: 65001} {MpReach(ipv4-unicast): {Nexthop: fd00:11:0:2::2, NLRIs: [10.1.1.0/24]}}] 
```

On peering routers we can see 10.1.1.0/24 prefix with appropriate route attributes and configured router ID.

**FRR Router0**

```
 docker exec -it clab-bgpv2-cplane-dev-mh-router0 vtysh -c 'sh bgp ipv4 10.1.1.0'
% Network not in table
```

**FRR Router1**

```
docker exec -it clab-bgpv2-cplane-dev-mh-router1 vtysh -c 'sh bgp ipv4 10.1.1.0'
BGP routing table entry for 10.1.1.0/24, version 2
Paths: (1 available, best #1, table default)
  Advertised to non peer-group peers:
  fd00:11:0:1::2 fd00:11:0:2::2
  65001
    fd00:11:0:2::2 from fd00:11:0:2::2 (5.6.7.8)               <<<<<<<<< Router ID
      Origin IGP, valid, external, best (First path received)
      Last update: Sat Apr  5 23:37:36 2025
```

Failover
------------

if the default route fails for any reason like interface going down, it will trigger a reconciliation and worker will failover to the other router i.e router0

**BGP Peering**

```
root@bgpv2-cplane-dev-mh-worker:/home/cilium# cilium bgp peers
Local AS   Peer AS   Peer Address         Session       Uptime   Family         Received   Advertised
65001      65000     fd00:10:0:2::1:179   established   42s      ipv4/unicast   2          2    
                                                                 ipv6/unicast   2          2  
```

**BGP Routes**

```
root@bgpv2-cplane-dev-mh-worker:/home/cilium# cilium bgp routes advertised ipv4 unicast
VRouter   Peer             Prefix        NextHop          Age     Attrs
65001     fd00:10:0:2::1   10.1.1.0/24   fd00:10:0:2::2   3m26s   [{Origin: i} {AsPath: 65001} {MpReach(ipv4-unicast): {Nexthop: fd00:10:0:2::2, NLRIs: [10.1.1.0/24]}}] 
```

On one of the peering router we can see 10.1.1.0/24 prefix with appropriate route attributes and configured router ID.

**FRR Router0**

```
 docker exec -it clab-bgpv2-cplane-dev-mh-router0 vtysh -c 'sh bgp ipv4 10.1.1.0'
BGP routing table entry for 10.1.1.0/24, version 2
Paths: (1 available, best #1, table default)
  Advertised to non peer-group peers:
  fd00:10:0:1::2 fd00:10:0:2::2
  65001
    fd00:10:0:2::2 from fd00:10:0:2::2 (5.6.7.8)
      Origin IGP, valid, external, best (First path received)
      Last update: Sun Apr  6 00:27:43 2025
```

**FRR Router1**

```
docker exec -it clab-bgpv2-cplane-dev-mh-router1 vtysh -c 'sh bgp ipv4 10.1.1.0'
% Network not in table
```
