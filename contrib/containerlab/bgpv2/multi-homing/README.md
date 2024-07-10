Multi-homing BGP
================

Multi-homing BGP means Cilium node is peering with two upstream routers over different links.

Common design requirements

- Node is connected to two different top-of-rack switches for redundancy.
- Separation of east-west and north-south traffic via different links on the node. This may require different advertisements to each peer.

BGP Resources
-------------

**BGP instance configuration**

In the below example, we define two eBGP peers - fd00:10:0:1::1 and fd00:11:0:1::1, both of which have identical peering configuration defined in
CiliumBGPPeerConfig resource with name `cilium-peer`.

```yaml
  bgpInstances:
  - name: "65001"
    localASN: 65001
    peers:
    - name: "65000"
      peerASN: 65000
      peerAddress: fd00:10::1
      peerConfigRef:
        name: "cilium-peer"
    - name: "65011"
      peerASN: 65011
      peerAddress: fd00:11::1
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

Snippet of 'PodCIDR' advertisement is defined below. BGP control plane will advertise pod cidr prefix with BGP community attribute of 'no-export'.

```yaml
    - advertisementType: "PodCIDR"
      attributes:
        communities:
          wellKnown: [ "no-export" ]
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
root@bgpv2-cplane-dev-multi-homing-worker:/home/cilium# cilium bgp peers
Local AS   Peer AS   Peer Address     Session       Uptime   Family         Received   Advertised
65001      65000     fd00:10::1:179   established   4m45s    ipv4/unicast   0          2
                                                             ipv6/unicast   0          2
65001      65011     fd00:11::1:179   established   4m47s    ipv4/unicast   0          2
                                                             ipv6/unicast   0          2

```

**BGP Routes**

PodCIDR is 10.1.1.0 on this node, which is advertised with communities attribute 'no-export'.

```
root@bgpv2-cplane-dev-multi-homing-worker:/home/cilium# cilium bgp routes advertised ipv4 unicast
VRouter   Peer         Prefix        NextHop          Age     Attrs
65001     fd00:10::1   10.1.1.0/24   fd00:10:0:2::2   5m35s   [{Origin: i} {AsPath: 65001} {Communities: no-export} {MpReach(ipv4-unicast): {Nexthop: fd00:10:0:2::2, NLRIs: [10.1.1.0/24]}}]
65001     fd00:11::1   10.1.1.0/24   fd00:11:0:2::2   5m35s   [{Origin: i} {AsPath: 65001} {Communities: no-export} {MpReach(ipv4-unicast): {Nexthop: fd00:11:0:2::2, NLRIs: [10.1.1.0/24]}}]
```

On peering routers we can see 10.1.1.0/24 prefix with appropriate route attributes and configured router ID.

**FRR Router0**

```
 docker exec -it clab-bgpv2-cplane-dev-multi-homing-router0 vtysh -c 'sh bgp ipv4 10.1.1.0'
BGP routing table entry for 10.1.1.0/24, version 2
Paths: (1 available, best #1, table default, not advertised to EBGP peer)
  Not advertised to any peer
  65001
    fd00:10:0:2::2 from fd00:10:0:2::2 (5.6.7.8)               <<<<<<<<< Router ID
      Origin IGP, valid, external, best (First path received)
      Community: no-export                                     <<<<<<<<< Community
      Last update: Fri Jun 28 15:30:33 2024
```

**FRR Router1**

```
docker exec -it clab-bgpv2-cplane-dev-multi-homing-router1 vtysh -c 'sh bgp ipv4 10.1.1.0'
BGP routing table entry for 10.1.1.0/24, version 1
Paths: (1 available, best #1, table default, not advertised to EBGP peer)
  Not advertised to any peer
  65001
    fd00:11:0:2::2 from fd00:11:0:2::2 (5.6.7.8)
      Origin IGP, valid, external, best (First path received)
      Community: no-export
      Last update: Fri Jun 28 15:30:31 2024
```
