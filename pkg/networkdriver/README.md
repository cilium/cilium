## Cilium Network Driver

Cilium Network Driver is a module that allows cilium-agent to expose
unmanaged network devices directly to pods. The Network Driver
registers itself as a DRA plugin and publishes resources to the Kubernetes api,
so pods can claim them as per the [DRA framework](https://kubernetes.io/docs/tasks/configure-pod-container/assign-resources/allocate-devices-dra/)

## Requirements

Kubernetes v1.34+

## Device Managers

A Device Manager implements the `types.DeviceManager` interface.
As of the time of writing, the only device manager with a working implementation
is for legacy SR-IOV VFs. 

## Use cases

Applications that benefit from direct network device access and 
do not require participating in the cilium fabric (ex: separate network plane),
such as:

- dpdk based applications (ex: VNFs)
- low latency applications (ex: HFT)

## Enabling the feature

(Right now it uses a hardcoded configuration. But in the future will look something like this below.)
Deploy a `CiliumNetworkDriverConfig` specifying the managers to be enabled:

```
---
apiVersion: cilium.io/v1
kind: CiliumNetworkDriverConfig
metadata:
  name: cilium-network-driver-config
spec:
  selectors:
    labels: 
       - cilium.io/network-driver
  driverName: "sriov.cilium.k8s.io"
  deviceManagerConfigs:
      sriov:
        enabled: true
        ifaces:
          - ifName: enp2s0f0np0
            vfCount: 6
          - ifName: enp2s0f1np1
            vfCount: 6
```

In order to publish ResourceSlices, the pools need to be specified along with a filter to match:
```
---
apiVersion: cilium.io/v1
kind: CiliumNetworkDriverConfig
metadata:
  name: cilium-network-driver-config
spec:
  selectors:
    labels: 
       - cilium.io/network-driver
  driverName: "sriov.cilium.k8s.io"
  pools:
    - name: a-side
      filter:
        pfNames:
          - enp2s0f0np0
    - name: b-side
      filter:
        pfNames:
          - enp2s0f1np1
  deviceManagerConfigs:
      sriov:
        enabled: true
        ifaces:
          - ifName: enp2s0f0np0
            vfCount: 6
          - ifName: enp2s0f1np1
            vfCount: 6
```

## References

## Feature status

Very experimental. Might not work flawlessly all the time.