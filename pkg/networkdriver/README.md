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

Deploy a `CiliumNetworkDriverConfig` CRD specifying the managers to be enabled:

```
---
apiVersion: cilium.io/v2alpha1
kind: CiliumNetworkDriverConfig
metadata:
  name: cilium-network-driver-config
spec:
  driverName: "sriov.cilium.k8s.io"
  deviceManagerConfigs:
      dummy:
        enabled: true

```

In order to publish ResourceSlices, the pools need to be specified along with a filter to match devices:
```
---
apiVersion: cilium.io/v2alpha1
kind: CiliumNetworkDriverConfig
metadata:
  name: cilium-network-driver-config
spec:
  driverName: "sriov.cilium.k8s.io"
  pools:
    - name: a-side
      filter:
        ifNames:
          - dummy0
          - dummy1
  deviceManagerConfigs:
      dummy:
        enabled: true
```

## References

## Feature status

Very experimental. Might not work flawlessly all the time.