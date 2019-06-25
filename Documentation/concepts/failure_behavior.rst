.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    http://docs.cilium.io

****************
Failure Behavior
****************

If Cilium loses connectivity with the KV-Store, it guarantees that:

* Normal networking operations will continue;

* If policy enforcement is enabled, the existing `endpoints` will still have
  their policy enforced but you will lose the ability to add additional
  containers that belong to security identities which are unknown on the node;

* If services are enabled, you will lose the ability to add additional services
  / loadbalancers;

* When the connectivity is restored to the KV-Store, Cilium can take up to 5
  minutes to re-sync the out-of-sync state with the KV-Store.

Cilium will keep running even if it is out-of-sync with the KV-Store.

If Cilium crashes / or the DaemonSet is accidentally deleted, the following are
guaranteed:

* When running Cilium as a DaemonSet / container, with the specification files
  provided in the documentation :ref:`admin_install_daemonset`, the endpoints /
  containers which are already running will not lose any connectivity, and they
  will keep running with the policy loaded before Cilium stopped unexpectedly.

* When running Cilium in a different way, just make sure the bpf fs is mounted
  :ref:`admin_mount_bpffs`.

