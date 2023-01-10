Restart unmanaged Pods
======================

If you did not create a cluster with the nodes tainted with the taint
``node.cilium.io/agent-not-ready``, then unmanaged pods need to be restarted
manually. Restart all already running pods which are not running in
host-networking mode to ensure that Cilium starts managing them. This is
required to ensure that all pods which have been running before Cilium was
deployed have network connectivity provided by Cilium and NetworkPolicy applies
to them:

.. code-block:: shell-session

    $ kubectl get pods --all-namespaces -o custom-columns=NAMESPACE:.metadata.namespace,NAME:.metadata.name,HOSTNETWORK:.spec.hostNetwork --no-headers=true | grep '<none>' | awk '{print "-n "$1" "$2}' | xargs -L 1 -r kubectl delete pod
    pod "event-exporter-v0.2.3-f9c896d75-cbvcz" deleted
    pod "fluentd-gcp-scaler-69d79984cb-nfwwk" deleted
    pod "heapster-v1.6.0-beta.1-56d5d5d87f-qw8pv" deleted
    pod "kube-dns-5f8689dbc9-2nzft" deleted
    pod "kube-dns-5f8689dbc9-j7x5f" deleted
    pod "kube-dns-autoscaler-76fcd5f658-22r72" deleted
    pod "kube-state-metrics-7d9774bbd5-n6m5k" deleted
    pod "l7-default-backend-6f8697844f-d2rq2" deleted
    pod "metrics-server-v0.3.1-54699c9cc8-7l5w2" deleted

.. note::

    This may error out on macOS due to ``-r`` being unsupported by
    ``xargs``. In this case you can safely run this command without ``-r``
    with the symptom that this will hang if there are no pods to
    restart. You can stop this with ``ctrl-c``.
