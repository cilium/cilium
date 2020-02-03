Restart remaining pods
======================

Once Cilium is up and running, pods in the ``kube-system`` namespace need to be
restarted to ensure that they can be managed by Cilium.

If the  flag ``--set global.restartPods=true`` was provided to the ``helm``
command during the deployment step, nothing should be required. Otherwise, they
need to be restarted manually:

::

    $ kubectl delete pods -n kube-system $(kubectl get pods -n kube-system -o custom-columns=NAME:.metadata.name,HOSTNETWORK:.spec.hostNetwork --no-headers=true | grep '<none>' | awk '{ print $1 }')
    pod "event-exporter-v0.2.3-f9c896d75-cbvcz" deleted
    pod "fluentd-gcp-scaler-69d79984cb-nfwwk" deleted
    pod "heapster-v1.6.0-beta.1-56d5d5d87f-qw8pv" deleted
    pod "kube-dns-5f8689dbc9-2nzft" deleted
    pod "kube-dns-5f8689dbc9-j7x5f" deleted
    pod "kube-dns-autoscaler-76fcd5f658-22r72" deleted
    pod "kube-state-metrics-7d9774bbd5-n6m5k" deleted
    pod "l7-default-backend-6f8697844f-d2rq2" deleted
    pod "metrics-server-v0.3.1-54699c9cc8-7l5w2" deleted
