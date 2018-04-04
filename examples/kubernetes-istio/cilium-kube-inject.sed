# Inject Cilium's /var/run/cilium directory into each Istio sidecar proxy to
# allow Cilium's Envoy filters to communicate with the Cilium agent.
#
# volumeMounts:
# - mountPath: /var/run/cilium
#   name: cilium-unix-sock-dir
#
# volumes:
# - hostPath:
#     path: /var/run/cilium
#   name: cilium-unix-sock-dir
s,^\(.*\)volumeMounts:$,&\n\1- mountPath: /var/run/cilium\n\1  name: cilium-unix-sock-dir,
s,^\(.*\)volumes:$,&\n\1- hostPath:\n\1    path: /var/run/cilium\n\1  name: cilium-unix-sock-dir,
