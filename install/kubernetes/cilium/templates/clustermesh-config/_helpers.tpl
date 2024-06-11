{{- define "clustermesh-config-generate-etcd-cfg" }}
{{- $cluster := index . 0 -}}
{{- $domain := index . 1 -}}
{{- $override := index . 2 -}}
{{- /* The parenthesis around $cluster.tls are required, since it can be null: https://stackoverflow.com/a/68807258 */}}
{{- $prefix := ternary "common-" (printf "%s." $cluster.name) (or (empty ($cluster.tls).cert) (empty ($cluster.tls).key)) -}}
{{- /* KVStoreMesh is enabled, and we are generating the secret used by Cilium agents. */}}
{{- /* In other words, we want to connect to KVStoreMesh, opposed to the etcd instance */}}
{{- /* in the remote cluster; hence we need to use the dedicated certificate and key.  */}}
{{- if ne $override "" -}}
{{- $prefix = "local-" -}}
{{- end -}}

endpoints:
{{- if ne $override "" }}
- {{ $override }}
{{- else if $cluster.ips }}
- https://{{ $cluster.name }}.{{ $domain }}:{{ $cluster.port }}
{{- else }}
- https://{{ $cluster.address | required "missing clustermesh.apiserver.config.clusters.address" }}:{{ $cluster.port }}
{{- end }}
{{- if or (ne $override "") (not (empty ($cluster.tls).caCert)) }}
{{- /* The custom CA configuration takes effect only if a custom certificate and key are also set, */}}
{{- /* otherwise we may enter this branch, but the prefix is still set to common-.                 */}}
{{- /* Additionally, when KVStoreMesh is enabled, and we are generating the secret for the agents, */}}
{{- /* we want to always use the corresponding CA certificate, that is the one with local- prefix. */}}
trusted-ca-file: /var/lib/cilium/clustermesh/{{ $prefix }}etcd-client-ca.crt
{{- else }}
trusted-ca-file: /var/lib/cilium/clustermesh/common-etcd-client-ca.crt
{{- end }}
key-file: /var/lib/cilium/clustermesh/{{ $prefix }}etcd-client.key
cert-file: /var/lib/cilium/clustermesh/{{ $prefix }}etcd-client.crt
{{- end }}
