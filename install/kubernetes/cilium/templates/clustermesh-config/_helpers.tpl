{{- define "clustermesh-config-generate-etcd-cfg" }}
{{- $cluster := index . 0 -}}
{{- $domain := index . 1 -}}
{{- /* The parenthesis around $cluster.tls are required, since it can be null: https://stackoverflow.com/a/68807258 */}}
{{- $prefix := ternary "common-" (printf "%s." $cluster.name) (or (empty ($cluster.tls).cert) (empty ($cluster.tls).key)) -}}

endpoints:
{{- if $cluster.ips }}
- https://{{ $cluster.name }}.{{ $domain }}:{{ $cluster.port }}
{{- else }}
- https://{{ $cluster.address | required "missing clustermesh.apiserver.config.clusters.address" }}:{{ $cluster.port }}
{{- end }}
trusted-ca-file: /var/lib/cilium/clustermesh/{{ $prefix }}etcd-client-ca.crt
key-file: /var/lib/cilium/clustermesh/{{ $prefix }}etcd-client.key
cert-file: /var/lib/cilium/clustermesh/{{ $prefix }}etcd-client.crt
{{- end }}
