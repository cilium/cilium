{{- define "clustermesh-config-generate-etcd-cfg" }}
{{- $cluster := index . 0 -}}
{{- $domain := index . 1 -}}
{{- $hasCustomCACert := index . 2 -}}
{{- $override := index . 3 -}}
{{- /* The parenthesis around $cluster.tls are required, since it can be null: https://stackoverflow.com/a/68807258 */}}
{{- $prefix := ternary "common-" (printf "%s." $cluster.name) (or (ne $override "") (empty ($cluster.tls).cert) (empty ($cluster.tls).key)) -}}

endpoints:
{{- if ne $override "" }}
- {{ $override }}
{{- else if $cluster.ips }}
- https://{{ $cluster.name }}.{{ $domain }}:{{ $cluster.port }}
{{- else }}
- https://{{ $cluster.address | required "missing clustermesh.apiserver.config.clusters.address" }}:{{ $cluster.port }}
{{- end }}
{{- if $hasCustomCACert }}
{{- /* The custom CA configuration takes effect only if a custom certificate and key are also set */}}
trusted-ca-file: /var/lib/cilium/clustermesh/{{ $prefix }}etcd-client-ca.crt
{{- else }}
trusted-ca-file: /var/lib/cilium/clustermesh/common-etcd-client-ca.crt
{{- end }}
key-file: /var/lib/cilium/clustermesh/{{ $prefix }}etcd-client.key
cert-file: /var/lib/cilium/clustermesh/{{ $prefix }}etcd-client.crt
{{- end }}
