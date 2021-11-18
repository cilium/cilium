{{- define "clustermesh-config-generate-etcd-cfg" }}
{{- $cluster := index . 0 -}}
{{- $domain := index . 1 -}}

endpoints:
{{- if $cluster.ips }}
- https://{{ $cluster.name }}.{{ $domain }}:{{ $cluster.port }}
{{ else }}
- https://{{ $cluster.address | required "missing clustermesh.apiserver.config.clusters.address" }}:{{ $cluster.port }}
{{- end }}
trusted-ca-file: /var/lib/cilium/clustermesh/{{ $cluster.name }}.etcd-client-ca.crt
key-file: /var/lib/cilium/clustermesh/{{ $cluster.name }}.etcd-client.key
cert-file: /var/lib/cilium/clustermesh/{{ $cluster.name }}.etcd-client.crt
{{- end }}
