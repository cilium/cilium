{{- define "clustermesh-config-generate-etcd-cfg" }}
{{- $cluster := index . 0 -}}
{{- $domain := index . 1 -}}

endpoints:
{{- if $cluster.ips }}
- https://{{ $cluster.name }}.{{ $domain }}:{{ $cluster.port }}
{{ else }}
- https://{{ $cluster.address | required "missing clustermesh.apiserver.config.clusters.address" }}:{{ $cluster.port }}
{{- end }}
{{- if $cluster.providedTls }}
trusted-ca-file: {{ $cluster.providedTls.caFile }}
cert-file: {{ $cluster.providedTls.certFile }}
key-file: {{ $cluster.providedTls.keyFile }}
{{- else }}
trusted-ca-file: /var/lib/cilium/clustermesh/{{ $cluster.name }}.etcd-client-ca.crt
cert-file: /var/lib/cilium/clustermesh/{{ $cluster.name }}.etcd-client.crt
key-file: /var/lib/cilium/clustermesh/{{ $cluster.name }}.etcd-client.key
{{- end }}
{{- end }}
