{{- define "clustermesh-apiserver-generate-certs.admin-common-name" -}}
admin-{{ .Values.cluster.name }}
{{- end -}}

{{- define "clustermesh-apiserver-generate-certs.local-common-name" -}}
local-{{ .Values.cluster.name }}
{{- end -}}

{{- define "clustermesh-apiserver-generate-certs.remote-common-name" -}}
{{- if eq .Values.clustermesh.apiserver.tls.authMode "cluster" -}}
remote-{{ .Values.cluster.name }}
{{- else -}}
remote
{{- end -}}
{{- end -}}

{{- define "clustermesh-apiserver-generate-certs.server-common-name" -}}
{{- (printf "clustermesh-apiserver.%s.svc" (include "cilium.namespace" .)) -}}
{{- end -}}

{{- define "clustermesh-apiserver-generate-certs.server-dns-names" -}}
{{- $default := (list (include "clustermesh-apiserver-generate-certs.server-common-name" .) "*.mesh.cilium.io") -}}
{{- $deprecated := dig "server" "extraDnsNames" (list) .Values.clustermesh.apiserver.tls -}}
{{- $extra := .Values.clustermesh.apiserver.tls.auto.server.extraDnsNames | default $deprecated -}}
{{- concat $default $extra | toYaml -}}
{{- end -}}

{{- define "clustermesh-apiserver-generate-certs.server-ip-addresses" -}}
{{- $deprecated := dig "server" "extraIpAddresses" (list) .Values.clustermesh.apiserver.tls -}}
{{- $extra := .Values.clustermesh.apiserver.tls.auto.server.extraIpAddresses | default $deprecated -}}
{{- concat (list "127.0.0.1" "::1") $extra | toYaml -}}
{{- end -}}
