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
