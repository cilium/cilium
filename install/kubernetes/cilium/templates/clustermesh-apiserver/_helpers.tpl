{{- define "clustermesh-apiserver-generate-certs.admin-common-name" -}}
admin-{{ .Values.cluster.name }}
{{- end -}}
