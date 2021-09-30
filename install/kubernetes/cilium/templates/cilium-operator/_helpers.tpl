{{- define "cilium.operator.cloud" -}}
{{- $cloud := "generic" -}}
{{- if .Values.eni.enabled -}}
  {{- $cloud = "aws" -}}
{{- else if .Values.azure.enabled -}}
  {{- $cloud = "azure" -}}
{{- else if .Values.alibabacloud.enabled -}}
  {{- $cloud = "alibabacloud" -}}
{{- end -}}
{{- $cloud -}}
{{- end -}}

{{/*
Return cilium operator image
*/}}
{{- define "cilium.operator.image" -}}
{{- $cloud := include "cilium.operator.cloud" . }}
{{- $digest := (.Values.operator.image.useDigest | default false) | ternary (printf "@%s" .Values.operator.image.digest) "" -}}
{{- if not .Values.operator.image.tag }}
  {{ fail "operator.image.tag needs to be set" }}
{{- end }}
{{- printf "%s-%s%s:%s%s" .Values.operator.image.repository $cloud .Values.operator.image.suffix .Values.operator.image.tag $digest -}}
{{- end -}}
