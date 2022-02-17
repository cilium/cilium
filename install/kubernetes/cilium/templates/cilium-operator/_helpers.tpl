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

{{- define "cilium.operator.imageDigestName" -}}
{{- $imageDigest := (.Values.operator.image.useDigest | default false) | ternary (printf "@%s" .Values.operator.image.genericDigest) "" -}}
{{- if .Values.eni.enabled -}}
  {{- $imageDigest = (.Values.operator.image.useDigest | default false) | ternary (printf "@%s" .Values.operator.image.awsDigest) "" -}}
{{- else if .Values.azure.enabled -}}
  {{- $imageDigest = (.Values.operator.image.useDigest | default false) | ternary (printf "@%s" .Values.operator.image.azureDigest) "" -}}
{{- else if .Values.alibabacloud.enabled -}}
  {{- $imageDigest = (.Values.operator.image.useDigest | default false) | ternary (printf "@%s" .Values.operator.image.alibabacloudDigest) "" -}}
{{- end -}}
{{- $imageDigest -}}
{{- end -}}

{{/*
Return cilium operator image
*/}}
{{- define "cilium.operator.image" -}}
{{- if .Values.operator.image.override -}}
{{- printf "%s" .Values.operator.image.override -}}
{{- else -}}
{{- $cloud := include "cilium.operator.cloud" . }}
{{- $imageDigest := include "cilium.operator.imageDigestName" . }}
{{- printf "%s-%s%s:%s%s" .Values.operator.image.repository $cloud .Values.operator.image.suffix .Values.operator.image.tag $imageDigest -}}
{{- end -}}
{{- end -}}
