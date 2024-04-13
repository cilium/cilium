{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "cilium.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Render full image name from given values, e.g:
```
image:
  repository: quay.io/cilium/cilium
  tag: v1.10.1
  useDigest: true
  digest: abcdefgh
```
then `include "cilium.image" .Values.image`
will return `quay.io/cilium/cilium:v1.10.1@abcdefgh`
*/}}
{{- define "cilium.image" -}}
{{- $digest := (.useDigest | default false) | ternary (printf "@%s" .digest) "" -}}
{{- if .override -}}
{{- printf "%s" .override -}}
{{- else -}}
{{- printf "%s:%s%s" .repository .tag $digest -}}
{{- end -}}
{{- end -}}

{{/*
Return user specify priorityClass or default criticalPriorityClass
Usage:
  include "cilium.priorityClass" (list $ <priorityClass> <criticalPriorityClass>)
where:
* `priorityClass`: is user specify priorityClass e.g `.Values.operator.priorityClassName`
* `criticalPriorityClass`: default criticalPriorityClass, e.g `"system-cluster-critical"`
  This value is used when `priorityClass` is `nil` and
  `.Values.enableCriticalPriorityClass=true` and kubernetes supported it.
*/}}
{{- define "cilium.priorityClass" -}}
{{- $root := index . 0 -}}
{{- $priorityClass := index . 1 -}}
{{- $criticalPriorityClass := index . 2 -}}
{{- if $priorityClass }}
  {{- $priorityClass }}
{{- else if and $root.Values.enableCriticalPriorityClass $criticalPriorityClass -}}
  {{- $criticalPriorityClass }}
{{- end -}}
{{- end -}}

{{/*
Generate TLS CA for Cilium
Note: Always use this template as follows:
    {{- $_ := include "cilium.ca.setup" . -}}

The assignment to `$_` is required because we store the generated CI in a global `commonCA`
and `commonCASecretName` variables.

*/}}
{{- define "cilium.ca.setup" }}
  {{- if not .commonCA -}}
    {{- $ca := "" -}}
    {{- $secretName := "cilium-ca" -}}
    {{- $crt := .Values.tls.ca.cert -}}
    {{- $key := .Values.tls.ca.key -}}
    {{- if and $crt $key }}
      {{- $ca = buildCustomCert $crt $key -}}
    {{- else }}
      {{- with lookup "v1" "Secret" .Release.Namespace $secretName }}
        {{- $crt := index .data "ca.crt" }}
        {{- $key := index .data "ca.key" }}
        {{- $ca = buildCustomCert $crt $key -}}
      {{- else }}
        {{- $validity := ( .Values.tls.ca.certValidityDuration | int) -}}
        {{- $ca = genCA "Cilium CA" $validity -}}
      {{- end }}
    {{- end -}}
    {{- $_ := set (set . "commonCA" $ca) "commonCASecretName" $secretName -}}
  {{- end -}}
{{- end -}}

{{/*
Check if duration is non zero value, return duration, empty when zero.
*/}}
{{- define "hasDuration" }}
{{- $now := now }}
{{- if ne $now ($now | dateModify (toString .)) }}
{{- . }}
{{- end }}
{{- end }}

{{/*
Validate duration field, return validated duration, 0s when provided duration is empty.
*/}}
{{- define "validateDuration" }}
{{- if . }}
{{- $_ := now | mustDateModify (toString .) }}
{{- . }}
{{- else -}}
0s
{{- end }}
{{- end }}
