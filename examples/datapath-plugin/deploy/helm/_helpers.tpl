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
will return `quay.io/cilium/cilium:v1.10.1@abcdefgh`.
Note that you can omit the tag by setting its value to `null` or `""` (in case
your container engine doesn't support specifying both the tag and digest for
instance).
*/}}
{{- define "cilium.image" -}}
{{- $digest := (.useDigest | default false) | ternary (printf "@%s" .digest) "" -}}
{{- $tag := .tag | default "" | eq "" | ternary "" (printf ":%s" .tag) -}}
{{- if .override -}}
{{- printf "%s" .override -}}
{{- else -}}
{{- printf "%s%s%s" .repository $tag $digest -}}
{{- end -}}
{{- end -}}

