{{/*
Generate TLS certificates for ClusterMesh.

Note: Always use this template as follows:

    {{- $_ := include "clustermesh-apiserver-generate-certs.helm.setup-ca" . -}}

The assignment to `$_` is required because we store the generated CI in a global `cmca` variable.
Please, don't try to "simplify" this, as without this trick, every generated
certificate would be signed by a different CA.
*/}}
{{- define "clustermesh-apiserver-generate-certs.helm.setup-ca" }}
  {{- if not .cmca }}
    {{- $ca := "" -}}
    {{- $crt := .Values.clustermesh.apiserver.tls.ca.cert | default .Values.tls.ca.cert -}}
    {{- $key := .Values.clustermesh.apiserver.tls.ca.key | default .Values.tls.ca.key -}}
    {{- if and $crt $key }}
      {{- $ca = buildCustomCert $crt $key -}}
    {{- else }}
      {{- with lookup "v1" "Secret" .Release.Namespace "clustermesh-apiserver-ca-cert" }}
        {{- $crt := index .data "ca.crt" }}
        {{- $key := index .data "ca.key" }}
        {{- $ca = buildCustomCert $crt $key -}}
      {{- else }}
        {{- $_ := include "cilium.ca.setup" . -}}
        {{- with lookup "v1" "Secret" .Release.Namespace .commonCASecretName }}
          {{- $crt := index .data "ca.crt" }}
          {{- $key := index .data "ca.key" }}
          {{- $ca = buildCustomCert $crt $key -}}
        {{- else }}
          {{- $ca = .commonCA -}}
        {{- end }}
      {{- end }}
    {{- end }}
    {{- $_ := set . "cmca" $ca -}}
  {{- end }}
{{- end }}
