{{/*
Generate TLS certificates for Hubble Server and Hubble Relay.

Note: Always use this template as follows:

    {{- $_ := include "hubble-generate-certs.helm.setup-ca" . -}}

The assignment to `$_` is required because we store the generated CI in a global `ca` variable.
Please, don't try to "simplify" this, as without this trick, every generated
certificate would be signed by a different CA.
*/}}
{{- define "hubble-generate-certs.helm.setup-ca" }}
  {{- if not .ca }}
    {{- $ca := "" -}}
    {{- $crt := .Values.hubble.tls.ca.cert | default .Values.tls.ca.cert -}}
    {{- $key := .Values.hubble.tls.ca.key | default .Values.tls.ca.key -}}
    {{- if and $crt $key }}
      {{- $ca = buildCustomCert $crt $key -}}
    {{- else }}
      {{- with lookup "v1" "Secret" (include "cilium.namespace" .) "hubble-ca-secret" }}
        {{- $crt := index .data "ca.crt" }}
        {{- $key := index .data "ca.key" }}
        {{- $ca = buildCustomCert $crt $key -}}
      {{- else }}
        {{- $_ := include "cilium.ca.setup" . -}}
        {{- with lookup "v1" "Secret" (include "cilium.namespace" .) .commonCASecretName }}
          {{- $crt := index .data "ca.crt" }}
          {{- $key := index .data "ca.key" }}
          {{- $ca = buildCustomCert $crt $key -}}
        {{- else }}
          {{- $ca = .commonCA -}}
        {{- end }}
      {{- end }}
    {{- end }}
    {{- $_ := set . "ca" $ca -}}
  {{- end }}
{{- end }}
