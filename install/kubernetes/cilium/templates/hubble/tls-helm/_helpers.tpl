{{/*
Generate TLS certificates for Hubble Server and Hubble Relay.

Note: this line, that is repeated several times below, is a trick to
ensure the CA certs are generated only once:

    {{- $_ := include "hubble-generate-certs.helm.setup-ca" . -}}

Please, don't try to "simplify" them as without this trick, every generated
certificate would be signed by a different CA.
*/}}
{{- define "hubble-generate-certs.helm.setup-ca" }}
  {{- if not .ca }}
    {{- $ca := "" -}}
    {{- if .Values.hubble.tls.ca.cert }}
      {{- $crt := .Values.hubble.tls.ca.cert }}
      {{- $key := .Values.hubble.tls.ca.key  | required "missing hubble.tls.ca.key" }}
      {{- $ca = buildCustomCert $crt $key -}}
    {{- else }}
      {{- $ca = genCA "hubble-ca.cilium.io" (.Values.hubble.tls.auto.certValidityDuration | int) -}}
    {{- end }}
    {{- $_ := set . "ca" $ca -}}
  {{- end }}
{{- end }}
