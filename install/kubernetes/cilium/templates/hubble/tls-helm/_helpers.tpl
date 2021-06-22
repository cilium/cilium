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
