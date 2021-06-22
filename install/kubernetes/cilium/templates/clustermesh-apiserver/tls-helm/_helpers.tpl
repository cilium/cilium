{{- define "clustermesh-apiserver-generate-certs.helm.setup-ca" }}
  {{- if not .cmca }}
    {{- $ca := "" -}}
    {{- if .Values.clustermesh.apiserver.tls.ca.cert }}
      {{- $crt := .Values.clustermesh.apiserver.tls.ca.cert }}
      {{- $key := .Values.clustermesh.apiserver.tls.ca.key  | required "missing clustermesh.apiserver.tls.ca.key" }}
      {{- $ca = buildCustomCert $crt $key -}}
    {{- else }}
      {{- $ca = genCA "clustermesh-apiserver-ca.cilium.io" (.Values.clustermesh.apiserver.tls.auto.certValidityDuration | int) -}}
    {{- end }}
    {{- $_ := set . "cmca" $ca -}}
  {{- end }}
{{- end }}
