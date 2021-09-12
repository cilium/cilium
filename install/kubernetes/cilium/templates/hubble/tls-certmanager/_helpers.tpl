{{- define "hubble-generate-certs.certmanager.issuer" }}
{{- if .Values.hubble.tls.auto.certManagerIssuerRef }}
  {{- toYaml .Values.hubble.tls.auto.certManagerIssuerRef }}
{{- else }}
  group: cert-manager.io
  kind: Issuer
  name: hubble-issuer
{{- end }}
{{- end }}
