{{- define "clustermesh-apiserver-generate-certs.certmanager.issuer" }}
{{- if .Values.clustermesh.apiserver.tls.auto.certManagerIssuerRef }}
  {{- toYaml .Values.clustermesh.apiserver.tls.auto.certManagerIssuerRef }}
{{- else }}
  group: cert-manager.io
  kind: Issuer
  name: clustermesh-apiserver-issuer
{{- end }}
{{- end }}
