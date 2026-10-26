{{/*
Name of the Secret holding the shared SPIRE upstream root. Multiple
CRD-managed servers need a common root so every server issues SVIDs that
chain to the same trust bundle.
*/}}
{{- define "cilium.spire.upstreamSecret" -}}
{{- $server := .Values.authentication.mutual.spire.install.server -}}
{{- if .Values.encryption.ztunnel.spire.useCRD -}}
{{- if $server.ca.upstreamSecret -}}
{{- $server.ca.upstreamSecret -}}
{{- else if gt (int64 $server.replicas) 1 -}}
spire-upstream-ca
{{- end -}}
{{- end -}}
{{- end -}}
