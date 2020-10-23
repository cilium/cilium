{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "cilium.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Return the appropriate apiVersion for ingress.
*/}}
{{- define "ingress.apiVersion" -}}
{{- if semverCompare ">=1.4-0, <1.14-0" .Capabilities.KubeVersion.Version -}}
{{- print "extensions/v1beta1" -}}
{{- else if semverCompare ">=1.14-0, <1.19.0" .Capabilities.KubeVersion.Version -}}
{{- print "networking.k8s.io/v1beta1" -}}
{{- else if semverCompare "^1.19-0" .Capabilities.KubeVersion.Version -}}
{{- print "networking.k8s.io/v1" -}}
{{- end -}}
{{- end -}}

{{/*
Return the appropriate backend for Hubble UI ingress.
*/}}
{{- define "ingress.paths" -}}
{{ if semverCompare ">=1.4-0, <1.19-0" .Capabilities.KubeVersion.Version -}}
backend:
  serviceName: hubble-ui
  servicePort: http
{{- else if semverCompare "^1.19-0" .Capabilities.KubeVersion.Version -}}
pathType: Prefix
backend:
  service:
    name: hubble-ui
    port:
      name: http
{{- end -}}
{{- end -}}


{{/*
Generate TLS certificates for Hubble Server and Hubble Relay.

Note: these 2 lines, that are repeated several times below, are a trick to
ensure the CA certs are generated only once:

    $ca := .ca | default (genCA "hubble-ca.cilium.io" (.Values.hubble.tls.auto.certValidityDuration | int))
    $_ := set . "ca" $ca

Please, don't try to "simplify" them as without this trick, every generated
certificate would be signed by a different CA.
*/}}
{{- define "hubble.ca.gen-cert-only" }}
{{- $ca := .ca | default (genCA "hubble-ca.cilium.io" (.Values.hubble.tls.auto.certValidityDuration | int)) -}}
{{- $_ := set . "ca" $ca -}}
ca.crt: |-
{{ $ca.Cert | indent 2 -}}
{{- end }}
{{- define "hubble.server.gen-certs" }}
{{- $ca := .ca | default (genCA "hubble-ca.cilium.io" (.Values.hubble.tls.auto.certValidityDuration | int)) -}}
{{- $_ := set . "ca" $ca -}}
{{- $cn := list "*" .Values.cluster.name "hubble-grpc.cilium.io" | join "." }}
{{- $cert := genSignedCert $cn nil (list $cn) (.Values.hubble.tls.auto.certValidityDuration | int) $ca -}}
tls.crt: {{ $cert.Cert | b64enc }}
tls.key: {{ $cert.Key | b64enc }}
{{- end }}
{{- define "hubble.relay.gen-certs" }}
{{- $ca := .ca | default (genCA "hubble-ca.cilium.io" (.Values.hubble.tls.auto.certValidityDuration | int)) -}}
{{- $_ := set . "ca" $ca -}}
{{- $cert := genSignedCert "*.hubble-relay.cilium.io" nil (list "*.hubble-relay.cilium.io") (.Values.hubble.tls.auto.certValidityDuration | int) $ca -}}
tls.crt: {{ $cert.Cert | b64enc }}
tls.key: {{ $cert.Key | b64enc }}
{{- end }}
