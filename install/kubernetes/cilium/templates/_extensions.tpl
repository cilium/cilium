{{/*
_extensions.tpl contains template blocks that are intended to allow packagers
to modify or extend the default chart behaviors.
*/}}

{{/*
Intentionally empty to allow downstream chart packagers to add extra
containers to hubble-relay without having to modify the deployment manifest
directly.
*/}}
{{- define "hubble-relay.containers.extra" }}
{{- end }}

{{/*
Allow packagers to add extra volumes to relay.
*/}}
{{- define "hubble-relay.volumes.extra" }}
{{- end }}

{{/*
Allow packagers to modify how hubble-relay TLS is configured.

A packager may want to change when TLS is enabled or prevent users from
disabling TLS. This means the template needs to allow overriding, not just
adding, which is why this template is not empty by default, like the ones
above.
*/}}
{{- define "hubble-relay.config.tls" }}
{{- if and .Values.hubble.tls.enabled .Values.hubble.relay.tls.server.enabled }}
tls-relay-server-cert-file: /var/lib/hubble-relay/tls/server.crt
tls-relay-server-key-file: /var/lib/hubble-relay/tls/server.key
{{- if .Values.hubble.relay.tls.server.mtls }}
tls-relay-client-ca-files: /var/lib/hubble-relay/tls/hubble-server-ca.crt
{{- end }}
{{- else }}
disable-server-tls: true
{{- end }}
{{- end }}

{{- define "hubble-relay.config.listenAddress" -}}
{{- .Values.hubble.relay.listenHost }}:{{- include "hubble-relay.config.listenPort" . -}}
{{- end }}

{{- define "hubble-relay.config.listenPort" -}}
{{- .Values.hubble.relay.listenPort }}
{{- end }}

{{- define "hubble-relay.service.targetPort" -}}
grpc
{{- end }}
