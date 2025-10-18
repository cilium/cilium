# shellcheck disable=SC2086
# shellcheck disable=SC2139
set -e

{{- $uid := 1000 }}
{{- $gid := 1000 }}
{{- with .Values.authentication.mutual.spire.install.server.securityContext }}
{{- if .runAsUser }}
{{- $uid = .runAsUser }}
{{- end }}
{{- if .runAsGroup }}
{{- $gid = .runAsGroup }}
{{- end }}
{{- end }}

echo "Setting ownership of spire data directories"
chown -R {{ $uid }}:{{ $gid }} /run/spire/data
chown -R {{ $uid }}:{{ $gid }} /tmp/spire-server
echo "Ownership set successfully"
