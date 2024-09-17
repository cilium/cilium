{{- define "hubble-generate-certs.job.spec" }}
{{- $certValidityStr := printf "%dh" (mul .Values.hubble.tls.auto.certValidityDuration 24) -}}
spec:
  template:
    metadata:
      labels:
        k8s-app: hubble-generate-certs
        {{- with .Values.certgen.podLabels }}
        {{- toYaml . | nindent 8 }}
        {{- end }}
    spec:
      securityContext:
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: certgen
          image: {{ include "cilium.image" .Values.certgen.image | quote }}
          imagePullPolicy: {{ .Values.certgen.image.pullPolicy }}
          securityContext:
            capabilities:
              drop:
              - ALL
            allowPrivilegeEscalation: false
          command:
            - "/usr/bin/cilium-certgen"
          # Because this is executed as a job, we pass the values as command
          # line args instead of via config map. This allows users to inspect
          # the values used in past runs by inspecting the completed pod.
          args:
            {{- if .Values.debug.enabled }}
            - "--debug"
            {{- end }}
            - "--ca-generate"
            - "--ca-reuse-secret"
            - "--ca-secret-namespace={{ .Release.Namespace }}"
            - "--ca-secret-name=cilium-ca"
            - "--ca-common-name=Cilium CA"
          env:
            - name: CILIUM_CERTGEN_CONFIG
              value: |
                certs:
                - name: hubble-server-certs
                  namespace: {{ .Release.Namespace }}
                  commonName: {{ list "*" (.Values.cluster.name | replace "." "-") "hubble-grpc.cilium.io" | join "." | quote }}
                  hosts:
                  - {{ list "*" (.Values.cluster.name | replace "." "-") "hubble-grpc.cilium.io" | join "." | quote }}
                  {{- range $dns := .Values.hubble.tls.server.extraDnsNames }}
                  - {{ $dns | quote }}
                  {{- end }}
                  {{- range $ip := .Values.hubble.tls.server.extraIpAddresses }}
                  - {{ $ip | quote }}
                  {{- end }}
                  usage:
                  - signing
                  - key encipherment
                  - server auth
                  - client auth
                  validity: {{ $certValidityStr }}
                {{- if .Values.hubble.relay.enabled }}
                - name: hubble-relay-client-certs
                  namespace: {{ .Release.Namespace }}
                  commonName: "*.hubble-relay.cilium.io"
                  hosts:
                  - "*.hubble-relay.cilium.io"
                  usage:
                  - signing
                  - key encipherment
                  - client auth
                  validity: {{ $certValidityStr }}
                {{- end }}
                {{- if and .Values.hubble.relay.enabled .Values.hubble.relay.tls.server.enabled }}
                - name: hubble-relay-server-certs
                  namespace: {{ .Release.Namespace }}
                  commonName: "*.hubble-relay.cilium.io"
                  hosts:
                  - "*.hubble-relay.cilium.io"
                  {{- range $dns := .Values.hubble.relay.tls.server.extraDnsNames }}
                  - {{ $dns | quote }}
                  {{- end }}
                  {{- range $ip := .Values.hubble.relay.tls.server.extraIpAddresses }}
                  - {{ $ip | quote }}
                  {{- end }}
                  usage:
                  - signing
                  - key encipherment
                  - server auth
                  validity: {{ $certValidityStr }}
                {{- end }}
                {{- if and .Values.hubble.metrics.enabled .Values.hubble.metrics.tls.enabled }}
                - name: hubble-metrics-server-certs
                  namespace: {{ .Release.Namespace }}
                  commonName: {{ list (.Values.cluster.name | replace "." "-") "hubble-metrics.cilium.io" | join "." }} | quote }}
                  hosts:
                  - {{ list (.Values.cluster.name | replace "." "-") "hubble-metrics.cilium.io" | join "." }} | quote }}
                  {{- range $dns := .Values.hubble.metrics.tls.server.extraDnsNames }}
                  - {{ $dns | quote }}
                  {{- end }}
                  {{- range $ip := .Values.hubble.metrics.tls.server.extraIpAddresses }}
                  - {{ $ip | quote }}
                  {{- end }}
                  usage:
                  - signing
                  - key encipherment
                  - server auth
                  validity: {{ $certValidityStr }}
                {{- end }}
                {{- if and .Values.hubble.ui.enabled .Values.hubble.relay.enabled .Values.hubble.relay.tls.server.enabled }}
                - name: hubble-ui-client-certs
                  namespace: {{ .Release.Namespace }}
                  commonName: "*.hubble-ui.cilium.io"
                  hosts:
                  - "*.hubble-ui.cilium.io"
                  usage:
                  - signing
                  - key encipherment
                  - client auth
                  validity: {{ $certValidityStr }}
                {{- end }}
          {{- with .Values.certgen.extraVolumeMounts }}
          volumeMounts:
          {{- toYaml . | nindent 10 }}
          {{- end }}
      hostNetwork: false
      {{- with .Values.certgen.tolerations }}
      tolerations:
        {{- toYaml . | nindent 8 }}
      {{- end }}
      serviceAccount: {{ .Values.serviceAccounts.hubblecertgen.name | quote }}
      serviceAccountName: {{ .Values.serviceAccounts.hubblecertgen.name | quote }}
      automountServiceAccountToken: {{ .Values.serviceAccounts.hubblecertgen.automount }}
      {{- with .Values.imagePullSecrets }}
      imagePullSecrets:
        {{- toYaml . | nindent 8 }}
      {{- end }}
      restartPolicy: OnFailure
      {{- with .Values.certgen.extraVolumes }}
      volumes:
      {{- toYaml . | nindent 6 }}
      {{- end }}
      affinity:
      {{- with .Values.certgen.affinity }}
      {{- toYaml . | nindent 8 }}
      {{- end }}
  ttlSecondsAfterFinished: {{ .Values.certgen.ttlSecondsAfterFinished }}
{{- end }}
