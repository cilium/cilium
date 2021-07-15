{{- define "hubble-generate-certs.job.spec" }}
{{- $certValiditySecondsStr := printf "%ds" (mul .Values.hubble.tls.auto.certValidityDuration 24 60 60) -}}
spec:
  template:
    metadata:
      labels:
        k8s-app: hubble-generate-certs
        {{- with .Values.certgen.podLabels }}
        {{- toYaml . | nindent 8 }}
        {{- end }}
    spec:
      containers:
        - name: certgen
          image: {{ include "cilium.image" .Values.certgen.image | quote }}
          imagePullPolicy: {{ .Values.certgen.image.pullPolicy }}
          command:
            - "/usr/bin/cilium-certgen"
          # Because this is executed as a job, we pass the values as command
          # line args instead of via config map. This allows users to inspect
          # the values used in past runs by inspecting the completed pod.
          args:
            - "--cilium-namespace={{ .Release.Namespace }}"
            - "--hubble-ca-reuse-secret=true"
            - "--hubble-ca-secret-name=hubble-ca-secret"
            {{- if .Values.debug.enabled }}
            - "--debug"
            {{- end }}
            {{- $hubbleCAProvided := and .Values.hubble.tls.ca.cert .Values.hubble.tls.ca.key -}}
            {{- if not $hubbleCAProvided }}
            - "--hubble-ca-generate=true"
            - "--hubble-ca-validity-duration={{ $certValiditySecondsStr }}"
            - "--hubble-ca-config-map-create=true"
            - "--hubble-ca-config-map-name=hubble-ca-cert"
            {{- else }}
            - "--hubble-ca-generate=false"
            {{- end }}
            - "--hubble-server-cert-generate=true"
            - "--hubble-server-cert-common-name={{ list "*" (.Values.cluster.name | replace "." "-") "hubble-grpc.cilium.io" | join "." }}"
            - "--hubble-server-cert-validity-duration={{ $certValiditySecondsStr }}"
            - "--hubble-server-cert-secret-name=hubble-server-certs"
            {{- if .Values.hubble.relay.enabled }}
            - "--hubble-relay-client-cert-generate=true"
            - "--hubble-relay-client-cert-validity-duration={{ $certValiditySecondsStr }}"
            - "--hubble-relay-client-cert-secret-name=hubble-relay-client-certs"
            {{- else }}
            - "--hubble-relay-client-cert-generate=false"
            {{- end }}
            {{- if and .Values.hubble.relay.enabled .Values.hubble.relay.tls.server.enabled }}
            - "--hubble-relay-server-cert-generate=true"
            - "--hubble-relay-server-cert-validity-duration={{ $certValiditySecondsStr }}"
            - "--hubble-relay-server-cert-secret-name=hubble-relay-server-certs"
            {{- else }}
            - "--hubble-relay-server-cert-generate=false"
            {{- end }}
      hostNetwork: true
      serviceAccount: {{ .Values.serviceAccounts.hubblecertgen.name | quote }}
      serviceAccountName: {{ .Values.serviceAccounts.hubblecertgen.name | quote }}
      {{- with .Values.imagePullSecrets }}
      imagePullSecrets:
        {{- toYaml . | nindent 8 }}
      {{- end }}
      restartPolicy: OnFailure
  ttlSecondsAfterFinished: {{ .Values.certgen.ttlSecondsAfterFinished }}
{{- end }}
