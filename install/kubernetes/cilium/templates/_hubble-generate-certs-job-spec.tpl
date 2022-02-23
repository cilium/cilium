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
      serviceAccount: {{ .Values.serviceAccounts.hubblecertgen.name | quote }}
      serviceAccountName: {{ .Values.serviceAccounts.hubblecertgen.name | quote }}
      containers:
        - name: certgen
          image: {{ if .Values.certgen.image.override }}{{ .Values.certgen.image.override }}{{ else }}{{ .Values.certgen.image.repository }}:{{ .Values.certgen.image.tag }}{{ end }}
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
            {{- if $hubbleCAProvided }}
            - "--hubble-ca-generate=false"
            {{- else }}
            - "--hubble-ca-generate=true"
            - "--hubble-ca-validity-duration={{ $certValiditySecondsStr }}"
            - "--hubble-ca-config-map-create=true"
            - "--hubble-ca-config-map-name=hubble-ca-cert"
            {{- end }}
            {{- if and .Values.hubble.tls.server.cert .Values.hubble.tls.server.key $hubbleCAProvided }}
            - "--hubble-server-cert-generate=false"
            {{- else }}
            - "--hubble-server-cert-generate=true"
            - "--hubble-server-cert-common-name={{ list "*" (.Values.cluster.name | replace "." "-") "hubble-grpc.cilium.io" | join "." }}"
            - "--hubble-server-cert-validity-duration={{ $certValiditySecondsStr }}"
            - "--hubble-server-cert-secret-name=hubble-server-certs"
            {{- end }}
            {{- if and .Values.hubble.relay.tls.client.cert .Values.hubble.relay.tls.client.key $hubbleCAProvided }}
            - "--hubble-relay-client-cert-generate=false"
            {{- else }}
            - "--hubble-relay-client-cert-generate=true"
            - "--hubble-relay-client-cert-validity-duration={{ $certValiditySecondsStr }}"
            - "--hubble-relay-client-cert-secret-name=hubble-relay-client-certs"
            {{- end }}
            {{- if or (and .Values.hubble.relay.tls.server.cert .Values.hubble.relay.tls.server.key) (not .Values.hubble.relay.tls.server.enabled) }}
            - "--hubble-relay-server-cert-generate=false"
            {{- else if .Values.hubble.relay.tls.server.enabled }}
            - "--hubble-relay-server-cert-generate=true"
            - "--hubble-relay-server-cert-validity-duration={{ $certValiditySecondsStr }}"
            - "--hubble-relay-server-cert-secret-name=hubble-relay-server-certs"
            {{- end }}
      hostNetwork: true
      {{- if .Values.imagePullSecrets }}
      imagePullSecrets:
      {{ toYaml .Values.imagePullSecrets | indent 6 }}
      {{- end }}
      restartPolicy: OnFailure
  ttlSecondsAfterFinished: {{ .Values.certgen.ttlSecondsAfterFinished }}
{{- end }}
