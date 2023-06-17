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
            {{- if .Values.debug.enabled }}
            - "--debug"
            {{- end }}
            - "--ca-generate"
            - "--ca-reuse-secret"
            {{- if and .Values.tls.ca.cert .Values.tls.ca.key }}
            - "--ca-secret-name=cilium-ca"
            {{- end }}
            - "--hubble-server-cert-generate"
            - "--hubble-server-cert-common-name={{ list "*" (.Values.cluster.name | replace "." "-") "hubble-grpc.cilium.io" | join "." }}"
            - "--hubble-server-cert-validity-duration={{ $certValiditySecondsStr }}"
            {{- if .Values.hubble.relay.enabled }}
            - "--hubble-relay-client-cert-generate"
            - "--hubble-relay-client-cert-validity-duration={{ $certValiditySecondsStr }}"
            {{- end }}
            {{- if and .Values.hubble.relay.enabled .Values.hubble.relay.tls.server.enabled }}
            - "--hubble-relay-server-cert-generate"
            - "--hubble-relay-server-cert-validity-duration={{ $certValiditySecondsStr }}"
            {{- end }}
          {{- with .Values.certgen.extraVolumeMounts }}
          volumeMounts:
          {{- toYaml . | nindent 10 }}
          {{- end }}
      hostNetwork: true
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
  ttlSecondsAfterFinished: {{ .Values.certgen.ttlSecondsAfterFinished }}
{{- end }}
