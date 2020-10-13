{{- define "hubble-generate-certs.job.spec" }}
{{- $certValiditySecondsStr := printf "%ds" (mul .Values.hubble.tls.auto.certValidityDuration 24 60 60) -}}
spec:
  template:
    metadata:
      labels:
        k8s-app: hubble-generate-certs
    spec:
      serviceAccount: hubble-generate-certs
      serviceAccountName: hubble-generate-certs
      containers:
        - name: certgen
          image: {{ .Values.hubble.tls.auto.cronJob.image.repository }}:{{ .Values.hubble.tls.auto.cronJob.image.tag }}
          imagePullPolicy: {{ .Values.hubble.tls.auto.cronJob.image.pullPolicy }}
          command:
            - "/usr/bin/cilium-certgen"
          {{/* Because this is executed as a job, we pass the values as command line args instead of via config map,
                this allows users to inspect the values used in past runs by inspecting the completed pod */ -}}
          args:
            {{- if .Values.debug.enabled }}
            - "--debug"
            {{- end }}
            {{- $hubbleCAProvided := and .Values.hubble.tls.ca.cert .Values.hubble.tls.ca.key -}}
            {{- if $hubbleCAProvided }}
            - "--hubble-ca-generate=false"
            - "--hubble-ca-key-file=/var/lib/cilium/tls/hubble-ca/tls.key"
            - "--hubble-ca-cert-file=/var/lib/cilium/tls/hubble-ca/tls.crt"
            {{- else }}
            - "--hubble-ca-generate=true"
            - "--hubble-ca-validity-duration={{ $certValiditySecondsStr }}"
            - "--hubble-ca-config-map-name=hubble-ca-cert"
            - "--hubble-ca-config-map-namespace={{ .Release.Namespace }}"
            {{- end }}
            {{- if and .Values.hubble.tls.server.cert .Values.hubble.tls.server.key $hubbleCAProvided }}
            - "--hubble-server-cert-generate=false"
            {{- else }}
            - "--hubble-server-cert-generate=true"
            - "--hubble-server-cert-validity-duration={{ $certValiditySecondsStr }}"
            - "--hubble-server-cert-secret-name=hubble-server-certs"
            - "--hubble-server-cert-secret-namespace={{ .Release.Namespace }}"
            {{- end }}
            {{- if and .Values.hubble.relay.tls.client.cert .Values.hubble.relay.tls.client.key $hubbleCAProvided }}
            - "--hubble-relay-client-cert-generate=false"
            {{- else }}
            - "--hubble-relay-client-cert-generate=true"
            - "--hubble-relay-client-cert-validity-duration={{ $certValiditySecondsStr }}"
            - "--hubble-relay-client-cert-secret-name=hubble-relay-client-certs"
            - "--hubble-relay-client-cert-secret-namespace={{ .Release.Namespace }}"
            {{- end }}
            {{- if or (and .Values.hubble.relay.tls.server.cert .Values.hubble.relay.tls.server.key) (not .Values.hubble.relay.tls.server.enabled) }}
            - "--hubble-relay-server-cert-generate=false"
            {{- else if .Values.hubble.relay.tls.server.enabled }}
            - "--hubble-relay-server-cert-generate=true"
            - "--hubble-relay-server-cert-validity-duration={{ $certValiditySecondsStr }}"
            - "--hubble-relay-server-cert-secret-name=hubble-relay-server-certs"
            - "--hubble-relay-server-cert-secret-namespace={{ .Release.Namespace }}"
            {{- end }}
          volumeMounts:
          {{- if $hubbleCAProvided }}
            - mountPath: /var/lib/cilium/tls/hubble-ca
              name: hubble-ca-secret
              readOnly: true
          {{- end }}
      hostNetwork: true
      {{- if .Values.imagePullSecrets }}
      imagePullSecrets:
      {{ toYaml .Values.imagePullSecrets | indent 6 }}
      {{- end }}
      restartPolicy: OnFailure
      volumes:
      {{- if $hubbleCAProvided }}
        - name: hubble-ca-secret
          secret:
            secretName: hubble-ca-secret
      {{- end }}
  ttlSecondsAfterFinished: {{ .Values.hubble.tls.auto.cronJob.ttlSecondsAfterFinished }}
{{- end }}
