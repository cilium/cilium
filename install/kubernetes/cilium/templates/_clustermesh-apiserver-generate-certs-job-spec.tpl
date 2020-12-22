{{- define "clustermesh-apiserver-generate-certs.job.spec" }}
{{- $certValiditySecondsStr := printf "%ds" (mul .Values.clustermesh.apiserver.tls.auto.certValidityDuration 24 60 60) -}}
spec:
  template:
    metadata:
      labels:
        k8s-app: clustermesh-apiserver-generate-certs
    spec:
      serviceAccount: clustermesh-apiserver-generate-certs
      serviceAccountName: clustermesh-apiserver-generate-certs
      containers:
        - name: certgen
          image: {{ .Values.certgen.image.repository }}:{{ .Values.certgen.image.tag }}
          imagePullPolicy: {{ .Values.certgen.image.pullPolicy }}
          command:
            - "/usr/bin/cilium-certgen"
          args:
            - "--cilium-namespace={{ .Release.Namespace }}"
            - "--clustermesh-apiserver-ca-cert-reuse-secret"
            {{- if .Values.debug.enabled }}
            - "--debug"
            {{- end }}
            {{- if not (and .Values.clustermesh.apiserver.tls.ca.cert .Values.clustermesh.apiserver.tls.ca.key) }}
            - "--clustermesh-apiserver-ca-cert-generate"
            {{- end }}
            {{- if not (and .Values.clustermesh.apiserver.tls.server.cert .Values.clustermesh.apiserver.tls.server.key) }}
            - "--clustermesh-apiserver-server-cert-generate"
            {{- end }}
            {{- if not (and .Values.clustermesh.apiserver.tls.admin.cert .Values.clustermesh.apiserver.tls.admin.key) }}
            - "--clustermesh-apiserver-admin-cert-generate"
            {{- end }}
            {{- if not (and .Values.clustermesh.apiserver.tls.client.cert .Values.clustermesh.apiserver.tls.client.key) }}
            - "--clustermesh-apiserver-client-cert-generate"
            {{- end }}
            {{- if not (and .Values.clustermesh.apiserver.tls.remote.cert .Values.clustermesh.apiserver.tls.remote.key) }}
            - "--clustermesh-apiserver-remote-cert-generate"
            {{- end }}
      hostNetwork: true
      {{- if .Values.imagePullSecrets }}
      imagePullSecrets:
      {{ toYaml .Values.imagePullSecrets | indent 6 }}
      {{- end }}
      restartPolicy: OnFailure
  ttlSecondsAfterFinished: {{ .Values.certgen.ttlSecondsAfterFinished }}
{{- end }}
