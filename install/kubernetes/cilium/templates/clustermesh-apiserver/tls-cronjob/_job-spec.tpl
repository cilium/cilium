{{- define "clustermesh-apiserver-generate-certs.job.spec" }}
{{- $certValiditySecondsStr := printf "%ds" (mul .Values.clustermesh.apiserver.tls.auto.certValidityDuration 24 60 60) -}}
spec:
  template:
    metadata:
      labels:
        k8s-app: clustermesh-apiserver-generate-certs
        {{- with .Values.clustermesh.apiserver.podLabels }}
        {{- toYaml . | nindent 8 }}
        {{- end }}
    spec:
      containers:
        - name: certgen
          image: {{ include "cilium.image" .Values.certgen.image | quote }}
          imagePullPolicy: {{ .Values.certgen.image.pullPolicy }}
          command:
            - "/usr/bin/cilium-certgen"
          args:
            - "--cilium-namespace={{ .Release.Namespace }}"
            - "--clustermesh-apiserver-ca-cert-reuse-secret"
            {{- if .Values.debug.enabled }}
            - "--debug"
            {{- end }}
            - "--clustermesh-apiserver-ca-cert-generate"
            - "--clustermesh-apiserver-ca-cert-reuse-secret"
            - "--clustermesh-apiserver-server-cert-generate"
            - "--clustermesh-apiserver-server-cert-validity-duration={{ $certValiditySecondsStr }}"
            - "--clustermesh-apiserver-admin-cert-generate"
            - "--clustermesh-apiserver-admin-cert-validity-duration={{ $certValiditySecondsStr }}"
            {{- if .Values.externalWorkloads.enabled }}
            - "--clustermesh-apiserver-client-cert-generate"
            - "--clustermesh-apiserver-client-cert-validity-duration={{ $certValiditySecondsStr }}"
            {{- end }}
            {{- if .Values.clustermesh.useAPIServer }}
            - "--clustermesh-apiserver-remote-cert-generate"
            - "--clustermesh-apiserver-remote-cert-validity-duration={{ $certValiditySecondsStr }}"
            {{- end }}
      hostNetwork: true
      serviceAccount: {{ .Values.serviceAccounts.clustermeshcertgen.name | quote }}
      serviceAccountName: {{ .Values.serviceAccounts.clustermeshcertgen.name | quote }}
      {{- with .Values.imagePullSecrets }}
      imagePullSecrets:
        {{- toYaml . | nindent 8 }}
      {{- end }}
      restartPolicy: OnFailure
  ttlSecondsAfterFinished: {{ .Values.certgen.ttlSecondsAfterFinished }}
{{- end }}
