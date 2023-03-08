{{- define "clustermesh-apiserver-generate-certs.job.spec" }}
{{- $certValiditySecondsStr := printf "%ds" (mul .Values.clustermesh.apiserver.tls.auto.certValidityDuration 24 60 60) -}}
{{- $clustermeshServerSANs := concat (list "*.mesh.cilium.io")
  .Values.clustermesh.apiserver.tls.server.extraDnsNames
  .Values.clustermesh.apiserver.tls.server.extraIpAddresses
-}}
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
            {{- if .Values.debug.enabled }}
            - "--debug"
            {{- end }}
            - "--ca-generate"
            - "--ca-reuse-secret"
            {{- if .Values.clustermesh.apiserver.tls.ca.cert }}
            - "--ca-secret-name=clustermesh-apiserver-ca-cert"
            {{- else -}}
              {{- if and .Values.tls.ca.cert .Values.tls.ca.key }}
            - "--ca-secret-name=cilium-ca"
              {{- end }}
            {{- end }}
            - "--clustermesh-apiserver-server-cert-generate"
            - "--clustermesh-apiserver-server-cert-validity-duration={{ $certValiditySecondsStr }}"
            - "--clustermesh-apiserver-server-cert-sans={{ join "," $clustermeshServerSANs }}"
            - "--clustermesh-apiserver-admin-cert-generate"
            - "--clustermesh-apiserver-admin-cert-validity-duration={{ $certValiditySecondsStr }}"
            - "--clustermesh-apiserver-admin-cert-common-name={{ include "clustermesh-apiserver-generate-certs.admin-common-name" . }}"
            {{- if .Values.externalWorkloads.enabled }}
            - "--clustermesh-apiserver-client-cert-generate"
            - "--clustermesh-apiserver-client-cert-validity-duration={{ $certValiditySecondsStr }}"
            {{- end }}
            {{- if .Values.clustermesh.useAPIServer }}
            - "--clustermesh-apiserver-remote-cert-generate"
            - "--clustermesh-apiserver-remote-cert-validity-duration={{ $certValiditySecondsStr }}"
            - "--clustermesh-apiserver-remote-cert-common-name={{ include "clustermesh-apiserver-generate-certs.remote-common-name" . }}"
            {{- end }}
          {{- with .Values.certgen.extraVolumeMounts }}
          volumeMounts:
          {{- toYaml . | nindent 10 }}
          {{- end }}
      hostNetwork: true
      serviceAccount: {{ .Values.serviceAccounts.clustermeshcertgen.name | quote }}
      serviceAccountName: {{ .Values.serviceAccounts.clustermeshcertgen.name | quote }}
      automountServiceAccountToken: {{ .Values.serviceAccounts.clustermeshcertgen.automount }}
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
