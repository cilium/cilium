{{- define "clustermesh-apiserver-generate-certs.job.spec" }}
{{- $certValidityStr := printf "%dh" (mul .Values.clustermesh.apiserver.tls.auto.certValidityDuration 24) -}}
spec:
  template:
    metadata:
      labels:
        k8s-app: clustermesh-apiserver-generate-certs
        {{- with .Values.clustermesh.apiserver.podLabels }}
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
          {{- with .Values.certgen.resources }}
          resources:
          {{- toYaml . | nindent 10 }}
          {{- end }}
          command:
            - "/usr/bin/cilium-certgen"
          args:
            {{- if .Values.debug.enabled }}
            - "--debug"
            {{- end }}
            - "--ca-generate={{ .Values.certgen.generateCA }}"
            - "--ca-reuse-secret"
            - "--ca-secret-namespace={{ include "cilium.namespace" . }}"
            - "--ca-secret-name=cilium-ca"
            - "--ca-common-name=Cilium CA"
          env:
            - name: CILIUM_CERTGEN_CONFIG
              value: |
                certs:
                - name: clustermesh-apiserver-server-cert
                  namespace: {{ include "cilium.namespace" . }}
                  commonName: "clustermesh-apiserver.cilium.io"
                  hosts:
                  - "clustermesh-apiserver.cilium.io"
                  - "*.mesh.cilium.io"
                  - "clustermesh-apiserver.{{ include "cilium.namespace" . }}.svc"
                  {{- range $dns := .Values.clustermesh.apiserver.tls.server.extraDnsNames }}
                  - {{ $dns | quote }}
                  {{- end }}
                  - "127.0.0.1"
                  - "::1"
                  {{- range $ip := .Values.clustermesh.apiserver.tls.server.extraIpAddresses }}
                  - {{ $ip | quote }}
                  {{- end }}
                  usage:
                  - signing
                  - key encipherment
                  - server auth
                  validity: {{ $certValidityStr }}
                - name: clustermesh-apiserver-admin-cert
                  namespace: {{ include "cilium.namespace" . }}
                  commonName: {{ include "clustermesh-apiserver-generate-certs.admin-common-name" . | quote }}
                  usage:
                  - signing
                  - key encipherment
                  - client auth
                  validity: {{ $certValidityStr }}
                {{- if .Values.clustermesh.useAPIServer }}
                - name: clustermesh-apiserver-remote-cert
                  namespace: {{ include "cilium.namespace" . }}
                  commonName: {{ include "clustermesh-apiserver-generate-certs.remote-common-name" . | quote }}
                  usage:
                  - signing
                  - key encipherment
                  - client auth
                  validity: {{ $certValidityStr }}
                {{- end }}
                {{- if and .Values.clustermesh.useAPIServer .Values.clustermesh.apiserver.kvstoremesh.enabled }}
                - name: clustermesh-apiserver-local-cert
                  namespace: {{ include "cilium.namespace" . }}
                  commonName: {{ include "clustermesh-apiserver-generate-certs.local-common-name" . | quote }}
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
      {{- with .Values.certgen.nodeSelector }}
      nodeSelector:
        {{- toYaml . | nindent 8 }}
      {{- end }}
      {{- if .Values.certgen.priorityClassName }}
      priorityClassName: {{ .Values.certgen.priorityClassName }}
      {{- end }}
      {{- with .Values.certgen.tolerations }}
      tolerations:
        {{- toYaml . | nindent 8 }}
      {{- end }}
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
      {{- with .Values.certgen.affinity }}
      affinity:
      {{- toYaml . | nindent 8 }}
      {{- end }}
  ttlSecondsAfterFinished: {{ .Values.certgen.ttlSecondsAfterFinished }}
{{- end }}
