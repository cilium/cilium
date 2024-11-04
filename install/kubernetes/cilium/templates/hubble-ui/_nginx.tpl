{{- define "hubble-ui.nginx.conf" }}
server {
    listen       8081;
{{- if .Values.hubble.ui.frontend.server.ipv6.enabled }}
    listen       [::]:8081;
{{- end }}
    server_name  localhost;
    root /app;
    index index.html;
    client_max_body_size 1G;

    location / {
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;

        location {{ .Values.hubble.ui.baseUrl }}api {
            {{- if not (eq .Values.hubble.ui.baseUrl "/") }}
            rewrite ^{{ (trimSuffix "/" .Values.hubble.ui.baseUrl) }}(/.*)$ $1 break;
            {{- end }}
            proxy_http_version 1.1;
            proxy_pass_request_headers on;
            {{- if eq .Values.hubble.ui.baseUrl "/" }}
            proxy_pass http://127.0.0.1:8090;
            {{- else }}
            proxy_pass http://127.0.0.1:8090/;
            {{- end }}
        }

        {{- if not (eq .Values.hubble.ui.baseUrl "/") }}
        sub_filter_once on;
        sub_filter '<base href="/"/>' '<base href="{{ .Values.hubble.ui.baseUrl }}"/>';
        {{- end }}
        location {{ .Values.hubble.ui.baseUrl }} {
            {{- if not (eq .Values.hubble.ui.baseUrl "/") }}
            rewrite ^{{ (trimSuffix "/" .Values.hubble.ui.baseUrl) }}(/.*)$ $1 break;
            {{- end }}
            # double `/index.html` is required here 
            try_files $uri $uri/ /index.html /index.html;
        }

        # Liveness probe
        location /healthz {
            access_log off;
            add_header Content-Type text/plain;
            return 200 'ok';
        }
    }
}
{{- end }}
