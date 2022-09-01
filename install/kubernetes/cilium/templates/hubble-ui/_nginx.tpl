{{- define "hubble-ui.nginx.conf" }}
server {
    listen       8081;
    listen       [::]:8081;
    server_name  localhost;
    root /app;
    index index.html;
    client_max_body_size 1G;

    location / {
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;

        # CORS
        add_header Access-Control-Allow-Methods "GET, POST, PUT, HEAD, DELETE, OPTIONS";
        add_header Access-Control-Allow-Origin *;
        add_header Access-Control-Max-Age 1728000;
        add_header Access-Control-Expose-Headers content-length,grpc-status,grpc-message;
        add_header Access-Control-Allow-Headers range,keep-alive,user-agent,cache-control,content-type,content-transfer-encoding,x-accept-content-transfer-encoding,x-accept-response-streaming,x-user-agent,x-grpc-web,grpc-timeout;
        if ($request_method = OPTIONS) {
            return 204;
        }
        # /CORS

        location /api {
            proxy_http_version 1.1;
            proxy_pass_request_headers on;
            proxy_hide_header Access-Control-Allow-Origin;
            proxy_pass http://127.0.0.1:8090;
        }

        location / {
            try_files $uri $uri/ /index.html;
        }
    }
}
{{- end }}
