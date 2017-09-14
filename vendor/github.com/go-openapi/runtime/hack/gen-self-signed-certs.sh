#!/bin/sh

# generate CA
openssl genrsa -out myCA.key 4096
openssl req -x509 -new -key myCA.key -out myCA.crt -days 730 -subj /CN="Go Swagger"

# generate server cert and key
openssl genrsa -out mycert1.key 4096
openssl req -new -out mycert1.req -key mycert1.key -subj /CN="goswagger.local"
openssl x509 -req -in mycert1.req -out mycert1.crt -CAkey myCA.key -CA myCA.crt -days 365 -CAcreateserial -CAserial serial

# generate client cert, key and bundle
openssl genrsa -out myclient.key 4096
openssl req -new -key myclient.key -out myclient.csr
openssl x509 -req -days 730 -in myclient.csr -out myclient.crt -CAkey myCA.key -CA myCA.crt -days 365 -CAcreateserial -CAserial serial
openssl pkcs12 -export -clcerts -in myclient.crt -inkey myclient.key -out myclient.p12
