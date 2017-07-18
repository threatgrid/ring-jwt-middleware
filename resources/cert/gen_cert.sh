#/bin/env bash
openssl genrsa -out ring-jwt-middleware.key 2048
openssl req -out ring-jwt-middleware.csr -key ring-jwt-middleware.key -new -sha256
openssl rsa -in ring-jwt-middleware.key -pubout -out ring-jwt-middleware.pub
