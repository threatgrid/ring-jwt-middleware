#!/usr/bin/env bash
keybasename=jwt-key

for i in `seq 1 3`; do

openssl genrsa -out $keybasename-$i.key -passout pass:clojure 2048
openssl req -passin pass:clojure -out ring-jwt-middleware.csr -key $keybasename-$i.key -new -sha256 -subjj"/C=FR/ST=France/L=Nice/O=Cisco/OU=CTR/CN=cisco.com/emailAddress=dev.null@dev.null"
openssl rsa -passin pass:clojure -in $keybasename-$i.key -pubout -out $keybasename-$i.pub

done
