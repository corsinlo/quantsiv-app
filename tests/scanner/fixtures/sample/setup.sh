#!/bin/sh
openssl genrsa -out server.key 4096
openssl ecparam -name secp384r1 -genkey -noout -out ec.key
ssh-keygen -t ed25519 -f deploy_key -N ""
