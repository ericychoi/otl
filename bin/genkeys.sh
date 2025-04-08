#!/bin/sh
set -ex
if [ ! -f "/app/keys/private.pem" ]; then
  echo "Generating RSA key pair..."
  openssl genrsa -out /app/keys/private.pem 2048
  openssl rsa -in /app/keys/private.pem -pubout -out /app/keys/public.pem
  echo "RSA key pair generated successfully!"
fi
