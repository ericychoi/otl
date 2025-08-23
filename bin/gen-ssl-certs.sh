#!/bin/bash

# Generate SSL certificates for HTTPS
# This creates self-signed certificates for development/testing
#
# Usage: ./gen-ssl-certs.sh [domain_or_ip]
# Example: ./gen-ssl-certs.sh example.com
#          ./gen-ssl-certs.sh 192.168.1.100

# Get domain/IP from command line argument
DOMAIN_OR_IP="${1:-localhost}"

# Use absolute path or relative to current working directory
if [ -d "/app/keys" ]; then
    KEYS_DIR="/app/keys"
else
    KEYS_DIR="keys"
fi

# Create keys directory if it doesn't exist
mkdir -p "$KEYS_DIR"

echo "Generating SSL certificate for: $DOMAIN_OR_IP"

# Create OpenSSL config file with SAN (Subject Alternative Names)
cat > "$KEYS_DIR/ssl.conf" << EOF
[req]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn
req_extensions = v3_req

[dn]
C=US
ST=State
L=City
O=Organization
CN=$DOMAIN_OR_IP

[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = $DOMAIN_OR_IP
IP.1 = 127.0.0.1
EOF

# Add IP address to alt_names if the input looks like an IP
if [[ $DOMAIN_OR_IP =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "IP.2 = $DOMAIN_OR_IP" >> "$KEYS_DIR/ssl.conf"
fi

# Generate private key
openssl genrsa -out "$KEYS_DIR/server.key" 2048

# Generate self-signed certificate with SAN
openssl req -new -x509 -days 365 -key "$KEYS_DIR/server.key" \
    -out "$KEYS_DIR/server.crt" \
    -config "$KEYS_DIR/ssl.conf" \
    -extensions v3_req

# Clean up config file
rm "$KEYS_DIR/ssl.conf"

echo "SSL certificates generated for: $DOMAIN_OR_IP"
echo "  Certificate: $KEYS_DIR/server.crt"
echo "  Private Key: $KEYS_DIR/server.key"
echo ""
echo "Certificate includes the following names:"
echo "  - localhost"
echo "  - 127.0.0.1"
echo "  - $DOMAIN_OR_IP"
if [[ $DOMAIN_OR_IP =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "  (IP address detected and added to certificate)"
fi
echo ""
echo "To enable HTTPS, set the environment variable:"
echo "  export ENABLE_HTTPS=true"
echo ""
echo "Optional: Customize certificate and key paths:"
echo "  export TLS_CERT_PATH=$KEYS_DIR/server.crt"
echo "  export TLS_KEY_PATH=$KEYS_DIR/server.key"
