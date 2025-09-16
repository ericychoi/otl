# OTL - OAuth2 Test Lab

**FOR TESTING AND DEVELOPMENT PURPOSES ONLY - NOT INTENDED FOR PRODUCTION USE**

A minimal test OAuth2 provider that issues JWT tokens signed with RSA keys for a single client.  You can use this to test a basic OAuth2 integration with other OAuth2-Signed payload servicers,
such as [Twilio SendGrid](https://www.twilio.com/docs/sendgrid/for-developers/tracking-events/getting-started-event-webhook-security-features) which implements [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3).

When `/token` is provided with an expected pair of `oauth_client_id` and `oauth_client_secret`, it will provide a JWT that is signed by the key pair provided.

`/webhook` can act as a webhook where the JWT token can be verified against the public key.  It will return 403 when the JWT fails validation.
When the webhook payload contains a twilio signature AND if otl started with TWILIO_SIGNATURE_PUBLIC_KEY supplied, it will also check the signature.

If OTL started without a key pair, a new key pair would be created and used.  `/jwks` can be queried to obtain the public key in such a case.

## Features

- OAuth2 token endpoint supporting client credentials flow
- JWT token issuance with RSA signature
- JWKS endpoint for public key distribution
- Webhook endpoint for token validation
- Dockerized for easy deployment

## Getting Started

### Local Development

```bash
go run cmd/server/main.go cmd/server/config.go
```

### Docker (Quick Start)

```bash
docker build -t otl:latest .
docker run -p 8080:8080 \
  -e OAUTH_CLIENT_ID=test-client-id \
  -e OAUTH_CLIENT_SECRET=test-client-secret \
  -e TWILIO_SIGNATURE_PUBLIC_KEY='MFkwEwYHKoZIzj...' \
  otl:latest
```

### HTTPS Support (Optional)

Enable HTTPS for testing SSL integrations:

```bash
# Generate self-signed certificates
./bin/gen-ssl-certs.sh

# Run with HTTPS enabled
ENABLE_HTTPS=true go run cmd/server/main.go cmd/server/config.go

# Or with Docker
docker run -p 8080:8080 \
  -e ENABLE_HTTPS=true \
  -e OAUTH_CLIENT_ID=test-client-id \
  -e OAUTH_CLIENT_SECRET=test-client-secret \
  -e TWILIO_SIGNATURE_PUBLIC_KEY='MFkwEwYHKoZIzj...' \
  otl:latest
```

### Docker with Pre-built Certificates

For testing in isolated environments:

```bash
# Build image with certificates included
docker build -f Dockerfile.with-certs -t otl:with-certs .

# Export for transfer to test servers
docker save otl:with-certs | gzip > otl-with-certs.tar.gz
```

### Deploy to Remote Server

Transfer and run the packaged image on a remote server:

```bash
# Transfer image to remote server
scp otl.tar.gz user@remote-server:/tmp/

# SSH to remote server copy
ssh user@remote-server
docker load < /tmp/otl.tar.gz

# then you can run it with docker run as above
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `OAUTH_CLIENT_ID` | Client ID for authentication | test-client-id |
| `OAUTH_CLIENT_SECRET` | Client secret for authentication | test-client-secret |
| `PORT` | Server port | 8080 |
| `ENABLE_HTTPS` | Enable HTTPS/TLS | false |
| `KEY_PATH` | JWT private key path | keys/private.pem |
| `PUBLIC_KEY_PATH` | JWT public key path | keys/public.pem |
| `TLS_CERT_PATH` | SSL certificate path | keys/server.crt |
| `TLS_KEY_PATH` | SSL private key path | keys/server.key |
| `TWILIO_SIGNATURE_PUBLIC_KEY` | Twilio webhook signature verification key | (empty) |

## HTTPS Configuration

OTL supports HTTPS/TLS for secure communication. To enable HTTPS:

1. **Generate SSL certificates** (for development/testing):
   ```bash
   ./bin/gen-ssl-certs.sh
   ```

2. **Enable HTTPS** by setting the environment variable:
   ```bash
   export ENABLE_HTTPS=true
   ```

3. **Run the server**:
   ```bash
   go run cmd/server/main.go cmd/server/config.go
   ```

The server will now be accessible at `https://localhost:8080` instead of `http://localhost:8080`.

**Note**: The generated certificates are self-signed and intended for testing only.

## API Usage

### Get an OAuth2 Token

```bash
curl -X POST http://localhost:8080/token \
  -d "grant_type=client_credentials" \
  -d "client_id=test-client-id" \
  -d "client_secret=test-client-secret"
```

**With HTTPS:**
```bash
curl -k -X POST https://localhost:8080/token \
  -d "grant_type=client_credentials" \
  -d "client_id=test-client-id" \
  -d "client_secret=test-client-secret"
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 3600
}
```

### Verify a Token Using the Webhook

```bash
curl -X GET http://localhost:8080/webhook \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
```

**Success Response:**
```json
{
  "status": "success",
  "message": "Token is valid"
}
```

### Get JWKS (Public Key Information)

```bash
curl http://localhost:8080/jwks
```

**Response:**
```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "key1",
      "use": "sig",
      "alg": "RS256",
      "n": "...",
      "e": "..."
    }
  ]
}
```

## References
* [RFC 6749 - The OAuth 2.0 Authorization Framework](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3)
* [Twilio SendGrid - Event Webhook Security](https://www.twilio.com/docs/sendgrid/for-developers/tracking-events/getting-started-event-webhook-security-features#oauth-20)
