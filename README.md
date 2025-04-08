# OTL - OAuth2 Test Lab

*NOT MEANT TO BE FOR PRODUCTION USE*

A minimal test OAuth2 provider that issues JWT tokens signed with RSA keys for a single client.  You can use this to test a basic OAuth2 integration with other OAuth2-Signed payload servicers, such as [Twilio SendGrid](https://www.twilio.com/docs/sendgrid/for-developers/tracking-events/getting-started-event-webhook-security-features).

When `/token` is provided with an expected pair of `oauth_client_id` and `oauth_client_secret`, it will provide a JWT that is signed by the key pair provided.

`/webhook` can act as a webhook where the JWT token can be verified against the public key.  It will return 403 when the JWT fails validation.

If OTL started without a key pair, a new key pair would be created and used.  `/jwks` can be queried to obtain the public key in such a case.

## Features

- OAuth2 token endpoint supporting client credentials flow
- JWT token issuance with RSA signature
- JWKS endpoint for public key distribution
- Webhook endpoint for token validation
- Dockerized for easy deployment

## Getting Started with Docker

### Build and Run the Docker Image

```
docker build -t ericychoi/otl:latest .
docker run -p 8080:8080 \
  -e OAUTH_CLIENT_ID=test-client-id \
  -e OAUTH_CLIENT_SECRET=test-client-secret \
  ericychoi/otl:latest
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `OAUTH_CLIENT_ID` | Client ID for authentication | test-client-id |
| `OAUTH_CLIENT_SECRET` | Client secret for authentication | test-client-secret |
| `PORT` | Port for the server to listen on | 8080 |
| `KEY_PATH` | Path to the private key | private.pem |
| `PUBLIC_KEY_PATH` | Path to the public key | public.pem |

## API Usage

### Get an OAuth2 Token

```
curl -X POST http://localhost:8080/token \
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

```
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

```
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
