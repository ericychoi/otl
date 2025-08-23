FROM golang:1.23-alpine AS builder
WORKDIR /app
COPY . .
RUN go mod download && CGO_ENABLED=0 GOOS=linux go build -o /bin/server ./cmd/server

FROM alpine:3.18
WORKDIR /app
RUN apk add --no-cache openssl && mkdir -p /app/keys
COPY --from=builder /bin/server /bin/server
COPY --from=builder /app/bin/genkeys.sh /bin/genkeys.sh
RUN chmod +x /bin/genkeys.sh
CMD /bin/genkeys.sh && /bin/server
