# Dockerfile
FROM golang:1.24.0

WORKDIR /app
COPY . .

RUN go test -tags=test ./...
