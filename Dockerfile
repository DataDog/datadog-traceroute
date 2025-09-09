# Dockerfile
FROM golang:1.24.6

WORKDIR /app
COPY . .

RUN go test -tags=test ./...
