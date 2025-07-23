# Dockerfile
FROM golang:1.24.5

WORKDIR /app
COPY . .

RUN go test -tags=test ./...
