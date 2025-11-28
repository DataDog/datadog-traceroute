.PHONY: build
build:
	go build -o datadog-traceroute .

.PHONY: test
test:
	go test ./...

