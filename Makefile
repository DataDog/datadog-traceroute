.PHONY: build
build:
	go build .

.PHONY: test
test:
	go test ./...

.PHONY: generate-mocks
generate-mocks:
	mockgen -source=publicip/publicip.go -destination=publicip/publicip_mockgen.go -package=publicip
	mockgen -source=packets/packet_sink.go -destination=packets/packet_sink_mockgen.go -package=packets
	mockgen -source=packets/packet_source.go -destination=packets/packet_source_mockgen.go -package=packets

