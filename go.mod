module github.com/DataDog/datadog-traceroute

go 1.25.6

toolchain go1.26.4

require (
	github.com/DataDog/datadog-agent/pkg/network/driver v0.81.0-devel.0.20260603133502-a41610237dba
	github.com/cenkalti/backoff/v5 v5.0.3
	github.com/golang/mock v1.6.0
	github.com/google/gopacket v1.1.19
	github.com/google/uuid v1.6.0
	github.com/patrickmn/go-cache v2.1.0+incompatible
	github.com/pkg/errors v0.9.1
	github.com/spf13/cobra v1.10.2
	github.com/stretchr/testify v1.11.1
	github.com/vishvananda/netlink v1.3.1
	github.com/vishvananda/netns v0.0.5
	golang.org/x/net v0.55.0
	golang.org/x/sync v0.20.0
	golang.org/x/sys v0.45.0
)

require (
	github.com/DataDog/datadog-agent/comp/core/flare/builder v0.81.0-devel.0.20260603133502-a41610237dba // indirect
	github.com/DataDog/datadog-agent/comp/core/flare/types v0.81.0-devel.0.20260603133502-a41610237dba // indirect
	github.com/DataDog/datadog-agent/comp/core/telemetry v0.81.0-devel.0.20260603133502-a41610237dba // indirect
	github.com/DataDog/datadog-agent/comp/def v0.81.0-devel.0.20260603133502-a41610237dba // indirect
	github.com/DataDog/datadog-agent/pkg/template v0.81.0-devel.0.20260603133502-a41610237dba // indirect
	github.com/DataDog/datadog-agent/pkg/util/fxutil v0.81.0-devel.0.20260603133502-a41610237dba // indirect
	github.com/DataDog/datadog-agent/pkg/util/log v0.81.0-devel.0.20260603133502-a41610237dba // indirect
	github.com/DataDog/datadog-agent/pkg/util/option v0.81.0-devel.0.20260603133502-a41610237dba // indirect
	github.com/DataDog/datadog-agent/pkg/util/scrubber v0.81.0-devel.0.20260603133502-a41610237dba // indirect
	github.com/DataDog/datadog-agent/pkg/util/winutil v0.81.0-devel.0.20260603133502-a41610237dba // indirect
	github.com/DataDog/datadog-agent/pkg/version v0.81.0-devel.0.20260603133502-a41610237dba // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/prometheus/client_golang v1.23.3-0.20251103151724-a5ae20370e5e // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/common v0.68.0 // indirect
	github.com/prometheus/procfs v0.20.1 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	go.uber.org/atomic v1.11.0 // indirect
	go.uber.org/dig v1.19.0 // indirect
	go.uber.org/fx v1.24.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.28.0 // indirect
	go.yaml.in/yaml/v3 v3.0.4 // indirect
	golang.org/x/time v0.15.0 // indirect
	google.golang.org/protobuf v1.36.12-0.20260116114154-8c4c4ae446ca // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/DataDog/datadog-agent/comp/core/flare/types v0.0.0-00010101000000-000000000000 => github.com/DataDog/datadog-agent/comp/core/flare/types v0.81.0-devel.0.20260603133502-a41610237dba
