module github.com/fcchbjm/dnsproxy

go 1.26.1

require (
	github.com/AdguardTeam/golibs v0.35.10
	github.com/ameshkov/dnscrypt/v2 v2.4.0
	github.com/ameshkov/dnsstamps v1.0.3
	github.com/beefsack/go-rate v0.0.0-20220214233405-116f4ca011a0
	github.com/bluele/gcache v0.0.2
	github.com/miekg/dns v1.1.72
	github.com/patrickmn/go-cache v2.1.0+incompatible
	// TODO(s.chzhen):  Update after investigation of the 0-RTT bug/behavior
	// when TestUpstreamDoH_serverRestart/http3/second_try keeps failing.
	github.com/quic-go/quic-go v0.59.0
	github.com/stretchr/testify v1.11.1
	golang.org/x/exp v0.0.0-20260312153236-7ab1446f8b90 // indirect
	golang.org/x/net v0.52.0
	golang.org/x/sys v0.42.0
	gonum.org/v1/gonum v0.17.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	cloud.google.com/go v0.123.0 // indirect
	cloud.google.com/go/auth v0.18.1 // indirect
	cloud.google.com/go/compute/metadata v0.9.0 // indirect
	github.com/BurntSushi/toml v1.6.0 // indirect
	github.com/anthropics/anthropic-sdk-go v1.19.0 // indirect
	github.com/ccojocar/zxcvbn-go v1.0.4 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/fzipp/gocyclo v0.6.0 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/golangci/misspell v0.7.0 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/google/renameio/v2 v2.0.2 // indirect
	github.com/google/s2a-go v0.1.9 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.3.11 // indirect
	github.com/googleapis/gax-go/v2 v2.16.0 // indirect
	github.com/gookit/color v1.6.0 // indirect
	github.com/gordonklaus/ineffassign v0.2.0 // indirect
	github.com/gorilla/websocket v1.5.3 // indirect
	github.com/jstemmer/go-junit-report/v2 v2.1.0 // indirect
	github.com/kisielk/errcheck v1.9.0 // indirect
	github.com/openai/openai-go/v3 v3.17.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/robfig/cron/v3 v3.0.1 // indirect
	github.com/rogpeppe/go-internal v1.14.1 // indirect
	github.com/securego/gosec/v2 v2.22.12-0.20260119173857-b579523bf6db // indirect
	github.com/tidwall/gjson v1.18.0 // indirect
	github.com/tidwall/match v1.2.0 // indirect
	github.com/tidwall/pretty v1.2.1 // indirect
	github.com/tidwall/sjson v1.2.5 // indirect
	github.com/uudashr/gocognit v1.2.0 // indirect
	github.com/xo/terminfo v0.0.0-20220910002029-abceb7e1c41e // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.64.0 // indirect
	go.opentelemetry.io/otel v1.40.0 // indirect
	go.opentelemetry.io/otel/metric v1.40.0 // indirect
	go.opentelemetry.io/otel/trace v1.40.0 // indirect
	go.uber.org/mock v0.6.0 // indirect
	go.yaml.in/yaml/v3 v3.0.4 // indirect
	golang.org/x/crypto v0.49.0 // indirect
	golang.org/x/exp/typeparams v0.0.0-20260112195511-716be5621a96 // indirect
	golang.org/x/mod v0.34.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/telemetry v0.0.0-20260311193753-579e4da9a98c // indirect
	golang.org/x/term v0.41.0 // indirect
	golang.org/x/text v0.35.0 // indirect
	golang.org/x/tools v0.43.0 // indirect
	golang.org/x/vuln v1.1.4 // indirect
	google.golang.org/genai v1.43.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260128011058-8636f8732409 // indirect
	google.golang.org/grpc v1.78.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
	honnef.co/go/tools v0.6.1 // indirect
	mvdan.cc/editorconfig v0.3.0 // indirect
	mvdan.cc/gofumpt v0.9.2 // indirect
	mvdan.cc/sh/v3 v3.12.0 // indirect
	mvdan.cc/unparam v0.0.0-20251027182757-5beb8c8f8f15 // indirect
)

// NOTE:  Keep in sync with .gitignore.
ignore (
	./bin/
	./test-reports/
	./tmp/
)

tool (
	github.com/fzipp/gocyclo/cmd/gocyclo
	github.com/golangci/misspell/cmd/misspell
	github.com/gordonklaus/ineffassign
	github.com/jstemmer/go-junit-report/v2
	github.com/kisielk/errcheck
	github.com/securego/gosec/v2/cmd/gosec
	github.com/uudashr/gocognit/cmd/gocognit
	golang.org/x/tools/go/analysis/passes/fieldalignment/cmd/fieldalignment
	golang.org/x/tools/go/analysis/passes/nilness/cmd/nilness
	golang.org/x/tools/go/analysis/passes/shadow/cmd/shadow
	golang.org/x/vuln/cmd/govulncheck
	honnef.co/go/tools/cmd/staticcheck
	mvdan.cc/gofumpt
	mvdan.cc/sh/v3/cmd/shfmt
	mvdan.cc/unparam
)
