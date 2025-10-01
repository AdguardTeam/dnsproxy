module github.com/AdguardTeam/dnsproxy

go 1.25.1

require (
	github.com/AdguardTeam/golibs v0.34.1
	github.com/ameshkov/dnscrypt/v2 v2.4.0
	github.com/ameshkov/dnsstamps v1.0.3
	github.com/beefsack/go-rate v0.0.0-20220214233405-116f4ca011a0
	github.com/bluele/gcache v0.0.2
	github.com/miekg/dns v1.1.66
	github.com/patrickmn/go-cache v2.1.0+incompatible
	// TODO(s.chzhen):  Update after investigation of the 0-RTT bug/behavior
	// when TestUpstreamDoH_serverRestart/http3/second_try keeps failing.
	github.com/quic-go/quic-go v0.53.0
	github.com/stretchr/testify v1.11.1
	golang.org/x/exp v0.0.0-20250813145105-42675adae3e6 // indirect
	golang.org/x/net v0.44.0
	golang.org/x/sys v0.36.0
	gonum.org/v1/gonum v0.16.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	cloud.google.com/go v0.123.0 // indirect
	cloud.google.com/go/auth v0.16.5 // indirect
	cloud.google.com/go/compute/metadata v0.9.0 // indirect
	github.com/BurntSushi/toml v1.5.0 // indirect
	github.com/anthropics/anthropic-sdk-go v1.13.0 // indirect
	github.com/ccojocar/zxcvbn-go v1.0.4 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/fzipp/gocyclo v0.6.0 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/golangci/misspell v0.7.0 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/google/renameio/v2 v2.0.0 // indirect
	github.com/google/s2a-go v0.1.9 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.3.6 // indirect
	github.com/googleapis/gax-go/v2 v2.15.0 // indirect
	github.com/gookit/color v1.6.0 // indirect
	github.com/gordonklaus/ineffassign v0.2.0 // indirect
	github.com/gorilla/websocket v1.5.3 // indirect
	github.com/jstemmer/go-junit-report/v2 v2.1.0 // indirect
	github.com/kisielk/errcheck v1.9.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/quic-go/qpack v0.5.1 // indirect
	github.com/robfig/cron/v3 v3.0.1 // indirect
	github.com/rogpeppe/go-internal v1.14.1 // indirect
	github.com/securego/gosec/v2 v2.22.9 // indirect
	github.com/tidwall/gjson v1.18.0 // indirect
	github.com/tidwall/match v1.2.0 // indirect
	github.com/tidwall/pretty v1.2.1 // indirect
	github.com/tidwall/sjson v1.2.5 // indirect
	github.com/uudashr/gocognit v1.2.0 // indirect
	github.com/xo/terminfo v0.0.0-20220910002029-abceb7e1c41e // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.63.0 // indirect
	go.opentelemetry.io/otel v1.38.0 // indirect
	go.opentelemetry.io/otel/metric v1.38.0 // indirect
	go.opentelemetry.io/otel/trace v1.38.0 // indirect
	go.uber.org/mock v0.5.2 // indirect
	golang.org/x/crypto v0.42.0 // indirect
	golang.org/x/exp/typeparams v0.0.0-20250911091902-df9299821621 // indirect
	golang.org/x/mod v0.28.0 // indirect
	golang.org/x/sync v0.17.0 // indirect
	golang.org/x/telemetry v0.0.0-20250930190813-8e6447515a8c // indirect
	golang.org/x/term v0.35.0 // indirect
	golang.org/x/text v0.29.0 // indirect
	golang.org/x/tools v0.37.0 // indirect
	golang.org/x/vuln v1.1.4 // indirect
	google.golang.org/genai v1.26.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250929231259-57b25ae835d4 // indirect
	google.golang.org/grpc v1.75.1 // indirect
	google.golang.org/protobuf v1.36.9 // indirect
	honnef.co/go/tools v0.6.1 // indirect
	mvdan.cc/editorconfig v0.3.0 // indirect
	mvdan.cc/gofumpt v0.9.1 // indirect
	mvdan.cc/sh/v3 v3.12.0 // indirect
	mvdan.cc/unparam v0.0.0-20250301125049-0df0534333a4 // indirect
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
