package upstream

import (
	"sync"
	"testing"

	"github.com/AdguardTeam/dnsproxy/internal/bootstrap"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/stretchr/testify/assert"
)

func TestDNSOverHTTPS_resetClient_H3NoError(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name                string
		resetErr            error
		wantQUICConfigReset bool
	}{{
		name: "handles_H3_NO_ERROR_gracefully",
		resetErr: &quic.ApplicationError{
			ErrorCode: quic.ApplicationErrorCode(http3.ErrCodeNoError),
		},
		wantQUICConfigReset: true,
	}, {
		name:                "resets_connection_on_H3_NO_ERROR",
		resetErr:            errors.Error("some error with H3_NO_ERROR"),
		wantQUICConfigReset: false,
	}, {
		name:                "retries_on_H3_NO_ERROR",
		resetErr:            quic.Err0RTTRejected,
		wantQUICConfigReset: true,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			u := &dnsOverHTTPS{
				quicConf:   &quic.Config{},
				quicConfMu: &sync.Mutex{},
				clientMu:   &sync.Mutex{},
				logger:     testLogger,
				getDialer: func() (bootstrap.DialHandler, error) {
					return nil, errors.Error("no dialer")
				},
			}

			originalConf := u.quicConf

			u.resetClient(tc.resetErr)

			if tc.wantQUICConfigReset {
				assert.NotSame(t, originalConf, u.quicConf)
			} else {
				assert.Same(t, originalConf, u.quicConf)
			}
		})
	}
}
