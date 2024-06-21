package proxy

import (
	"bytes"
	"encoding/binary"
	"log/slog"
	"testing"
	"time"

	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestRecursionDetector_Check(t *testing.T) {
	rd := newRecursionDetector(0, 2)

	const (
		recID  = 1234
		recTTL = time.Hour * 1
	)

	const nonRecID = recID * 2

	sampleQuestion := dns.Question{
		Name:  "some.domain",
		Qtype: dns.TypeAAAA,
	}
	sampleMsg := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id: recID,
		},
		Question: []dns.Question{sampleQuestion},
	}

	// Manually add the message with big ttl.
	key := msgToSignature(sampleMsg)
	expire := make([]byte, uint64sz)
	binary.BigEndian.PutUint64(expire, uint64(time.Now().Add(recTTL).UnixNano()))
	rd.recentRequests.Set(key, expire)

	// Add an expired message.
	sampleMsg.Id = nonRecID
	rd.add(sampleMsg)

	testCases := []struct {
		name      string
		questions []dns.Question
		id        uint16
		want      bool
	}{{
		name:      "recurrent",
		questions: []dns.Question{sampleQuestion},
		id:        recID,
		want:      true,
	}, {
		name:      "not_suspected",
		questions: []dns.Question{sampleQuestion},
		id:        recID + 1,
		want:      false,
	}, {
		name:      "expired",
		questions: []dns.Question{sampleQuestion},
		id:        nonRecID,
		want:      false,
	}, {
		name:      "empty",
		questions: []dns.Question{},
		id:        nonRecID,
		want:      false,
	}}

	for _, tc := range testCases {
		sampleMsg.Id = tc.id
		sampleMsg.Question = tc.questions
		t.Run(tc.name, func(t *testing.T) {
			detected := rd.check(sampleMsg)
			assert.Equal(t, tc.want, detected)
		})
	}
}

func TestRecursionDetector_Suspect(t *testing.T) {
	rd := newRecursionDetector(0, 1)

	testCases := []struct {
		msg  *dns.Msg
		name string
		want int
	}{{
		msg: &dns.Msg{
			MsgHdr: dns.MsgHdr{
				Id: 1234,
			},
			Question: []dns.Question{{
				Name:  "some.domain",
				Qtype: dns.TypeA,
			}},
		},
		name: "simple",
		want: 1,
	}, {
		msg:  &dns.Msg{},
		name: "unencumbered",
		want: 0,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Cleanup(rd.clear)
			rd.add(tc.msg)
			assert.Equal(t, tc.want, rd.recentRequests.Stats().Count)
		})
	}
}

// byteSink is a typed sink for benchmark results.
var byteSink []byte

func BenchmarkMsgToSignature(b *testing.B) {
	const name = "some.not.very.long.host.name"

	msg := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id: 1234,
		},
		Question: []dns.Question{{
			Name:  name,
			Qtype: dns.TypeAAAA,
		}},
	}

	b.Run("efficient", func(b *testing.B) {
		b.ReportAllocs()

		for range b.N {
			byteSink = msgToSignature(msg)
		}

		assert.NotEmpty(b, byteSink)
	})

	b.Run("inefficient", func(b *testing.B) {
		b.ReportAllocs()

		for range b.N {
			byteSink = msgToSignatureSlow(msg)
		}

		assert.NotEmpty(b, byteSink)
	})

	// goos: darwin
	// goarch: amd64
	// pkg: github.com/AdguardTeam/dnsproxy/proxy
	// cpu: Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz
	// BenchmarkMsgToSignature/efficient-12		17155314	68.84 ns/op		288 B/op	1 allocs/op
	// BenchmarkMsgToSignature/inefficient-12	460803		2367 ns/op		648 B/op	6 allocs/op
}

// msgToSignatureSlow converts msg into it's signature represented in bytes in
// the less efficient way.
//
// See BenchmarkMsgToSignature.
func msgToSignatureSlow(msg *dns.Msg) (sig []byte) {
	type msgSignature struct {
		name  [netutil.MaxDomainNameLen]byte
		id    uint16
		qtype uint16
	}

	b := bytes.NewBuffer(sig)
	q := msg.Question[0]
	signature := msgSignature{
		id:    msg.Id,
		qtype: q.Qtype,
	}
	copy(signature.name[:], q.Name)
	if err := binary.Write(b, binary.BigEndian, signature); err != nil {
		slog.Default().Debug("writing message signature", slogutil.KeyError, err)
	}

	return b.Bytes()
}
