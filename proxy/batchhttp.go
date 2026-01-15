package proxy

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/miekg/dns"
)

// batchQueryRequest represents the custom batch DoH request format.
type batchQueryRequest struct {
	Token     string              `json:"token"`
	Timestamp string              `json:"timestamp"`
	ID        string              `json:"id"`
	Query     []batchQuerySection `json:"query"`
}

// batchQuerySection represents a section of the batch query.
type batchQuerySection struct {
	Type   []string `json:"type"`
	Domain []string `json:"domain"`
}

// batchQueryResponse represents a single DNS query result in the batch response.
type batchQueryResponse struct {
	Domain    string        `json:"domain"`
	Type      string        `json:"type"`
	Status    string        `json:"status"`
	Answers   []string      `json:"answers,omitempty"`
	TTL       uint32        `json:"ttl,omitempty"`
	RCode     string        `json:"rcode,omitempty"`
	QueryTime float64       `json:"query_time_ms"`
	Timestamp string        `json:"timestamp"`
	Error     string        `json:"error,omitempty"`
}

// validateJWT validates the JWT token using HS256 (HMAC-SHA256).
func validateJWT(token, secret string) (err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return fmt.Errorf("invalid jwt format: expected 3 parts, got %d", len(parts))
	}

	// Header and payload
	message := parts[0] + "." + parts[1]

	// Signature
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("decoding signature: %w", err)
	}

	// Compute HMAC
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(message))
	expectedSignature := mac.Sum(nil)

	// Compare signatures
	if !hmac.Equal(signature, expectedSignature) {
		return fmt.Errorf("invalid jwt signature")
	}

	return nil
}

// handleBatchQuery handles the custom batch DoH query format.
func (p *Proxy) handleBatchQuery(w http.ResponseWriter, r *http.Request) {
	p.logger.Debug("incoming batch query request", "url", r.URL)

	// Only accept POST for batch queries
	if r.Method != http.MethodPost {
		http.Error(w, "batch queries only accept POST", http.StatusMethodNotAllowed)
		return
	}

	// Read request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		p.logger.Debug("reading batch request body", slogutil.KeyError, err)
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}
	defer slogutil.CloseAndLog(r.Context(), p.logger, r.Body, slog.LevelDebug)

	// Parse JSON request
	var batchReq batchQueryRequest
	err = json.Unmarshal(body, &batchReq)
	if err != nil {
		p.logger.Debug("parsing batch json request", slogutil.KeyError, err)
		http.Error(w, "invalid json format", http.StatusBadRequest)
		return
	}

	// Validate JWT token
	if p.Config.HTTPBatchJWTSecret != "" {
		err = validateJWT(batchReq.Token, p.Config.HTTPBatchJWTSecret)
		if err != nil {
			p.logger.Debug("validating jwt token", slogutil.KeyError, err)
			http.Error(w, "invalid or expired token", http.StatusUnauthorized)
			return
		}
	}

	// Get client address
	raddr, _, err := remoteAddr(r, p.logger)
	if err != nil {
		p.logger.Debug("getting real ip", slogutil.KeyError, err)
	}

	// Process batch queries
	responses := make([]batchQueryResponse, 0)

	for _, section := range batchReq.Query {
		for _, domain := range section.Domain {
			for _, qtype := range section.Type {
				resp := p.processBatchQueryItem(domain, qtype, raddr, r)
				responses = append(responses, resp)
			}
		}
	}

	// Return JSON response
	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(responses)
	if err != nil {
		p.logger.Debug("encoding batch response", slogutil.KeyError, err)
	}
}

// processBatchQueryItem processes a single DNS query in the batch.
func (p *Proxy) processBatchQueryItem(
	domain string,
	qtype string,
	raddr netip.AddrPort,
	r *http.Request,
) (resp batchQueryResponse) {
	startTime := time.Now()

	resp = batchQueryResponse{
		Domain:    domain,
		Type:      qtype,
		Timestamp: startTime.Format(time.RFC3339),
	}

	// Convert query type string to uint16
	var dnsType uint16
	switch strings.ToUpper(qtype) {
	case "A":
		dnsType = dns.TypeA
	case "AAAA":
		dnsType = dns.TypeAAAA
	case "CNAME":
		dnsType = dns.TypeCNAME
	case "MX":
		dnsType = dns.TypeMX
	case "TXT":
		dnsType = dns.TypeTXT
	case "NS":
		dnsType = dns.TypeNS
	case "PTR":
		dnsType = dns.TypePTR
	case "SOA":
		dnsType = dns.TypeSOA
	case "SRV":
		dnsType = dns.TypeSRV
	default:
		resp.Status = "error"
		resp.Error = fmt.Sprintf("unsupported query type: %s", qtype)
		resp.QueryTime = float64(time.Since(startTime).Microseconds()) / 1000.0
		return resp
	}

	// Create DNS query
	req := &dns.Msg{}
	req.SetQuestion(dns.Fqdn(domain), dnsType)
	req.RecursionDesired = true

	// Create DNS context
	d := p.newDNSContext(ProtoHTTPS, req, raddr)
	d.HTTPRequest = r

	// Handle DNS request
	err := p.handleDNSRequest(d)
	if err != nil {
		resp.Status = "error"
		resp.Error = err.Error()
		resp.QueryTime = float64(time.Since(startTime).Microseconds()) / 1000.0
		return resp
	}

	// Process response
	if d.Res == nil {
		resp.Status = "error"
		resp.Error = "no response from upstream"
		resp.QueryTime = float64(time.Since(startTime).Microseconds()) / 1000.0
		return resp
	}

	resp.RCode = dns.RcodeToString[d.Res.Rcode]

	if d.Res.Rcode == dns.RcodeSuccess {
		resp.Status = "success"

		// Extract answers
		answers := make([]string, 0)
		var minTTL uint32 = 0

		for i, rr := range d.Res.Answer {
			switch v := rr.(type) {
			case *dns.A:
				answers = append(answers, v.A.String())
				if i == 0 || v.Hdr.Ttl < minTTL {
					minTTL = v.Hdr.Ttl
				}
			case *dns.AAAA:
				answers = append(answers, v.AAAA.String())
				if i == 0 || v.Hdr.Ttl < minTTL {
					minTTL = v.Hdr.Ttl
				}
			case *dns.CNAME:
				answers = append(answers, v.Target)
				if i == 0 || v.Hdr.Ttl < minTTL {
					minTTL = v.Hdr.Ttl
				}
			case *dns.MX:
				answers = append(answers, fmt.Sprintf("%d %s", v.Preference, v.Mx))
				if i == 0 || v.Hdr.Ttl < minTTL {
					minTTL = v.Hdr.Ttl
				}
			case *dns.TXT:
				answers = append(answers, strings.Join(v.Txt, " "))
				if i == 0 || v.Hdr.Ttl < minTTL {
					minTTL = v.Hdr.Ttl
				}
			case *dns.NS:
				answers = append(answers, v.Ns)
				if i == 0 || v.Hdr.Ttl < minTTL {
					minTTL = v.Hdr.Ttl
				}
			case *dns.PTR:
				answers = append(answers, v.Ptr)
				if i == 0 || v.Hdr.Ttl < minTTL {
					minTTL = v.Hdr.Ttl
				}
			case *dns.SOA:
				answers = append(answers, fmt.Sprintf("%s %s %d %d %d %d %d",
					v.Ns, v.Mbox, v.Serial, v.Refresh, v.Retry, v.Expire, v.Minttl))
				if i == 0 || v.Hdr.Ttl < minTTL {
					minTTL = v.Hdr.Ttl
				}
			case *dns.SRV:
				answers = append(answers, fmt.Sprintf("%d %d %d %s",
					v.Priority, v.Weight, v.Port, v.Target))
				if i == 0 || v.Hdr.Ttl < minTTL {
					minTTL = v.Hdr.Ttl
				}
			default:
				answers = append(answers, rr.String())
				if i == 0 || rr.Header().Ttl < minTTL {
					minTTL = rr.Header().Ttl
				}
			}
		}

		resp.Answers = answers
		resp.TTL = minTTL
	} else {
		resp.Status = "error"
	}

	resp.QueryTime = float64(time.Since(startTime).Microseconds()) / 1000.0

	return resp
}
