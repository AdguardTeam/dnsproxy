package dnscrypt

import (
	"github.com/AdguardTeam/golibs/log"
	"github.com/miekg/dns"
)

// Server - a simple DNSCrypt server implementation
type Server struct {
	// ProviderName - DNSCrypt provider name
	ProviderName string

	// ResolverCert - contains resolver certificate.
	ResolverCert *Cert

	// Handler to invoke. If nil, uses DefaultHandler.
	Handler Handler
}

// serveDNS - serves DNS response
func (s *Server) serveDNS(rw ResponseWriter, r *dns.Msg) {
	if r == nil || len(r.Question) != 1 || r.Response {
		log.Tracef("Invalid query: %v", r)
		return
	}

	log.Tracef("Handling a DNS query: %s", r.Question[0].Name)

	handler := s.Handler
	if handler == nil {
		handler = DefaultHandler
	}

	err := handler.ServeDNS(rw, r)
	if err != nil {
		log.Tracef("Error while handing a DNS query: %v", err)

		reply := &dns.Msg{}
		reply.SetRcode(r, dns.RcodeServerFailure)
		_ = rw.WriteMsg(reply)
	}
}

// encrypt - encrypts DNSCrypt response
func (s *Server) encrypt(m *dns.Msg, q EncryptedQuery) ([]byte, error) {
	r := EncryptedResponse{
		EsVersion: q.EsVersion,
		Nonce:     q.Nonce,
	}
	packet, err := m.Pack()
	if err != nil {
		return nil, err
	}

	sharedKey, err := computeSharedKey(q.EsVersion, &s.ResolverCert.ResolverSk, &q.ClientPk)
	if err != nil {
		return nil, err
	}

	return r.Encrypt(packet, sharedKey)
}

// decrypt - decrypts the incoming message and returns a DNS message to process
func (s *Server) decrypt(b []byte) (*dns.Msg, EncryptedQuery, error) {
	q := EncryptedQuery{
		EsVersion:   s.ResolverCert.EsVersion,
		ClientMagic: s.ResolverCert.ClientMagic,
	}
	msg, err := q.Decrypt(b, s.ResolverCert.ResolverSk)
	if err != nil {
		// Failed to decrypt, dropping it
		return nil, q, err
	}

	r := new(dns.Msg)
	err = r.Unpack(msg)
	if err != nil {
		// Invalid DNS message, ignore
		return nil, q, err
	}

	return r, q, nil
}

// handleHandshake - handles a TXT request that requests certificate data
func (s *Server) handleHandshake(b []byte, certTxt string) ([]byte, error) {
	m := new(dns.Msg)
	err := m.Unpack(b)
	if err != nil {
		// Not a handshake, just ignore it
		return nil, err
	}

	if len(m.Question) != 1 || m.Response {
		// Invalid query
		return nil, ErrInvalidQuery
	}

	q := m.Question[0]
	providerName := dns.Fqdn(s.ProviderName)
	if q.Qtype != dns.TypeTXT || q.Name != providerName {
		// Invalid provider name or type, doing nothing
		return nil, ErrInvalidQuery
	}

	reply := new(dns.Msg)
	reply.SetReply(m)
	txt := &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   q.Name,
			Rrtype: dns.TypeTXT,
			Ttl:    60, // use 60 seconds by default, but it shouldn't matter
			Class:  dns.ClassINET,
		},
		Txt: []string{
			certTxt,
		},
	}
	reply.Answer = append(reply.Answer, txt)
	return reply.Pack()
}

// validate - checks if the Server config is properly set
func (s *Server) validate() bool {
	if s.ResolverCert == nil {
		log.Error("ResolverCert must be set")
		return false
	}

	if !s.ResolverCert.VerifyDate() {
		log.Error("ResolverCert date is not valid")
		return false
	}

	if s.ProviderName == "" {
		log.Error("ProviderName must be set")
		return false
	}

	return true
}
