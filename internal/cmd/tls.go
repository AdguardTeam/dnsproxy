package cmd

import (
	"crypto/tls"
	"fmt"
	"os"
)

// NewTLSConfig returns the TLS config that includes a certificate.  Use it for
// server TLS configuration or for a client certificate.  If caPath is empty,
// system CAs will be used.
func newTLSConfig(conf *configuration) (c *tls.Config, err error) {
	// Set default TLS min/max versions
	tlsMinVersion := tls.VersionTLS10
	tlsMaxVersion := tls.VersionTLS13

	switch conf.TLSMinVersion {
	case 1.1:
		tlsMinVersion = tls.VersionTLS11
	case 1.2:
		tlsMinVersion = tls.VersionTLS12
	case 1.3:
		tlsMinVersion = tls.VersionTLS13
	}

	switch conf.TLSMaxVersion {
	case 1.0:
		tlsMaxVersion = tls.VersionTLS10
	case 1.1:
		tlsMaxVersion = tls.VersionTLS11
	case 1.2:
		tlsMaxVersion = tls.VersionTLS12
	}

	cert, err := loadX509KeyPair(conf.TLSCertPath, conf.TLSKeyPath)
	if err != nil {
		return nil, fmt.Errorf("loading TLS cert: %s", err)
	}

	// #nosec G402 -- TLS MinVersion is configured by user.
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   uint16(tlsMinVersion),
		MaxVersion:   uint16(tlsMaxVersion),
	}, nil
}

// loadX509KeyPair reads and parses a public/private key pair from a pair of
// files.  The files must contain PEM encoded data.  The certificate file may
// contain intermediate certificates following the leaf certificate to form a
// certificate chain.  On successful return, Certificate.Leaf will be nil
// because the parsed form of the certificate is not retained.
func loadX509KeyPair(certFile, keyFile string) (crt tls.Certificate, err error) {
	// #nosec G304 -- Trust the file path that is given in the configuration.
	certPEMBlock, err := os.ReadFile(certFile)
	if err != nil {
		return tls.Certificate{}, err
	}

	// #nosec G304 -- Trust the file path that is given in the configuration.
	keyPEMBlock, err := os.ReadFile(keyFile)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.X509KeyPair(certPEMBlock, keyPEMBlock)
}
