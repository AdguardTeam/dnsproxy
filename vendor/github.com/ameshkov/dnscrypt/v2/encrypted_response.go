package dnscrypt

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"time"

	"github.com/ameshkov/dnscrypt/v2/xsecretbox"
	"golang.org/x/crypto/nacl/secretbox"
)

// EncryptedResponse - structure for encrypting/decrypting server responses
//
// <dnscrypt-response> ::= <resolver-magic> <nonce> <encrypted-response>
// <encrypted-response> ::= AE(<shared-key>, <nonce>, <resolver-response> <resolver-response-pad>)
type EncryptedResponse struct {
	// EsVersion - encryption to use
	EsVersion CryptoConstruction

	// Nonce - <nonce> ::= <client-nonce> <resolver-nonce>
	// <client-nonce> ::= the nonce sent by the client in the related query.
	Nonce [nonceSize]byte
}

// Encrypt - encrypts the server response
//
// EsVersion must be set.
// Nonce needs to be set to "client-nonce".
// This method will generate "resolver-nonce" and set it automatically.
func (r *EncryptedResponse) Encrypt(packet []byte, sharedKey [sharedKeySize]byte) ([]byte, error) {
	var response []byte

	// Step 1: generate nonce
	rand.Read(r.Nonce[12:16])
	binary.BigEndian.PutUint64(r.Nonce[16:nonceSize], uint64(time.Now().UnixNano()))

	// Unencrypted part of the query:
	response = append(response, resolverMagic[:]...)
	response = append(response, r.Nonce[:]...)

	// <resolver-response> <resolver-response-pad>
	padded := pad(packet)

	// <encrypted-response>
	nonce := r.Nonce
	if r.EsVersion == XChacha20Poly1305 {
		response = xsecretbox.Seal(response, nonce[:], padded, sharedKey[:])
	} else if r.EsVersion == XSalsa20Poly1305 {
		var xsalsaNonce [nonceSize]byte
		copy(xsalsaNonce[:], nonce[:])
		response = secretbox.Seal(response, padded, &xsalsaNonce, &sharedKey)
	} else {
		return nil, ErrEsVersion
	}

	return response, nil
}

// Decrypt - decrypts the server response
//
// EsVersion must be set.
func (r *EncryptedResponse) Decrypt(response []byte, sharedKey [sharedKeySize]byte) ([]byte, error) {
	headerLength := len(resolverMagic) + nonceSize
	if len(response) < headerLength+xsecretbox.TagSize+minDNSPacketSize {
		return nil, ErrInvalidResponse
	}

	// read and verify <resolver-magic>
	magic := [resolverMagicSize]byte{}
	copy(magic[:], response[:resolverMagicSize])
	if !bytes.Equal(magic[:], resolverMagic[:]) {
		return nil, ErrInvalidResolverMagic
	}

	// read nonce
	copy(r.Nonce[:], response[resolverMagicSize:nonceSize+resolverMagicSize])

	// read and decrypt <encrypted-response>
	encryptedResponse := response[nonceSize+resolverMagicSize:]
	var packet []byte
	var err error
	if r.EsVersion == XChacha20Poly1305 {
		packet, err = xsecretbox.Open(nil, r.Nonce[:], encryptedResponse, sharedKey[:])
		if err != nil {
			return nil, ErrInvalidResponse
		}
	} else if r.EsVersion == XSalsa20Poly1305 {
		var xsalsaServerNonce [24]byte
		copy(xsalsaServerNonce[:], r.Nonce[:])
		var ok bool
		packet, ok = secretbox.Open(nil, encryptedResponse, &xsalsaServerNonce, &sharedKey)
		if !ok {
			return nil, ErrInvalidResponse
		}
	} else {
		return nil, ErrEsVersion
	}

	packet, err = unpad(packet)
	if err != nil {
		return nil, ErrInvalidPadding
	}

	return packet, nil
}
