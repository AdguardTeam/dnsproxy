package dnscrypt

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"time"

	"github.com/ameshkov/dnscrypt/v2/xsecretbox"
	"golang.org/x/crypto/nacl/secretbox"
)

// EncryptedQuery is a structure for encrypting and decrypting client queries
//
// <dnscrypt-query> ::= <client-magic> <client-pk> <client-nonce> <encrypted-query>
// <encrypted-query> ::= AE(<shared-key> <client-nonce> <client-nonce-pad>, <client-query> <client-query-pad>)
type EncryptedQuery struct {
	// EsVersion is the encryption to use
	EsVersion CryptoConstruction

	// ClientMagic is a 8 byte identifier for the resolver certificate
	// chosen by the client.
	ClientMagic [clientMagicSize]byte

	// ClientPk is the client's public key
	ClientPk [keySize]byte

	// With a 24 bytes nonce, a question sent by a DNSCrypt client must be
	// encrypted using the shared secret, and a nonce constructed as follows:
	// 12 bytes chosen by the client followed by 12 NUL (0) bytes.
	//
	// The client's half of the nonce can include a timestamp in addition to a
	// counter or to random bytes, so that when a response is received, the
	// client can use this timestamp to immediately discard responses to
	// queries that have been sent too long ago, or dated in the future.
	Nonce [nonceSize]byte
}

// Encrypt encrypts the specified DNS query, returns encrypted data ready to be sent.
//
// Note that this method will generate a random nonce automatically.
//
// The following fields must be set before calling this method:
// * EsVersion -- to encrypt the query
// * ClientMagic -- to send it with the query
// * ClientPk -- to send it with the query
func (q *EncryptedQuery) Encrypt(packet []byte, sharedKey [sharedKeySize]byte) ([]byte, error) {
	var query []byte

	// Step 1: generate nonce
	binary.BigEndian.PutUint64(q.Nonce[:8], uint64(time.Now().UnixNano()))
	rand.Read(q.Nonce[8:12])

	// Unencrypted part of the query:
	// <client-magic> <client-pk> <client-nonce>
	query = append(query, q.ClientMagic[:]...)
	query = append(query, q.ClientPk[:]...)
	query = append(query, q.Nonce[:nonceSize/2]...)

	// <client-query> <client-query-pad>
	padded := pad(packet)

	// <encrypted-query>
	nonce := q.Nonce
	if q.EsVersion == XChacha20Poly1305 {
		query = xsecretbox.Seal(query, nonce[:], padded, sharedKey[:])
	} else if q.EsVersion == XSalsa20Poly1305 {
		var xsalsaNonce [nonceSize]byte
		copy(xsalsaNonce[:], nonce[:])
		query = secretbox.Seal(query, padded, &xsalsaNonce, &sharedKey)
	} else {
		return nil, ErrEsVersion
	}

	if len(query) > maxQueryLen {
		return nil, ErrQueryTooLarge
	}

	return query, nil
}

// Decrypt decrypts the client query, returns decrypted DNS packet.
//
// Please note, that before calling this method the following fields must be set:
// * ClientMagic -- to verify the query
// * EsVersion -- to decrypt
func (q *EncryptedQuery) Decrypt(query []byte, serverSecretKey [keySize]byte) ([]byte, error) {
	headerLength := clientMagicSize + keySize + nonceSize/2
	if len(query) < headerLength+xsecretbox.TagSize+minDNSPacketSize {
		return nil, ErrInvalidQuery
	}

	// read and verify <client-magic>
	clientMagic := [clientMagicSize]byte{}
	copy(clientMagic[:], query[:clientMagicSize])
	if !bytes.Equal(clientMagic[:], q.ClientMagic[:]) {
		return nil, ErrInvalidClientMagic
	}

	// read <client-pk>
	idx := clientMagicSize
	copy(q.ClientPk[:keySize], query[idx:idx+keySize])

	// generate server shared key
	sharedKey, err := computeSharedKey(q.EsVersion, &serverSecretKey, &q.ClientPk)
	if err != nil {
		return nil, err
	}

	// read <client-nonce>
	idx = idx + keySize
	copy(q.Nonce[:nonceSize/2], query[idx:idx+nonceSize/2])

	// read and decrypt <encrypted-query>
	idx = idx + nonceSize/2
	encryptedQuery := query[idx:]
	var packet []byte
	if q.EsVersion == XChacha20Poly1305 {
		packet, err = xsecretbox.Open(nil, q.Nonce[:], encryptedQuery, sharedKey[:])
		if err != nil {
			return nil, ErrInvalidQuery
		}
	} else if q.EsVersion == XSalsa20Poly1305 {
		var xsalsaServerNonce [24]byte
		copy(xsalsaServerNonce[:], q.Nonce[:])
		var ok bool
		packet, ok = secretbox.Open(nil, encryptedQuery, &xsalsaServerNonce, &sharedKey)
		if !ok {
			return nil, ErrInvalidQuery
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
