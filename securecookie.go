// Copyright 2012 The Gorilla Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package securecookie

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"time"
)

// Codec defines an interface to encode and decode cookie values.
type Codec interface {
	Encode(name string, value []byte) (string, error)
	Decode(name, value string) ([]byte, time.Time, error)
}

// New returns a new SecureCookie.
//
// hashKey is required, used to authenticate values using HMAC. Create it using
// GenerateRandomKey(). It is recommended to use a key with 32 or 64 bytes.
//
// blockKey is optional, used to encrypt values. Create it using
// GenerateRandomKey(). The key length must correspond to the block size
// of the encryption algorithm. For AES, used by default, valid lengths are
// 16, 24, or 32 bytes to select AES-128, AES-192, or AES-256.
func New(hashKey, blockKey []byte) *SecureCookie {
	s := &SecureCookie{
		hashKey:   hashKey,
		blockKey:  blockKey,
		hashFunc:  sha256.New,
		hashSize:  sha256.Size,
		maxLength: 4096,
	}
	if hashKey == nil {
		s.err = errors.New("securecookie: hash key is not set")
	}
	if blockKey != nil {
		s.BlockFunc(aes.NewCipher)
	}
	return s
}

// SecureCookie encodes and decodes authenticated and optionally encrypted
// cookie values.
type SecureCookie struct {
	hashKey   []byte
	hashFunc  func() hash.Hash
	hashSize  int
	blockKey  []byte
	block     cipher.Block
	maxLength int
	err       error
	// For testing purposes, the function that returns the current timestamp.
	// If not set, it will use time.Now().UTC().Unix().
	timeFunc func() int64
}

// MaxLength restricts the maximum length, in bytes, for the cookie value.
//
// Default is 4096, which is the maximum value accepted by Internet Explorer.
func (s *SecureCookie) MaxLength(value int) *SecureCookie {
	s.maxLength = value
	return s
}

// HashFunc sets the hash function used to create HMAC.
//
// Default is crypto/sha256.New.
func (s *SecureCookie) HashFunc(f func() hash.Hash) *SecureCookie {
	s.hashFunc = f
	s.hashSize = f().Size()
	return s
}

// BlockFunc sets the encryption function used to create a cipher.Block.
//
// Default is crypto/aes.New.
func (s *SecureCookie) BlockFunc(f func([]byte) (cipher.Block, error)) *SecureCookie {
	if s.blockKey == nil {
		s.err = errors.New("securecookie: block key is not set")
	} else if block, err := f(s.blockKey); err == nil {
		s.block = block
	} else {
		s.err = err
	}
	return s
}

// Encode encodes a cookie value.
//
// It serializes, optionally encrypts, signs with a message authentication code, and
// finally encodes the value.
func (s *SecureCookie) Encode(name string, value []byte) (string, error) {
	if s.err != nil {
		return "", s.err
	}
	if s.hashKey == nil {
		s.err = errors.New("securecookie: hash key is not set")
		return "", s.err
	}
	var err error
	// Encrypt (optional).
	if s.block != nil {
		if value, err = encrypt(s.block, value); err != nil {
			return "", err
		}
	}

	// Create value and MAC
	value = encodeValue(s.timestamp(), value, s.hashSize)
	h := hmac.New(s.hashFunc, s.hashKey)
	h.Write(value)
	value = h.Sum(value)
	// Encode to base64.
	value = encode(value)
	// Check length.
	if s.maxLength != 0 && len(value) > s.maxLength {
		return "", errors.New("securecookie: the value is too long")
	}
	// Done.
	return string(value), nil
}

func encodeValue(ts int64, value []byte, hashSize int) []byte {
	// ts int64, value, hmac
	val := make([]byte, 8+len(value), 8+len(value)+hashSize)
	binary.BigEndian.PutUint64(val, uint64(ts))
	copy(val[8:], value)
	return val
}

func decodeValue(value []byte) (int64, []byte) {
	t := binary.BigEndian.Uint64(value)
	return int64(t), value[8:]
}

// Decode decodes a cookie value.
//
// It decodes, verifies a message authentication code, optionally decrypts and
// finally deserializes the value.
//
// The name argument is the cookie name. It must be the same name used when
// it was stored. The value argument is the encoded cookie value. The dst
// argument is where the cookie will be decoded. It must be a pointer.
func (s *SecureCookie) Decode(name, value string) ([]byte, time.Time, error) {
	if s.err != nil {
		return nil, time.Time{}, s.err
	}
	if s.hashKey == nil {
		s.err = errors.New("securecookie: hash key is not set")
		return nil, time.Time{}, s.err
	}
	// Check length.
	if s.maxLength != 0 && len(value) > s.maxLength {
		return nil, time.Time{}, errors.New("securecookie: the value is too long")
	}
	// Decode from base64.
	b, err := decode([]byte(value))
	if err != nil {
		return nil, time.Time{}, err
	}
	// Verify MAC.
	mac := b[len(b)-s.hashSize:]
	b = b[:len(b)-s.hashSize]
	if err = verifyMac(hmac.New(s.hashFunc, s.hashKey), mac, b); err != nil {
		return nil, time.Time{}, err
	}
	t, b := decodeValue(b)
	if s.block != nil {
		if b, err = decrypt(s.block, b); err != nil {
			return nil, time.Time{}, err
		}
	}
	// Done.
	return b, time.Unix(t, 0).UTC(), nil
}

// timestamp returns the current timestamp, in seconds.
//
// For testing purposes, the function that generates the timestamp can be
// overridden. If not set, it will return time.Now().UTC().Unix().
func (s *SecureCookie) timestamp() int64 {
	if s.timeFunc == nil {
		return time.Now().UTC().Unix()
	}
	return s.timeFunc()
}

// verifyMac verifies that a message authentication code (MAC) is valid.
func verifyMac(h hash.Hash, mac []byte, value []byte) error {
	h.Write(value)
	if hmac.Equal(h.Sum(nil), mac) {
		return nil
	}
	return errors.New("securecookie: the value is not valid")
}

// Encryption -----------------------------------------------------------------

// encrypt encrypts a value using the given block in counter mode.
//
// A random initialization vector (http://goo.gl/zF67k) with the length of the
// block size is prepended to the resulting ciphertext.
func encrypt(block cipher.Block, value []byte) ([]byte, error) {
	iv := GenerateRandomKey(block.BlockSize())
	if iv == nil {
		return nil, errors.New("securecookie: failed to generate random iv")
	}
	// Encrypt it.
	stream := cipher.NewCTR(block, iv)
	dst := make([]byte, len(value))
	stream.XORKeyStream(dst, value)
	// Return iv + ciphertext.
	return append(iv, dst...), nil
}

// decrypt decrypts a value using the given block in counter mode.
//
// The value to be decrypted must be prepended by a initialization vector
// (http://goo.gl/zF67k) with the length of the block size.
func decrypt(block cipher.Block, value []byte) ([]byte, error) {
	size := block.BlockSize()
	if len(value) > size {
		// Extract iv.
		iv := value[:size]
		// Extract ciphertext.
		value = value[size:]
		// Decrypt it.
		stream := cipher.NewCTR(block, iv)
		stream.XORKeyStream(value, value)
		return value, nil
	}
	return nil, errors.New("securecookie: the value could not be decrypted")
}

// Encoding -------------------------------------------------------------------

// encode encodes a value using base64.
func encode(value []byte) []byte {
	encoded := make([]byte, base64.URLEncoding.EncodedLen(len(value)))
	base64.URLEncoding.Encode(encoded, value)
	return encoded
}

// decode decodes a cookie using base64.
func decode(value []byte) ([]byte, error) {
	decoded := make([]byte, base64.URLEncoding.DecodedLen(len(value)))
	b, err := base64.URLEncoding.Decode(decoded, value)
	if err != nil {
		return nil, err
	}
	return decoded[:b], nil
}

// Helpers --------------------------------------------------------------------

// GenerateRandomKey creates a random key with the given strength.
func GenerateRandomKey(strength int) []byte {
	k := make([]byte, strength)
	if _, err := io.ReadFull(rand.Reader, k); err != nil {
		return nil
	}
	return k
}

// CodecsFromPairs returns a slice of SecureCookie instances.
//
// It is a convenience function to create a list of codecs for key rotation.
func CodecsFromPairs(keyPairs ...[]byte) []Codec {
	codecs := make([]Codec, len(keyPairs)/2+len(keyPairs)%2)
	for i := 0; i < len(keyPairs); i += 2 {
		var blockKey []byte
		if i+1 < len(keyPairs) {
			blockKey = keyPairs[i+1]
		}
		codecs[i/2] = New(keyPairs[i], blockKey)
	}
	return codecs
}

// EncodeMulti encodes a cookie value using a group of codecs.
//
// The codecs are tried in order. Multiple codecs are accepted to allow
// key rotation.
func EncodeMulti(name string, value []byte, codecs ...Codec) (string, error) {
	var errors MultiError
	for _, codec := range codecs {
		if encoded, err := codec.Encode(name, value); err == nil {
			return encoded, nil
		} else {
			errors = append(errors, err)
		}
	}
	return "", errors
}

// DecodeMulti decodes a cookie value using a group of codecs.
//
// The codecs are tried in order. Multiple codecs are accepted to allow
// key rotation.
func DecodeMulti(name string, value string, codecs ...Codec) ([]byte, time.Time, error) {
	var errors MultiError
	for _, codec := range codecs {
		if v, t, err := codec.Decode(name, value); err == nil {
			return v, t, nil
		} else {
			errors = append(errors, err)
		}
	}
	return nil, time.Time{}, errors
}

// MultiError groups multiple errors.
type MultiError []error

func (m MultiError) Error() string {
	s, n := "", 0
	for _, e := range m {
		if e != nil {
			if n == 0 {
				s = e.Error()
			}
			n++
		}
	}
	switch n {
	case 0:
		return "(0 errors)"
	case 1:
		return s
	case 2:
		return s + " (and 1 other error)"
	}
	return fmt.Sprintf("%s (and %d other errors)", s, n-1)
}
