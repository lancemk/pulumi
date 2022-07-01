// Copyright 2016-2022, Pulumi Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package config

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/common/util/contract"
	"golang.org/x/crypto/pbkdf2"
)

// Encrypter encrypts plaintext into its encrypted ciphertext.
type Encrypter interface {
	EncryptValue(plaintext string) (string, error)
	EncryptValueWithContext(ctx context.Context, plaintext string) (string, error)
}

// Decrypter decrypts encrypted ciphertext to its plaintext representation.
type Decrypter interface {
	DecryptValue(ciphertext string) (string, error)

	DecryptValueWithContext(ctx context.Context, ciphertext string) (string, error)

	// BulkDecrypt supports bulk decryption of secrets.
	BulkDecrypt(ciphertexts []string) (map[string]string, error)

	BulkDecryptWithContext(ctx context.Context, ciphertexts []string) (map[string]string, error)
}

// Crypter can both encrypt and decrypt values.
type Crypter interface {
	Encrypter
	Decrypter
}

// A nopCrypter simply returns the ciphertext as-is.
type nopCrypter struct{}

var NopDecrypter Decrypter = nopCrypter{}
var NopEncrypter Encrypter = nopCrypter{}

func (nopCrypter) DecryptValueWithContext(ctx context.Context, ciphertext string) (string, error) {
	return ciphertext, nil
}

func (nopCrypter) BulkDecryptWithContext(ctx context.Context, ciphertexts []string) (map[string]string, error) {
	return DefaultBulkDecryptWithContext(ctx, NopDecrypter, ciphertexts)
}

func (nopCrypter) EncryptValueWithContext(ctx context.Context, plaintext string) (string, error) {
	return plaintext, nil
}

func (nop nopCrypter) DecryptValue(ciphertext string) (string, error) {
	return nop.DecryptValueWithContext(context.Background(), ciphertext)
}

func (nop nopCrypter) BulkDecrypt(ciphertexts []string) (map[string]string, error) {
	return nop.BulkDecryptWithContext(context.Background(), ciphertexts)
}

func (nop nopCrypter) EncryptValue(plaintext string) (string, error) {
	return nop.EncryptValueWithContext(context.Background(), plaintext)
}

// TrackingDecrypter is a Decrypter that keeps track if decrypted values, which
// can be retrieved via SecureValues().
type TrackingDecrypter interface {
	Decrypter
	SecureValues() []string
}

// NewTrackingDecrypter returns a Decrypter that keeps track of decrypted values.
func NewTrackingDecrypter(decrypter Decrypter) TrackingDecrypter {
	return &trackingDecrypter{decrypter: decrypter}
}

type trackingDecrypter struct {
	decrypter    Decrypter
	secureValues []string
}

func (t *trackingDecrypter) DecryptValueWithContext(ctx context.Context, ciphertext string) (string, error) {
	v, err := t.decrypter.DecryptValue(ciphertext)
	if err != nil {
		return "", err
	}
	t.secureValues = append(t.secureValues, v)
	return v, nil
}

func (t *trackingDecrypter) BulkDecryptWithContext(ctx context.Context, ciphertexts []string) (map[string]string, error) {
	return DefaultBulkDecryptWithContext(ctx, t, ciphertexts)
}

func (t *trackingDecrypter) SecureValues() []string {
	return t.secureValues
}

func (t *trackingDecrypter) DecryptValue(ciphertext string) (string, error) {
	return t.DecryptValueWithContext(context.Background(), ciphertext)
}

func (t *trackingDecrypter) BulkDecrypt(ciphertexts []string) (map[string]string, error) {
	return t.BulkDecryptWithContext(context.Background(), ciphertexts)
}

// BlindingCrypter returns a Crypter that instead of decrypting or encrypting data, just returns "[secret]", it can
// be used when you want to display configuration information to a user but don't want to prompt for a password
// so secrets will not be decrypted or encrypted.
var BlindingCrypter Crypter = blindingCrypter{}

// NewBlindingDecrypter returns a blinding decrypter.
func NewBlindingDecrypter() Decrypter {
	return blindingCrypter{}
}

type blindingCrypter struct{}

func (b blindingCrypter) DecryptValueWithContext(ctx context.Context, _ string) (string, error) {
	return "[secret]", nil //nolint:goconst
}

func (b blindingCrypter) EncryptValueWithContext(ctx context.Context, plaintext string) (string, error) {
	return "[secret]", nil
}

func (b blindingCrypter) BulkDecryptWithContext(ctx context.Context, ciphertexts []string) (map[string]string, error) {
	return DefaultBulkDecryptWithContext(ctx, b, ciphertexts)
}

func (b blindingCrypter) DecryptValue(ciphertext string) (string, error) {
	return b.DecryptValueWithContext(context.Background(), ciphertext)
}

func (b blindingCrypter) BulkDecrypt(ciphertexts []string) (map[string]string, error) {
	return b.BulkDecryptWithContext(context.Background(), ciphertexts)
}

func (b blindingCrypter) EncryptValue(plaintext string) (string, error) {
	return b.EncryptValueWithContext(context.Background(), plaintext)
}

// NewPanicCrypter returns a new config crypter that will panic if used.
func NewPanicCrypter() Crypter {
	return &panicCrypter{}
}

type panicCrypter struct{}

func (p panicCrypter) EncryptValueWithContext(ctx context.Context, _ string) (string, error) {
	panic("attempt to encrypt value")
}

func (p panicCrypter) DecryptValueWithContext(ctx context.Context, _ string) (string, error) {
	panic("attempt to decrypt value")
}

func (p panicCrypter) BulkDecryptWithContext(ctx context.Context, ciphertexts []string) (map[string]string, error) {
	panic("attempt to bulk decrypt values")
}

func (p panicCrypter) DecryptValue(ciphertext string) (string, error) {
	return p.DecryptValueWithContext(context.Background(), ciphertext)
}

func (p panicCrypter) BulkDecrypt(ciphertexts []string) (map[string]string, error) {
	return p.BulkDecryptWithContext(context.Background(), ciphertexts)
}

func (p panicCrypter) EncryptValue(plaintext string) (string, error) {
	return p.EncryptValueWithContext(context.Background(), plaintext)
}

// NewSymmetricCrypter creates a crypter that encrypts and decrypts values using AES-256-GCM.  The nonce is stored with
// the value itself as a pair of base64 values separated by a colon and a version tag `v1` is prepended.
func NewSymmetricCrypter(key []byte) Crypter {
	contract.Requiref(len(key) == SymmetricCrypterKeyBytes, "key", "AES-256-GCM needs a 32 byte key")
	return &symmetricCrypter{key}
}

// NewSymmetricCrypterFromPassphrase uses a passphrase and salt to generate a key, and then returns a crypter using it.
func NewSymmetricCrypterFromPassphrase(phrase string, salt []byte) Crypter {
	// Generate a key using PBKDF2 to slow down attempts to crack it.  1,000,000 iterations was chosen because it
	// took a little over a second on an i7-7700HQ Quad Core processor
	key := pbkdf2.Key([]byte(phrase), salt, 1000000, SymmetricCrypterKeyBytes, sha256.New)
	return NewSymmetricCrypter(key)
}

// SymmetricCrypterKeyBytes is the required key size in bytes.
const SymmetricCrypterKeyBytes = 32

type symmetricCrypter struct {
	key []byte
}

func (s symmetricCrypter) EncryptValueWithContext(ctx context.Context, value string) (string, error) {
	secret, nonce := encryptAES256GCGM(value, s.key)
	return fmt.Sprintf("v1:%s:%s",
		base64.StdEncoding.EncodeToString(nonce), base64.StdEncoding.EncodeToString(secret)), nil
}

func (s symmetricCrypter) DecryptValueWithContext(ctx context.Context, value string) (string, error) {
	vals := strings.Split(value, ":")

	if len(vals) != 3 {
		return "", errors.New("bad value")
	}

	if vals[0] != "v1" {
		return "", errors.New("unknown value version")
	}

	nonce, err := base64.StdEncoding.DecodeString(vals[1])
	if err != nil {
		return "", errors.Wrap(err, "bad value")
	}

	enc, err := base64.StdEncoding.DecodeString(vals[2])
	if err != nil {
		return "", errors.Wrap(err, "bad value")
	}

	return decryptAES256GCM(enc, s.key, nonce)
}

func (s symmetricCrypter) BulkDecryptWithContext(ctx context.Context, ciphertexts []string) (map[string]string, error) {
	return DefaultBulkDecryptWithContext(ctx, s, ciphertexts)
}

func (s symmetricCrypter) DecryptValue(ciphertext string) (string, error) {
	return s.DecryptValueWithContext(context.Background(), ciphertext)
}

func (s symmetricCrypter) BulkDecrypt(ciphertexts []string) (map[string]string, error) {
	return s.BulkDecryptWithContext(context.Background(), ciphertexts)
}

func (s symmetricCrypter) EncryptValue(plaintext string) (string, error) {
	return s.EncryptValueWithContext(context.Background(), plaintext)
}

// encryptAES256GCGM returns the ciphertext and the generated nonce
func encryptAES256GCGM(plaintext string, key []byte) ([]byte, []byte) {
	contract.Requiref(len(key) == SymmetricCrypterKeyBytes, "key", "AES-256-GCM needs a 32 byte key")

	nonce := make([]byte, 12)

	_, err := cryptorand.Read(nonce)
	contract.Assertf(err == nil, "could not read from system random source")

	block, err := aes.NewCipher(key)
	contract.AssertNoError(err)

	aesgcm, err := cipher.NewGCM(block)
	contract.AssertNoError(err)

	msg := aesgcm.Seal(nil, nonce, []byte(plaintext), nil)

	return msg, nonce
}

func decryptAES256GCM(ciphertext []byte, key []byte, nonce []byte) (string, error) {
	contract.Requiref(len(key) == SymmetricCrypterKeyBytes, "key", "AES-256-GCM needs a 32 byte key")

	block, err := aes.NewCipher(key)
	contract.AssertNoError(err)

	aesgcm, err := cipher.NewGCM(block)
	contract.AssertNoError(err)

	msg, err := aesgcm.Open(nil, nonce, ciphertext, nil)

	return string(msg), err
}

// Crypter that just adds a prefix to the plaintext string when encrypting,
// and removes the prefix from the ciphertext when decrypting, for use in tests.
type prefixCrypter struct {
	prefix string
}

func newPrefixCrypter(prefix string) Crypter {
	return prefixCrypter{prefix: prefix}
}

func (c prefixCrypter) DecryptValueWithContext(ctx context.Context, ciphertext string) (string, error) {
	return strings.TrimPrefix(ciphertext, c.prefix), nil
}

func (c prefixCrypter) EncryptValueWithContext(ctx context.Context, plaintext string) (string, error) {
	return c.prefix + plaintext, nil
}

func (c prefixCrypter) BulkDecryptWithContext(ctx context.Context, ciphertexts []string) (map[string]string, error) {
	return DefaultBulkDecryptWithContext(ctx, c, ciphertexts)
}

func (c prefixCrypter) DecryptValue(ciphertext string) (string, error) {
	return c.DecryptValueWithContext(context.Background(), ciphertext)
}

func (c prefixCrypter) BulkDecrypt(ciphertexts []string) (map[string]string, error) {
	return c.BulkDecryptWithContext(context.Background(), ciphertexts)
}

func (c prefixCrypter) EncryptValue(plaintext string) (string, error) {
	return c.EncryptValueWithContext(context.Background(), plaintext)
}

// DefaultBulkDecrypt decrypts a list of ciphertexts. Each ciphertext is decrypted individually. The returned
// map maps from ciphertext to plaintext. This should only be used by implementers of Decrypter to implement
// their BulkDecrypt method in cases where they can't do more efficient than just individual decryptions.
func DefaultBulkDecrypt(decrypter Decrypter, ciphertexts []string) (map[string]string, error) {
	return DefaultBulkDecryptWithContext(context.Background(), decrypter, ciphertexts)
}

func DefaultBulkDecryptWithContext(ctx context.Context, decrypter Decrypter, ciphertexts []string) (map[string]string, error) {
	if len(ciphertexts) == 0 {
		return nil, nil
	}

	secretMap := map[string]string{}
	for _, ct := range ciphertexts {
		pt, err := decrypter.DecryptValueWithContext(ctx, ct)
		if err != nil {
			return nil, err
		}
		secretMap[ct] = pt
	}
	return secretMap, nil
}
