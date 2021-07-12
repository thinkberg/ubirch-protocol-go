/*
 * Copyright (c) 2019 ubirch GmbH.
 *
 * ```
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ```
 */

package ubirch

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"reflect"

	"github.com/google/uuid"
)

const (
	//constants for number of bytes used for parameters of NIST P-256 curve
	nistp256PrivkeyLength   = 32                                //Bytes
	nistp256XLength         = 32                                //Bytes
	nistp256YLength         = 32                                //Bytes
	nistp256PubkeyLength    = nistp256XLength + nistp256YLength //Bytes, Pubkey = concatenate(X,Y)
	nistp256RLength         = 32                                //Bytes
	nistp256SLength         = 32                                //Bytes
	nistp256SignatureLength = nistp256RLength + nistp256SLength //Bytes, Signature = concatenate(R,S)
	sha256Length            = 32                                // length of a SHA256 hash
)

// ECDSACryptoContext contains the key store
type ECDSACryptoContext struct {
	Keystore Keystorer
}

func (c *ECDSACryptoContext) SignatureLength() int {
	return nistp256SignatureLength
}

func (c *ECDSACryptoContext) HashLength() int {
	return sha256Length
}

// Ensure ECDSACryptoContext implements the Crypto interface
var _ Crypto = (*ECDSACryptoContext)(nil)

// storePrivateKey stores the private Key, returns 'nil', if successful
func (c *ECDSACryptoContext) storePrivateKey(id uuid.UUID, k *ecdsa.PrivateKey) error {
	if c.Keystore == nil || reflect.ValueOf(c.Keystore).IsNil() {
		return fmt.Errorf("uninitialized keystore")
	}

	privKeyBytes, err := PrivateKeyStructToPEM(k)
	if err != nil {
		return err
	}

	return c.Keystore.SetPrivateKey(id, privKeyBytes)
}

// storePublicKey stores the public Key, returns 'nil', if successful
func (c *ECDSACryptoContext) storePublicKey(id uuid.UUID, k *ecdsa.PublicKey) error {
	if c.Keystore == nil || reflect.ValueOf(c.Keystore).IsNil() {
		return fmt.Errorf("uninitialized keystore")
	}

	pubKeyBytes, err := PublicKeyStructToPEM(k)
	if err != nil {
		return err
	}

	return c.Keystore.SetPublicKey(id, pubKeyBytes)
}

// getPrivateKey gets the decoded private key for the given name.
func (c *ECDSACryptoContext) getPrivateKey(id uuid.UUID) (*ecdsa.PrivateKey, error) {
	if c.Keystore == nil || reflect.ValueOf(c.Keystore).IsNil() {
		return nil, fmt.Errorf("uninitialized keystore")
	}

	// get encoded private key from keystore
	privKey, err := c.Keystore.GetPrivateKey(id)
	if err != nil {
		return nil, err
	}

	// decode the key
	return PrivateKeyPEMToStruct(privKey)
}

// getPublicKey gets the decoded public key for the given name.
func (c *ECDSACryptoContext) getPublicKey(id uuid.UUID) (*ecdsa.PublicKey, error) {
	if c.Keystore == nil || reflect.ValueOf(c.Keystore).IsNil() {
		return nil, fmt.Errorf("uninitialized keystore")
	}

	// get encoded public key from keystore
	pubKey, err := c.Keystore.GetPublicKey(id)
	if err != nil {
		return nil, err
	}

	// decode the key
	return PublicKeyPEMToStruct(pubKey)
}

// storeKey stores the Private Key, as well as the Public Key, returns 'nil', if successful
func (c *ECDSACryptoContext) storeKey(id uuid.UUID, k *ecdsa.PrivateKey) error {
	err := c.storePublicKey(id, &k.PublicKey)
	if err != nil {
		return err
	}
	return c.storePrivateKey(id, k)
}

// GenerateKey generates a new key pair and stores it, using the given name and associated UUID.
func (c *ECDSACryptoContext) GenerateKey(id uuid.UUID) error {
	if id == uuid.Nil {
		return fmt.Errorf("UUID \"Nil\"-value")
	}

	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	return c.storeKey(id, k)
}

//SetPublicKey sets the public key (64 bytes)
func (c *ECDSACryptoContext) SetPublicKey(id uuid.UUID, pubKeyBytes []byte) error {
	if id == uuid.Nil {
		return fmt.Errorf("UUID \"Nil\"-value")
	}

	pubKey, err := PublicKeyBytesToStruct(pubKeyBytes)
	if err != nil {
		return err
	}

	return c.storePublicKey(id, pubKey)
}

//SetKey takes a private key (32 bytes), calculates the public key and sets both private and public key
func (c *ECDSACryptoContext) SetKey(id uuid.UUID, privKeyBytes []byte) error {
	if id == uuid.Nil {
		return fmt.Errorf("UUID \"Nil\"-value")
	}

	privKey, err := PrivateKeyBytesToStruct(privKeyBytes)
	if err != nil {
		return err
	}

	return c.storeKey(id, privKey)
}

// GetCSR gets a certificate signing request.
func (c *ECDSACryptoContext) GetCSR(id uuid.UUID, subjectCountry string, subjectOrganization string) ([]byte, error) {
	template := &x509.CertificateRequest{
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		Subject: pkix.Name{
			Country:      []string{subjectCountry},
			Organization: []string{subjectOrganization},
			CommonName:   id.String(),
		},
	}

	priv, err := c.getPrivateKey(id)
	if err != nil {
		return nil, err
	}

	return x509.CreateCertificateRequest(rand.Reader, template, priv)
}

// GetPublicKey gets the public key bytes for the given name.
func (c *ECDSACryptoContext) GetPublicKey(id uuid.UUID) ([]byte, error) {
	decodedPubKey, err := c.getPublicKey(id)
	if err != nil {
		return nil, fmt.Errorf("decoding public key from keystore failed: %s", err)
	}
	if decodedPubKey.Curve.Params().Name != "P-256" {
		return nil, fmt.Errorf("public key from keystore has unexpected type: %s", decodedPubKey.Curve.Params().Name)
	}

	return PublicKeyStructToBytes(decodedPubKey)
}

// PrivateKeyExists Checks if a private key entry for the given name exists in the keystore.
func (c *ECDSACryptoContext) PrivateKeyExists(id uuid.UUID) (bool, error) {
	if c.Keystore == nil || reflect.ValueOf(c.Keystore).IsNil() {
		return false, fmt.Errorf("uninitialized keystore") //TODO: safer to assume there is a key?
	}
	return c.Keystore.PrivateKeyExists(id)
}

// Sign returns the signature for the SHA256 of 'data' using the private key of a specific UUID.
func (c *ECDSACryptoContext) Sign(id uuid.UUID, data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty data")
	}

	hash := sha256.Sum256(data)
	return c.SignHash(id, hash[:])
}

func (c *ECDSACryptoContext) SignHash(id uuid.UUID, hash []byte) ([]byte, error) {
	if len(hash) != sha256Length {
		return nil, fmt.Errorf("invalid sha256 size: expected %d, got %d", sha256Length, len(hash))
	}

	priv, err := c.getPrivateKey(id)
	if err != nil {
		return nil, err
	}

	r, s, err := ecdsa.Sign(rand.Reader, priv, hash)
	if err != nil {
		return nil, err
	}

	//convert r and s to zero-byte padded byte slices
	bytesR := r.Bytes()
	bytesS := s.Bytes()
	paddedR := make([]byte, nistp256RLength)
	paddedS := make([]byte, nistp256SLength)
	copy(paddedR[nistp256RLength-len(bytesR):], bytesR)
	copy(paddedS[nistp256SLength-len(bytesS):], bytesS)

	return append(paddedR, paddedS...), nil
}

// Verify verifies that 'signature' matches 'data' using the public key with a specific UUID.
// Need to get the UUID via ECDSACryptoContext#GetUUID().
// Returns 'true' and 'nil' error if signature was verifiable.
func (c *ECDSACryptoContext) Verify(id uuid.UUID, data []byte, signature []byte) (bool, error) {
	if len(data) == 0 {
		return false, fmt.Errorf("empty data cannot be verified")
	}
	if len(signature) != nistp256SignatureLength {
		return false, fmt.Errorf("wrong signature length: expected: %d, got: %d", nistp256SignatureLength, len(signature))
	}

	pub, err := c.getPublicKey(id)
	if err != nil {
		return false, err
	}

	r, s := &big.Int{}, &big.Int{}
	r.SetBytes(signature[:nistp256RLength])
	s.SetBytes(signature[nistp256SLength:])

	hash := sha256.Sum256(data)
	return ecdsa.Verify(pub, hash[:], r, s), nil
}

func (c *ECDSACryptoContext) Close() error {
	return nil
}
