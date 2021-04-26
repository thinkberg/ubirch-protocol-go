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
	"encoding/pem"
	"fmt"
	"math/big"

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

type ECDSACryptoContext struct{}

func (c *ECDSACryptoContext) SignatureLength() int {
	return nistp256SignatureLength
}

func (c *ECDSACryptoContext) HashLength() int {
	return sha256Length
}

// Ensure ECDSACryptoContext implements the Crypto interface
var _ Crypto = (*ECDSACryptoContext)(nil)

// encodePrivateKey encodes the Private Key as x509 and returns the encoded PEM
func encodePrivateKey(privateKey *ecdsa.PrivateKey) ([]byte, error) {
	x509Encoded, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded})
	return pemEncoded, nil
}

// encodePublicKey encodes the Public Key as x509 and returns the encoded PEM
func encodePublicKey(publicKey *ecdsa.PublicKey) ([]byte, error) {
	x509EncodedPub, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509EncodedPub})
	return pemEncoded, nil
}

// decodePrivateKey decodes a Private Key from the x509 PEM format and returns the Private Key
func decodePrivateKey(pemEncoded []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemEncoded)
	if block == nil {
		return nil, fmt.Errorf("unable to parse PEM block")
	}
	x509Encoded := block.Bytes
	return x509.ParseECPrivateKey(x509Encoded)
}

// decodePublicKey decodes a Public Key from the x509 PEM format and returns the Public Key
func decodePublicKey(pemEncoded []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(pemEncoded)
	if block == nil {
		return nil, fmt.Errorf("unable to parse PEM block")
	}
	genericPublicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return genericPublicKey.(*ecdsa.PublicKey), nil
}

// PublicKeyBytesToPEM PublicKeyToPEM converts a ECDSA P-256 public key (64 bytes) to PEM format
func (c *ECDSACryptoContext) PublicKeyBytesToPEM(pubKeyBytes []byte) (pubkeyPEM []byte, err error) {
	if len(pubKeyBytes) != nistp256PubkeyLength {
		return nil, fmt.Errorf("unexpected length for ECDSA public key: expected %d, got %d", nistp256PubkeyLength, len(pubKeyBytes))
	}

	pubKey := new(ecdsa.PublicKey)
	pubKey.Curve = elliptic.P256()
	pubKey.X = &big.Int{}
	pubKey.X.SetBytes(pubKeyBytes[0:nistp256XLength])
	pubKey.Y = &big.Int{}
	pubKey.Y.SetBytes(pubKeyBytes[nistp256XLength:(nistp256XLength + nistp256YLength)])

	if !pubKey.IsOnCurve(pubKey.X, pubKey.Y) {
		return nil, fmt.Errorf("invalid public key value: point not on curve")
	}

	return encodePublicKey(pubKey)
}

// PrivateKeyBytesToPEM PrivateKeyToPEM converts a ECDSA P-256 private key (32 bytes) to PEM format
func (c *ECDSACryptoContext) PrivateKeyBytesToPEM(privKeyBytes []byte) (privKeyPEM []byte, err error) {
	if len(privKeyBytes) != nistp256PrivkeyLength {
		return nil, fmt.Errorf("unexpected length for ECDSA private key: expected %d, got %d", nistp256PrivkeyLength, len(privKeyBytes))
	}

	privKey := new(ecdsa.PrivateKey)
	privKey.PublicKey.Curve = elliptic.P256()
	privKey.D = new(big.Int)
	privKey.D.SetBytes(privKeyBytes)
	privKey.PublicKey.X, privKey.PublicKey.Y = privKey.PublicKey.Curve.ScalarBaseMult(privKey.D.Bytes())

	curveOrder := privKey.PublicKey.Curve.Params().N
	if privKey.D.Cmp(curveOrder) >= 0 {
		return nil, fmt.Errorf("invalid private key value: value is greater or equal curve order")
	}

	return encodePrivateKey(privKey)
}

// PublicKeyPEMToBytes PublicKeyToBytes converts a given public key from PEM format to raw bytes
func (c *ECDSACryptoContext) PublicKeyPEMToBytes(pubKeyPEM []byte) ([]byte, error) {
	decodedPubKey, err := decodePublicKey(pubKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("decoding public key failed: %v", err)
	}

	pubKeyBytes := make([]byte, 0, 0)

	//copy only the bytes vailable in X/Y.Bytes() while preverving the leading zeroes in paddedX/Y
	//this ensures pubkeybytes is always the correct size even if X/Y could be representend in
	//less bytes (and thus X/Y.bytes will actually return less bytes)
	paddedX := make([]byte, nistp256XLength)
	paddedY := make([]byte, nistp256YLength)
	copy(paddedX[nistp256XLength-len(decodedPubKey.X.Bytes()):], decodedPubKey.X.Bytes())
	copy(paddedY[nistp256YLength-len(decodedPubKey.Y.Bytes()):], decodedPubKey.Y.Bytes())
	pubKeyBytes = append(pubKeyBytes, paddedX...)
	pubKeyBytes = append(pubKeyBytes, paddedY...)

	return pubKeyBytes, nil
}

// GenerateKey generates a new private key and returns it in PEM format
func (c *ECDSACryptoContext) GenerateKey() (privKeyPEM []byte, err error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	return encodePrivateKey(k)
}

// GetPublicKeyFromPrivateKey calculates the matching public key (PEM) for a given private key (PEM)
func (c *ECDSACryptoContext) GetPublicKeyFromPrivateKey(privKeyPEM []byte) ([]byte, error) {
	decodedPrivKey, err := decodePrivateKey(privKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("decoding private key failed: %v", err)
	}
	if decodedPrivKey.Curve.Params().Name != "P-256" {
		return nil, fmt.Errorf("private key has unexpected type: %s, expected: P-256", decodedPrivKey.Curve.Params().Name)
	}

	return encodePublicKey(&decodedPrivKey.PublicKey)
}

// GetCSR gets a certificate signing request.
func (c *ECDSACryptoContext) GetCSR(privKeyPEM []byte, id uuid.UUID, subjectCountry string, subjectOrganization string) ([]byte, error) {
	template := &x509.CertificateRequest{
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		Subject: pkix.Name{
			Country:      []string{subjectCountry},
			Organization: []string{subjectOrganization},
			CommonName:   id.String(),
		},
	}

	priv, err := decodePrivateKey(privKeyPEM)
	if err != nil {
		return nil, err
	}

	return x509.CreateCertificateRequest(rand.Reader, template, priv)
}

// Sign returns the signature for the SHA256 of 'data' using the private key of a specific UUID.
func (c *ECDSACryptoContext) Sign(privKeyPEM []byte, data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty data")
	}

	hash := sha256.Sum256(data)
	return c.SignHash(privKeyPEM, hash[:])
}

func (c *ECDSACryptoContext) SignHash(privKeyPEM []byte, hash []byte) ([]byte, error) {
	if len(hash) != sha256Length {
		return nil, fmt.Errorf("invalid sha256 size: expected %d, got %d", sha256Length, len(hash))
	}

	priv, err := decodePrivateKey(privKeyPEM)
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
func (c *ECDSACryptoContext) Verify(pubKeyPEM []byte, data []byte, signature []byte) (bool, error) {
	if len(data) == 0 {
		return false, fmt.Errorf("empty data cannot be verified")
	}
	if len(signature) != nistp256SignatureLength {
		return false, fmt.Errorf("wrong signature length: expected: %d, got: %d", nistp256SignatureLength, len(signature))
	}

	pub, err := decodePublicKey(pubKeyPEM)
	if err != nil {
		return false, err
	}

	r, s := &big.Int{}, &big.Int{}
	r.SetBytes(signature[:nistp256RLength])
	s.SetBytes(signature[nistp256SLength:])

	hash := sha256.Sum256(data)
	return ecdsa.Verify(pub, hash[:], r, s), nil
}
