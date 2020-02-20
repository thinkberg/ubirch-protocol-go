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
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"

	"github.com/google/uuid"
	"github.com/paypal/go.crypto/keystore"
)

// This crypto context contains the key store, a mapping for names -> UUIDs
// and the last generated signature per UUID.
type CryptoContext struct {
	Keystore *keystore.Keystore
	Names    map[string]uuid.UUID
}

func encodePrivateKey(privateKey *ecdsa.PrivateKey) ([]byte, error) {
	x509Encoded, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded})
	return pemEncoded, nil
}

func encodePublicKey(publicKey *ecdsa.PublicKey) ([]byte, error) {
	x509EncodedPub, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509EncodedPub})

	return pemEncoded, nil
}

func decodePrivateKey(pemEncoded []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemEncoded)
	x509Encoded := block.Bytes
	return x509.ParseECPrivateKey(x509Encoded)
}

func decodePublicKey(pemEncoded []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(pemEncoded)
	genericPublicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return genericPublicKey.(*ecdsa.PublicKey), nil
}

//func signatureToPoints(signature []byte) (r, s *big.Int, err error) {
//	r, s = &big.Int{}, &big.Int{}
//
//	data := asn1.RawValue{}
//	_, err = asn1.Unmarshal(signature, &data)
//	if err != nil {
//		return nil, nil, err
//	}
//
//	rLen := data.Bytes[1]
//	r.SetBytes(data.Bytes[2 : rLen+2])
//	s.SetBytes(data.Bytes[rLen+4:])
//
//	return r, s, nil
//}

func (c *CryptoContext) storePublicKey(name string, id uuid.UUID, k *ecdsa.PublicKey) error {
	if c.Names == nil {
		c.Names = make(map[string]uuid.UUID, 1)
	}
	c.Names[name] = id

	pubKeyBytes, err := encodePublicKey(k)
	if err != nil {
		return err
	}
	pph, _ := id.MarshalBinary()
	return c.Keystore.Set("_"+id.String(), pubKeyBytes, pph)
}

func (c *CryptoContext) storePrivateKey(name string, id uuid.UUID, k *ecdsa.PrivateKey) error {
	if c.Names == nil {
		c.Names = make(map[string]uuid.UUID, 1)
	}
	c.Names[name] = id

	privKeyBytes, err := encodePrivateKey(k)
	if err != nil {
		return err
	}
	pph, _ := id.MarshalBinary()
	return c.Keystore.Set(id.String(), privKeyBytes, pph)
}

func (c *CryptoContext) storeKey(name string, id uuid.UUID, k *ecdsa.PrivateKey) error {
	err := c.storePublicKey(name, id, &k.PublicKey)
	if err != nil {
		return err
	}
	return c.storePrivateKey(name, id, k)
}

// Get the uuid that is related the given name.
func (c *CryptoContext) GetUUID(name string) (uuid.UUID, error) {
	id, found := c.Names[name]
	if !found {
		return uuid.Nil, errors.New(fmt.Sprintf("no uuid/key entry for '%s'", name))
	}
	return id, nil
}

// Generate a new key pair and store it using the given name and associated UUID.
func (c *CryptoContext) GenerateKey(name string, id uuid.UUID) error {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	return c.storeKey(name, id, k)
}

func (c *CryptoContext) SetPublicKey(name string, id uuid.UUID, pubKeyBytes []byte) error {
	if len(pubKeyBytes) != 64 {
		return errors.New(fmt.Sprintf("public key length wrong: %d != 64", len(pubKeyBytes)))
	}

	pubKey := new(ecdsa.PublicKey)
	pubKey.Curve = elliptic.P256()
	pubKey.X = &big.Int{}
	pubKey.X.SetBytes(pubKeyBytes[0:32])
	pubKey.Y = &big.Int{}
	pubKey.Y.SetBytes(pubKeyBytes[32:64])

	return c.storePublicKey(name, id, pubKey)
}

func (c *CryptoContext) SetKey(name string, id uuid.UUID, privKeyBytes []byte) error {
	if len(privKeyBytes) != 32 {
		return errors.New(fmt.Sprintf("private key lenght wrong: %d != 32", len(privKeyBytes)))
	}

	privKey := new(ecdsa.PrivateKey)
	privKey.D = new(big.Int)
	privKey.D.SetBytes(privKeyBytes)
	privKey.PublicKey.Curve = elliptic.P256()
	privKey.PublicKey.X, privKey.PublicKey.Y = privKey.PublicKey.Curve.ScalarBaseMult(privKey.D.Bytes())

	return c.storeKey(name, id, privKey)
}

// Get a certificate signing request.
func (c *CryptoContext) GetCSR(name string) ([]byte, error) { return nil, nil }

// Get the public key bytes for the given name.
func (c *CryptoContext) GetPublicKey(name string) ([]byte, error) {
	id, err := c.GetUUID(name)
	if err != nil {
		return nil, err
	}

	pph, _ := id.MarshalBinary()
	pubKeyBytes, err := c.Keystore.Get("_"+id.String(), pph)
	if err != nil {
		return nil, err
	}
	return pubKeyBytes, nil
}

// Sign a message using a specific UUID. Need to get the UUID via CryptoContext#GetUUID().
func (c *CryptoContext) Sign(id uuid.UUID, data []byte) ([]byte, error) {
	pph, _ := id.MarshalBinary()
	privKeyBytes, err := c.Keystore.Get(id.String(), pph)
	if err != nil {
		return nil, err
	}

	priv, err := decodePrivateKey(privKeyBytes)
	if err != nil {
		return nil, err
	}

	// ecdsa in go does not automatically apply the hashing
	hash := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, priv, hash[:])
	if err != nil {
		return nil, err
	}
	return append(r.Bytes(), s.Bytes()...), nil
}

// Verify a message using a specific UUID. Need to get the UUID via CryptoContext#GetUUID().
func (c *CryptoContext) Verify(id uuid.UUID, data []byte, signature []byte) (bool, error) {
	pph, _ := id.MarshalBinary()
	pubKeyBytes, err := c.Keystore.Get("_"+id.String(), pph)
	if err != nil {
		return false, err
	}

	pub, err := decodePublicKey(pubKeyBytes)
	if err != nil {
		return false, err
	}

	r, s := &big.Int{}, &big.Int{}
	r.SetBytes(signature[:32])
	s.SetBytes(signature[32:])

	hash := sha256.Sum256(data)
	if ecdsa.Verify(pub, hash[:], r, s) {
		return true, nil
	}
	return false, errors.New("signature verification failed")
}
