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
	"errors"
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
)

// CryptoContext contains the key store, a mapping for names -> UUIDs
// and the last generated signature per UUID.
type CryptoContext struct {
	Keystore Keystorer
	Names    map[string]uuid.UUID
}

// Ensure CryptoContext implements the Crypto interface
var _ Crypto = (*CryptoContext)(nil)

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

// privKeyEntryTitle returns a string of the Private Key Entry
func privKeyEntryTitle(id uuid.UUID) string {
	return "_" + id.String()
}

// pubKeyEntryTitle returns a string of the Public Key Entry
func pubKeyEntryTitle(id uuid.UUID) string {
	return id.String()
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

// storePublicKey stores the public Key, returns 'nil', if successful
func (c *CryptoContext) storePublicKey(name string, id uuid.UUID, k *ecdsa.PublicKey) error {
	if c.Names == nil {
		c.Names = make(map[string]uuid.UUID, 1)
	}
	c.Names[name] = id

	pubKeyBytes, err := encodePublicKey(k)
	if err != nil {
		return err
	}
	//check for invalid keystore
	if c.Keystore == nil { //check for 'direct' nil
		return fmt.Errorf("can't set public key: keystore is nil")
	} else if reflect.ValueOf(c.Keystore).IsNil() { //check for pointer which is nil
		return fmt.Errorf("can't set public key: keystore pointer is nil, pointer type is %T", c.Keystore)
	}
	return c.Keystore.SetKey(pubKeyEntryTitle(id), pubKeyBytes)
}

// storePrivateKey stores the private Key, returns 'nil', if successful
func (c *CryptoContext) storePrivateKey(name string, id uuid.UUID, k *ecdsa.PrivateKey) error {
	if c.Names == nil {
		c.Names = make(map[string]uuid.UUID, 1)
	}
	c.Names[name] = id

	privKeyBytes, err := encodePrivateKey(k)
	if err != nil {
		return err
	}
	//check for invalid keystore
	if c.Keystore == nil { //check for 'direct' nil
		return fmt.Errorf("can't set private key: keystore is nil")
	} else if reflect.ValueOf(c.Keystore).IsNil() { //check for pointer which is nil
		return fmt.Errorf("can't set private key: keystore pointer is nil, pointer type is %T", c.Keystore)
	}
	return c.Keystore.SetKey(privKeyEntryTitle(id), privKeyBytes)
}

// storeKey stores the Private Key, as well as the Public Key, returns 'nil', if successful
func (c *CryptoContext) storeKey(name string, id uuid.UUID, k *ecdsa.PrivateKey) error {
	err := c.storePublicKey(name, id, &k.PublicKey)
	if err != nil {
		return err
	}
	return c.storePrivateKey(name, id, k)
}

// GetUUID gets the uuid that is related the given name.
func (c *CryptoContext) GetUUID(name string) (uuid.UUID, error) {
	id, found := c.Names[name]
	if !found {
		return uuid.Nil, errors.New(fmt.Sprintf("no uuid/key entry for '%s'", name))
	}
	return id, nil
}

// GenerateKey generates a new key pair and stores it, using the given name and associated UUID.
func (c *CryptoContext) GenerateKey(name string, id uuid.UUID) error {
	//check for invalid keystore
	if c.Keystore == nil { //check for 'direct' nil
		return fmt.Errorf("can't generate key: keystore is nil")
	} else if reflect.ValueOf(c.Keystore).IsNil() { //check for pointer which is nil
		return fmt.Errorf("can't generate key: keystore pointer is nil, pointer type is %T", c.Keystore)
	}
	// check for empty name
	if name == "" {
		return errors.New(fmt.Sprintf("generating key for empty name not possible"))
	}
	if id == uuid.Nil {
		return errors.New(fmt.Sprintf("generating key for uuid = \"Nil\" not possible"))
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	return c.storeKey(name, id, k)
}

//SetPublicKey sets the public key (64 bytes)
func (c *CryptoContext) SetPublicKey(name string, id uuid.UUID, pubKeyBytes []byte) error {
	const expectedKeyLength = nistp256PubkeyLength
	if len(pubKeyBytes) != expectedKeyLength {
		return errors.New(fmt.Sprintf("public key length wrong: %d != %d", len(pubKeyBytes), expectedKeyLength))
	}
	if name == "" {
		return errors.New(fmt.Sprintf("Setting key for empty name not possible"))
	}
	if id == uuid.Nil {
		return errors.New(fmt.Sprintf("Setting key for uuid = \"Nil\" not possible"))
	}

	pubKey := new(ecdsa.PublicKey)
	pubKey.Curve = elliptic.P256()
	pubKey.X = &big.Int{}
	pubKey.X.SetBytes(pubKeyBytes[0:nistp256XLength])
	pubKey.Y = &big.Int{}
	pubKey.Y.SetBytes(pubKeyBytes[nistp256XLength:(nistp256XLength + nistp256YLength)])

	return c.storePublicKey(name, id, pubKey)
}

//SetKey takes a private key (32 bytes), calculates the public key and sets both private and public key
func (c *CryptoContext) SetKey(name string, id uuid.UUID, privKeyBytes []byte) error {
	const expectedKeyLength = nistp256PrivkeyLength
	if len(privKeyBytes) != expectedKeyLength {
		return errors.New(fmt.Sprintf("private key lenght wrong: %d != %d", len(privKeyBytes), expectedKeyLength))
	}
	if name == "" {
		return errors.New(fmt.Sprintf("Setting key for empty name not possible"))
	}
	if id == uuid.Nil {
		return errors.New(fmt.Sprintf("Setting key for uuid = \"Nil\" not possible"))
	}

	privKey := new(ecdsa.PrivateKey)
	privKey.D = new(big.Int)
	privKey.D.SetBytes(privKeyBytes)
	privKey.PublicKey.Curve = elliptic.P256()
	privKey.PublicKey.X, privKey.PublicKey.Y = privKey.PublicKey.Curve.ScalarBaseMult(privKey.D.Bytes())

	return c.storeKey(name, id, privKey)
}

// GetCSR gets a certificate signing request.
func (c *CryptoContext) GetCSR(name string) ([]byte, error) {

	template := &x509.CertificateRequest{
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		Subject: pkix.Name{
			Country:      []string{"DE"},
			Organization: []string{"ubirch GmbH"},
			CommonName:   c.Names[name].String(),
		},
	}

	priv, err := c.getDecodedPrivateKey(name)
	if err != nil {
		return nil, err
	}

	return x509.CreateCertificateRequest(rand.Reader, template, priv)
}

// getDecodedPublicKey gets the decoded public key for the given name.
func (c *CryptoContext) getDecodedPublicKey(name string) (*ecdsa.PublicKey, error) {
	id, err := c.GetUUID(name)
	if err != nil {
		return nil, err
	}
	//check for invalid keystore
	if c.Keystore == nil { //check for 'direct' nil
		return nil, fmt.Errorf("can't get public key: keystore is nil")
	} else if reflect.ValueOf(c.Keystore).IsNil() { //check for pointer which is nil
		return nil, fmt.Errorf("can't get public key: keystore pointer is nil, pointer type is %T", c.Keystore)
	}
	pubKey, err := c.Keystore.GetKey(pubKeyEntryTitle(id))
	if err != nil {
		return nil, err
	}

	// decode the key
	return decodePublicKey(pubKey)
}

// GetPublicKey gets the public key bytes for the given name.
func (c *CryptoContext) GetPublicKey(name string) ([]byte, error) {
	decodedPubKey, err := c.getDecodedPublicKey(name)
	if err != nil {
		return nil, fmt.Errorf("decoding public key from keystore failed: %s", err)
	}
	if decodedPubKey.Curve.Params().Name != "P-256" {
		return nil, fmt.Errorf("public key from keystore has unexpected type: %s", decodedPubKey.Curve.Params().Name)
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

// getDecodedPrivateKey gets the decoded private key for the given name.
func (c *CryptoContext) getDecodedPrivateKey(name string) (*ecdsa.PrivateKey, error) {
	id, err := c.GetUUID(name)
	if err != nil {
		return nil, err
	}
	//check for invalid keystore
	if c.Keystore == nil { //check for 'direct' nil
		return nil, fmt.Errorf("can't get private key: keystore is nil")
	} else if reflect.ValueOf(c.Keystore).IsNil() { //check for pointer which is nil
		return nil, fmt.Errorf("can't get private key: keystore pointer is nil, pointer type is %T", c.Keystore)
	}
	privKey, err := c.Keystore.GetKey(privKeyEntryTitle(id))
	if err != nil {
		return nil, err
	}

	// decode the key
	return decodePrivateKey(privKey) //todo, check if this is necessary
}

// PrivateKeyExists Checks if a private key entry for the given name exists in the keystore.
func (c *CryptoContext) PrivateKeyExists(name string) bool {
	_, err := c.getDecodedPrivateKey(name)
	if err != nil {
		return false
	}
	return true
}

// TODO
//  // Sign a message using a signing key corresponding to a specific name.
//  func (c *CryptoContext) Sign(name string, data []byte) ([]byte, error) {
//		privKeyBytes, err := c.getDecodedPrivateKey(name)
//		...

// Sign returns the signature for 'data' using the private key of a specific UUID. Need to get the UUID via CryptoContext#GetUUID().
func (c *CryptoContext) Sign(id uuid.UUID, data []byte) ([]byte, error) {

	if len(data) == 0 {
		return nil, errors.New("empty data cannot be signed")
	}
	//check for invalid keystore
	if c.Keystore == nil { //check for 'direct' nil
		return nil, fmt.Errorf("can't get private key: keystore is nil")
	} else if reflect.ValueOf(c.Keystore).IsNil() { //check for pointer which is nil
		return nil, fmt.Errorf("can't get private key: keystore pointer is nil, pointer type is %T", c.Keystore)
	}
	privKeyBytes, err := c.Keystore.GetKey(privKeyEntryTitle(id))

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

	//convert r and s to zero-byte padded byte slices
	bytesR := r.Bytes()
	bytesS := s.Bytes()
	paddedR := make([]byte, nistp256RLength)
	paddedS := make([]byte, nistp256SLength)
	copy(paddedR[nistp256RLength-len(bytesR):], bytesR)
	copy(paddedS[nistp256SLength-len(bytesS):], bytesS)

	return append(paddedR, paddedS...), nil
}

// TODO
//  // Verify a message using a verifying key corresponding to a specific name.
//  func (c *CryptoContext) Verify(name string, data []byte, signature []byte) (bool, error) {
//		pubKeyBytes, err := c.getDecodedPublicKey(name)
//		...
// Verify that 'signature' matches 'data' using the pubkey of a specific UUID. Need to get the UUID via CryptoContext#GetUUID().
func (c *CryptoContext) Verify(id uuid.UUID, data []byte, signature []byte) (bool, error) {
	const expectedSignatureLength = nistp256SignatureLength
	if len(data) == 0 {
		return false, errors.New("empty data cannot be verified")
	}
	if len(signature) != expectedSignatureLength {
		return false, errors.New(fmt.Sprintf("signature lenght wrong: %d != %d", len(signature), expectedSignatureLength))
	}
	//check for invalid keystore
	if c.Keystore == nil { //check for 'direct' nil
		return false, fmt.Errorf("can't get public key: keystore is nil")
	} else if reflect.ValueOf(c.Keystore).IsNil() { //check for pointer which is nil
		return false, fmt.Errorf("can't get public key: keystore pointer is nil, pointer type is %T", c.Keystore)
	}
	pubKeyBytes, err := c.Keystore.GetKey(pubKeyEntryTitle(id))

	if err != nil {
		return false, err
	}

	pub, err := decodePublicKey(pubKeyBytes)
	if err != nil {
		return false, err
	}

	r, s := &big.Int{}, &big.Int{}
	r.SetBytes(signature[:nistp256RLength])
	s.SetBytes(signature[nistp256SLength:])

	hash := sha256.Sum256(data)
	return ecdsa.Verify(pub, hash[:], r, s), nil
}
