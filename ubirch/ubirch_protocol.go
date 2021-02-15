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
	"crypto/sha256"
	"fmt"

	"github.com/google/uuid"
	"github.com/ugorji/go/codec"
)

// ProtocolVersion definition
type ProtocolVersion uint8

const (
	Signed  ProtocolVersion = 0x22 // Signed protocol, the Ubirch Protocol Package is signed
	Chained ProtocolVersion = 0x23 // Chained protocol, the Ubirch Protocol Package contains the previous signature and is signed
)

// Crypto Interaface for exported functionality
type Crypto interface {
	GetUUID(name string) (uuid.UUID, error)
	GenerateKey(name string, id uuid.UUID) error
	GetCSR(name string, subjectCountry string, subjectOrganization string) ([]byte, error)
	GetPublicKey(name string) ([]byte, error)
	PrivateKeyExists(name string) bool
	SetPublicKey(name string, id uuid.UUID, pubKeyBytes []byte) error
	SetKey(name string, id uuid.UUID, privKeyBytes []byte) error

	Sign(id uuid.UUID, value []byte) ([]byte, error)
	Verify(id uuid.UUID, value []byte, signature []byte) (bool, error)
}

// Protocol structure
type Protocol struct {
	Crypto
	Signatures map[uuid.UUID][]byte
}

// interface for Ubirch Protocol Packages
type UPP interface {
	GetVersion() ProtocolVersion
	GetUuid() uuid.UUID
	GetPrevSignature() []byte
	GetHint() uint8
	GetPayload() []byte
	GetSignature() []byte
}

// SignedUPP is the Signed Ubirch Protocol Package
type SignedUPP struct {
	Version   ProtocolVersion
	Uuid      uuid.UUID
	Hint      uint8
	Payload   []byte
	Signature []byte
}

func (upp SignedUPP) GetVersion() ProtocolVersion {
	return upp.Version
}

func (upp SignedUPP) GetUuid() uuid.UUID {
	return upp.Uuid
}

func (upp SignedUPP) GetPrevSignature() []byte {
	return nil
}

func (upp SignedUPP) GetHint() uint8 {
	return upp.Hint
}

func (upp SignedUPP) GetPayload() []byte {
	return upp.Payload
}

func (upp SignedUPP) GetSignature() []byte {
	return upp.Signature
}

// ChainedUPP is the Chained Ubirch Protocol Package
type ChainedUPP struct {
	Version       ProtocolVersion
	Uuid          uuid.UUID
	PrevSignature []byte
	Hint          uint8
	Payload       []byte
	Signature     []byte
}

func (upp ChainedUPP) GetVersion() ProtocolVersion {
	return upp.Version
}

func (upp ChainedUPP) GetUuid() uuid.UUID {
	return upp.Uuid
}

func (upp ChainedUPP) GetPrevSignature() []byte {
	return upp.PrevSignature
}

func (upp ChainedUPP) GetHint() uint8 {
	return upp.Hint
}

func (upp ChainedUPP) GetPayload() []byte {
	return upp.Payload
}

func (upp ChainedUPP) GetSignature() []byte {
	return upp.Signature
}

// Encode encodes a UPP into MsgPack and returns it, if successful with 'nil' error
func Encode(upp UPP) ([]byte, error) {
	var mh codec.MsgpackHandle
	mh.StructToArray = true
	mh.WriteExt = true

	encoded := make([]byte, 128)
	encoder := codec.NewEncoderBytes(&encoded, &mh)
	if err := encoder.Encode(upp); err != nil {
		return nil, err
	}
	return encoded, nil
}

// Decode decodes a protocol package into a UPP a returns it, if successful with 'nil' error
func Decode(upp []byte) (UPP, error) {
	if upp == nil || len(upp) < 2 {
		return nil, fmt.Errorf("input nil or invalid length")
	}

	var mh codec.MsgpackHandle
	mh.StructToArray = true
	mh.WriteExt = true

	decoder := codec.NewDecoderBytes(upp, &mh)
	switch upp[1] {
	case byte(Signed):
		signedUPP := new(SignedUPP)
		err := decoder.Decode(signedUPP)
		if err != nil {
			return nil, err
		}
		return signedUPP, nil
	case byte(Chained):
		chainedUPP := new(ChainedUPP)
		err := decoder.Decode(chainedUPP)
		if err != nil {
			return nil, err
		}
		return chainedUPP, nil
	default:
		return nil, fmt.Errorf("invalid protocol version: 0x%02x", upp[1])
	}
}

func DecodeSigned(upp []byte) (*SignedUPP, error) {
	i, err := Decode(upp)
	if err != nil {
		return nil, err
	}

	signed, ok := i.(*SignedUPP)
	if !ok {
		return nil, fmt.Errorf("type assertion failed: input not a signed UPP")
	}

	return signed, nil
}

func DecodeChained(upp []byte) (*ChainedUPP, error) {
	i, err := Decode(upp)
	if err != nil {
		return nil, err
	}

	chained, ok := i.(*ChainedUPP)
	if !ok {
		return nil, fmt.Errorf("type assertion failed: input not a chained UPP")
	}

	return chained, nil
}

// appendSignature appends a signature to an encoded message and returns it
func appendSignature(encoded []byte, signature []byte) []byte {
	if len(encoded) == 0 || len(signature) == 0 {
		return nil
	}
	encoded = append(encoded[:len(encoded)-1], 0xC4, byte(len(signature)))
	encoded = append(encoded, signature...)
	return encoded
}

// sign encodes, signs and appends the signature to a UPP
// also saves the signature for chained UPPs
func (p *Protocol) sign(upp UPP) ([]byte, error) {
	encoded, err := Encode(upp)
	if err != nil {
		return nil, err
	}
	signature, err := p.Crypto.Sign(upp.GetUuid(), encoded[:len(encoded)-1])
	if err != nil {
		return nil, err
	}
	if len(signature) != nistp256SignatureLength {
		return nil, fmt.Errorf("generated signature has invalid length")
	}
	uppWithSig := appendSignature(encoded, signature)
	if uppWithSig == nil {
		return nil, fmt.Errorf("generated UPP is nil")
	}

	// save the signature for chained UPPs
	if upp.GetVersion() == Chained {
		p.Signatures[upp.GetUuid()] = signature
	}

	return uppWithSig, nil
}

//Sign is a wrapper for backwards compatibility with Sign() calls, will be removed in the future
func (p *Protocol) Sign(name string, hash []byte, protocol ProtocolVersion) ([]byte, error) {
	fmt.Println("Warning: Sign() is deprecated, please use SignHash() or SignData() as appropriate")
	return p.SignHash(name, hash, protocol)
}

// SignHash creates and signs a ubirch-protocol message using the given hash and the protocol type.
// The method expects a hash as input data.
// Returns a standard ubirch-protocol packet (UPP) with the hint 0x00 (binary hash).
func (p *Protocol) SignHash(name string, hash []byte, protocol ProtocolVersion) ([]byte, error) {
	const expectedHashSize = 32
	if len(hash) != expectedHashSize {
		return nil, fmt.Errorf("invalid hash size, expected %v, got %v bytes", expectedHashSize, len(hash))
	}

	id, err := p.GetUUID(name)
	if err != nil {
		return nil, err
	}
	if id == uuid.Nil { //catch error if there is an entry but the UUID is nil
		return nil, fmt.Errorf("entry for name found but UUID is nil")
	}

	switch protocol {
	case Signed:
		return p.sign(&SignedUPP{protocol, id, 0x00, hash, nil})
	case Chained:
		prevSignature, found := p.Signatures[id] // load signature of last UPP
		if !found {
			prevSignature = make([]byte, nistp256SignatureLength) // not found: make new chain start (all zeroes signature)
		} else if len(prevSignature) != nistp256SignatureLength { // found: check that loaded signature has valid length
			return nil, fmt.Errorf("invalid last signature, can't create chained UPP")
		}
		return p.sign(&ChainedUPP{protocol, id, prevSignature, 0x00, hash, nil})
	default:
		return nil, fmt.Errorf("invalid protocol version: 0x%02x", protocol)
	}
}

// SignData creates and signs a ubirch-protocol message using the given user data and the protocol type.
// The method expects the user data as input data. Data will be hashed and a UPP using
// the hash as payload will be created by calling SignHash(). The UUID is automatically retrieved
// from the context using the given device name.
// FIXME this method name might be confusing. If the user explicitly wants to sign original data,
//  (e.g. for msgpack key registration messages) the method name sounds like it would do that.
func (p *Protocol) SignData(name string, userData []byte, protocol ProtocolVersion) ([]byte, error) {
	//Catch errors
	if userData == nil || len(userData) < 1 {
		return nil, fmt.Errorf("input data is nil or empty")
	}
	//Calculate hash
	//TODO: Make this dependent on the used crypto if we implement more than one
	hash := sha256.Sum256(userData)

	return p.SignHash(name, hash[:], protocol)
}

// Verify the signature of a ubirch-protocol message.
func (p *Protocol) Verify(name string, value []byte) (bool, error) {
	const lenMsgpackSignatureElement = 2 + nistp256SignatureLength // length of the signature plus msgpack header for byte array (0xc4XX)

	if len(value) <= lenMsgpackSignatureElement {
		return false, fmt.Errorf("input not verifiable: len %d <= %d bytes", len(value), lenMsgpackSignatureElement)
	}

	id, err := p.GetUUID(name)
	if err != nil {
		return false, err
	}

	switch value[1] {
	case byte(Signed):
		fallthrough
	case byte(Chained):
		data := value[:len(value)-lenMsgpackSignatureElement]
		signature := value[len(value)-nistp256SignatureLength:]
		return p.Crypto.Verify(id, data, signature)
	default:
		return false, fmt.Errorf("invalid protocol version: 0x%02x", value[1])
	}
}
