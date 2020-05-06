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
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/ugorji/go/codec"
)

// ProtocolType definition
type ProtocolType uint8

const (
	Plain   ProtocolType = 0x21 // Plain protocol, without hashing and signing
	Signed  ProtocolType = 0x22 // Signed protocol, the payload is signed
	Chained ProtocolType = 0x23 // Chained protocol, the payload contains the previous signature and is signed
)

// Crypto Interaface for exported functionality
type Crypto interface {
	GetUUID(name string) (uuid.UUID, error)
	GenerateKey(name string, id uuid.UUID) error
	GetCSR(name string) ([]byte, error)
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

// SignedUPP is the Signed Ubirch Protocol Package
type SignedUPP struct {
	Version   ProtocolType
	Uuid      uuid.UUID
	Hint      uint8
	Payload   []byte
	Signature []byte
}

// ChainedUPP is the Chained Ubirch Protocol Package
type ChainedUPP struct {
	Version       ProtocolType
	Uuid          uuid.UUID
	PrevSignature []byte
	Hint          uint8
	Payload       []byte
	Signature     []byte
}

// Encode is encoding an interface into MsgPack and returns it, if successful with 'nil' error
func Encode(v interface{}) ([]byte, error) {
	var mh codec.MsgpackHandle
	mh.StructToArray = true
	mh.WriteExt = true

	encoded := make([]byte, 128)
	encoder := codec.NewEncoderBytes(&encoded, &mh)
	if err := encoder.Encode(v); err != nil {
		return nil, err
	}
	return encoded, nil
}

// Decode is decoding a protocol package into a message a returns it, if successful with 'nil' error
func Decode(upp []byte) (interface{}, error) {
	var mh codec.MsgpackHandle
	mh.StructToArray = true
	mh.WriteExt = true

	decoder := codec.NewDecoderBytes(upp, &mh)
	switch upp[0] {
	case 0x95:
		msg := new(SignedUPP)
		err := decoder.Decode(msg)
		if err != nil {
			return nil, err
		}
		return msg, nil
	case 0x96:
		msg := new(ChainedUPP)
		err := decoder.Decode(msg)
		if err != nil {
			return nil, err
		}
		return msg, nil
	default:
		return nil, errors.New(fmt.Sprintf("corrupt UPP: array len=%d", upp[0]))
	}
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

// sign encodes, signs and appends the signature to a SignedUPP
func (upp SignedUPP) sign(p *Protocol) ([]byte, error) {
	encoded, err := Encode(upp)
	if err != nil {
		return nil, err
	}
	signature, err := p.Crypto.Sign(upp.Uuid, encoded[:len(encoded)-1])
	if err != nil {
		return nil, err
	}
	if len(signature) != nistp256SignatureLength {
		return nil, fmt.Errorf("Generated signature has invalid length")
	}
	uppWithSig := appendSignature(encoded, signature)
	if uppWithSig == nil {
		return nil, fmt.Errorf("Generated UPP is nil")
	}
	return uppWithSig, nil
}

// sign encodes, signs and appends the signature to a ChainedUPP.
// also the signature is stored for later usage
func (upp ChainedUPP) sign(p *Protocol) ([]byte, error) {
	encoded, err := Encode(upp)
	if err != nil {
		return nil, err
	}
	signature, err := p.Crypto.Sign(upp.Uuid, encoded[:len(encoded)-1])
	if err != nil {
		return nil, err
	}
	if len(signature) != nistp256SignatureLength {
		return nil, fmt.Errorf("Generated signature has invalid length")
	}
	uppWithSig := appendSignature(encoded, signature)
	if uppWithSig == nil {
		return nil, fmt.Errorf("Generated UPP is nil")
	}
	p.Signatures[upp.Uuid] = signature
	return uppWithSig, nil
}

// Init initializes the Protocol, which is not necessary in Golang
func (p *Protocol) Init() {
	//Keep this function for compatibility in ubirch/ubirch-go-udp-client
}

//Sign is a wrapper for backwards compatibility with Sign() calls, will be removed in the future
func (p *Protocol) Sign(name string, hash []byte, protocol ProtocolType) ([]byte, error) {
	fmt.Println("Warning: Sign() is deprecated, please use SignHash() or SignData() as appropriate")
	return p.SignHash(name, hash, protocol)
}

// SignHash creates and signs a ubirch-protocol message using the given hash and the protocol type.
// The method expects a hash as input data.
// Returns a standard ubirch-protocol packet (UPP) with the hint 0x00 (binary hash).
//TODO: this should not be a public function, users should use SignData() instead.
func (p *Protocol) SignHash(name string, hash []byte, protocol ProtocolType) ([]byte, error) {
	const expectedHashSize = 32

	id, err := p.Crypto.GetUUID(name)
	if err != nil {
		return nil, err
	}
	if id == uuid.Nil { //catch error if there is an entry but the UUID is nil
		return nil, fmt.Errorf("Entry for name found but UUID is nil")
	}

	if len(hash) != expectedHashSize {
		return nil, fmt.Errorf("Invalid hash size, expected %v, got %v bytes", expectedHashSize, len(hash))
	}

	switch protocol {
	case Plain:
		return nil, fmt.Errorf("Plain type packets are deprecated") //p.Crypto.Sign(id, value)
	case Signed:
		return SignedUPP{protocol, id, 0x00, hash, nil}.sign(p)
	case Chained:
		signature, found := p.Signatures[id] //load signature of last UPP
		if !found {
			signature = make([]byte, nistp256SignatureLength) //not found: make new chain start (all zeroes signature)
		} else if len(signature) != nistp256SignatureLength { //found: check that loaded signature seems valid
			return nil, fmt.Errorf("invalid last signature, can't create chained UPP")
		}
		return ChainedUPP{protocol, id, signature, 0x00, hash, nil}.sign(p)
	default:
		return nil, fmt.Errorf("unknown protocol type: 0x%02x", protocol)
	}
}

// SignData creates and signs a ubirch-protocol message using the given user data and the protocol type.
// The method expects the user data as input data. Data will be hashed and a UPP using
// the hash as payload will be created by calling SignHash(). The UUID is automatically retrieved
// from the context using the given device name.
func (p *Protocol) SignData(name string, userData []byte, protocol ProtocolType) ([]byte, error) {
	//Catch errors
	if len(userData) < 1 || userData == nil {
		return nil, fmt.Errorf("Input data is nil or empty")
	}
	//Calculate hash
	//TODO: Make this dependent on the used crypto if we implement more than one
	hash := sha256.Sum256(userData)

	return p.SignHash(name, hash[:], protocol)
}

// Verify a ubirch-protocol message and return the payload.
func (p *Protocol) Verify(name string, value []byte, protocol ProtocolType) (bool, error) {
	const signatureMsgpackHeaderLength = 2 //Bytes, Length of the header for msgpack byte array containing the signature (0xc4XX)

	id, err := p.Crypto.GetUUID(name)
	if err != nil {
		return false, err
	}

	if len(value) < (nistp256SignatureLength + signatureMsgpackHeaderLength) {
		return false, errors.New(fmt.Sprintf("data must contain signature: len %d < 64+2 bytes", len(value)))
	}

	switch protocol {
	case Plain:
		return false, errors.New("Plain type packets are deprecated") //return p.Crypto.Verify(id, value[:len(value)-64], value[len(value)-64:])
	case Signed:
		fallthrough
	case Chained:
		data := value[:len(value)-(nistp256SignatureLength+signatureMsgpackHeaderLength)]
		signature := value[len(value)-nistp256SignatureLength:]
		return p.Crypto.Verify(id, data, signature)
	default:
		return false, errors.New(fmt.Sprintf("unknown protocol type: %d", protocol))
	}

	// TODO: fix and implement automatic UPP decoding to structs
	//switch protocol {
	//case Plain:
	//	return data, nil
	//case Signed:
	//	upp, err := Decode(value)
	//	if err != nil {
	//		return nil, err
	//	}
	//	return upp.(SignedUPP), nil
	//case Chained:
	//	upp, err := Decode(value)
	//	if err != nil {
	//		return nil, err
	//	}
	//	return upp.(ChainedUPP), nil
	//default:
	//	return nil, errors.New(fmt.Sprintf("unknown message type: %d", protocol))
	//}
}
