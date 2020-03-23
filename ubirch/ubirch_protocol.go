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
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/ugorji/go/codec"
)

type ProtocolType uint8

const (
	Plain   ProtocolType = 0x00
	Signed  ProtocolType = 0x22
	Chained ProtocolType = 0x23
)

type Crypto interface {
	GetUUID(name string) (uuid.UUID, error)
	GenerateKey(name string, id uuid.UUID) error
	GetCSR(name string) ([]byte, error)
	GetPublicKey(name string) ([]byte, error)
	SetPublicKey(name string, id uuid.UUID, pubKeyBytes []byte) error
	SetKey(name string, id uuid.UUID, privKeyBytes []byte) error

	Sign(id uuid.UUID, value []byte) ([]byte, error)
	Verify(id uuid.UUID, value []byte, signature []byte) (bool, error)
}

type Protocol struct {
	Crypto
	Signatures map[uuid.UUID][]byte
}

type SignedUPP struct {
	Version   ProtocolType
	Uuid      uuid.UUID
	Hint      uint8
	Payload   []byte
	Signature []byte
}

type ChainedUPP struct {
	Version       ProtocolType
	Uuid          uuid.UUID
	PrevSignature []byte
	Hint          uint8
	Payload       []byte
	Signature     []byte
}

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

func appendSignature(encoded []byte, signature []byte) []byte {
	encoded = append(encoded[:len(encoded)-1], 0xC4, byte(len(signature)))
	encoded = append(encoded, signature...)
	return encoded
}

func (upp SignedUPP) sign(p *Protocol) ([]byte, error) {
	encoded, err := Encode(upp)
	if err != nil {
		return nil, err
	}
	signature, err := p.Crypto.Sign(upp.Uuid, encoded[:len(encoded)-1])
	return appendSignature(encoded, signature), nil
}

func (upp ChainedUPP) sign(p *Protocol) ([]byte, error) {
	encoded, err := Encode(upp)
	if err != nil {
		return nil, err
	}
	signature, err := p.Crypto.Sign(upp.Uuid, encoded[:len(encoded)-1])
	p.Signatures[upp.Uuid] = signature
	return appendSignature(encoded, signature), nil
}

func (p *Protocol) Init() {
	//Keep this function for compatibility in ubirch/ubirch-go-udp-client
}

// Create and sign a ubirch-protocol message using the given data and the protocol type.
// The method expects a hash as input data.
// Returns a standard ubirch-protocol packet (UPP) with the hint 0x00 (binary hash).
func (p *Protocol) Sign(name string, hash []byte, protocol ProtocolType) ([]byte, error) {
	const expectedHashSize = 32

	id, err := p.Crypto.GetUUID(name)
	if err != nil {
		return nil, err
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
		signature, found := p.Signatures[id]
		if !found {
			signature = make([]byte, 64)
		}
		return ChainedUPP{protocol, id, signature, 0x00, hash, nil}.sign(p)
	default:
		return nil, errors.New(fmt.Sprintf("unknown protocol type: 0x%02x", protocol))
	}
}

// Verify a ubirch-protocol message and return the payload.
func (p *Protocol) Verify(name string, value []byte, protocol ProtocolType) (bool, error) {
	id, err := p.Crypto.GetUUID(name)
	if err != nil {
		return false, err
	}

	if len(value) <= 64 {
		return false, errors.New(fmt.Sprintf("data must contain signature: len %d < 64+2 bytes", len(value)))
	}

	switch protocol {
	case Plain:
		return p.Crypto.Verify(id, value[:len(value)-64], value[len(value)-64:])
	case Signed:
		fallthrough
	case Chained:
		data := value[:len(value)-66]
		signature := value[len(value)-64:]
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
