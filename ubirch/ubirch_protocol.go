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
	Signed  ProtocolType = 0x22
	Chained ProtocolType = 0x23
)

type Crypto interface {
	Sign(name string, value []byte) ([]byte, error)
	Verify(name string, value []byte) ([]byte, error)
	SaveSignature(id uuid.UUID, signature []byte) error
	LoadSignature(id uuid.UUID) ([]byte, error)
}

type Protocol struct {
	Crypto
}

type simple struct {
	Version   ProtocolType
	Uuid      uuid.UUID
	Hint      uint8
	Payload   []byte
	Signature []byte
}

type chained struct {
	Version       ProtocolType
	Uuid          uuid.UUID
	PrevSignature []byte
	Hint          uint8
	Payload       []byte
	Signature     []byte
}

func encode(v interface{}) ([]byte, error) {
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

func appendSignature(encoded []byte, signature []byte) []byte {
	encoded = append(encoded[:len(encoded)-1], 0xC4, byte(len(signature)))
	encoded = append(encoded, signature...)
	return encoded
}

func (upp simple) sign(p *Protocol) ([]byte, error) {
	encoded, err := encode(upp)
	if err != nil {
		return nil, err
	}
	signature, err := p.Crypto.Sign(upp.Uuid, encoded[:len(encoded)-1])
}

func (upp chained) sign(p *Protocol) ([]byte, error) {
	encoded, err := encode(upp)
	if err != nil {
		return nil, err
	}
	signature, err := p.Crypto.Sign(upp.Uuid, encoded[:len(encoded)-1])
	return appendSignature(encoded, signature), nil
}

// Create and sign a ubirch-protocol message using the given data.
// This method allows adding a hint value with the data.
// Returns a fully signed ubirch-protocol packet (UPP).
func (p *Protocol) SignExt(name string, hint uint8, value []byte, protocol ProtocolType) ([]byte, error) {
	switch protocol {
	case Signed:
		return simple{
			protocol,
			p.getUUID(name),
			hint,
			value,
			nil,
		}.sign(p)
	case Chained:
		return chained{
			protocol,
			p.getUUID(name),
			make([]byte, 64),
			hint,
			value,
			nil,
		}.sign(p)
	default:
		return nil, errors.New(fmt.Sprintf("unknown protocol type: 0x%02x", protocol))
	}
}

// Create and sign a ubirch-protocol message using the given data and the protocol type.
// The method expects a hash as input data for the value.
// Returns a standard ubirch-protocol packet (UPP) with the hint 0x00 (binary hash).
func (p *Protocol) Sign(name string, value []byte, protocol ProtocolType) ([]byte, error) {
	return p.SignExt(name, 0x00, value, protocol)
}

// Verify a ubirch-protocol message and return the payload.
func (p *Protocol) Verify(name string, value []byte, protocol int) ([]byte, error) {
	return nil, nil
}
