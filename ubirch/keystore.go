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
	"encoding/json"
	"github.com/google/uuid"
	"github.com/ubirch/go.crypto/keystore"
	"strings"
)

// Keystorer contains the methods that must be implemented by the keystore
// implementation.
type Keystorer interface {
	GetIDs() ([]uuid.UUID, error)

	GetPrivateKey(id uuid.UUID) ([]byte, error)
	SetPrivateKey(id uuid.UUID, key []byte) error

	GetPublicKey(id uuid.UUID) ([]byte, error)
	SetPublicKey(id uuid.UUID, key []byte) error
}

// EncryptedKeystore is the reference implementation for a simple keystore.
// The secret has to be 16 Bytes long
type EncryptedKeystore struct {
	*keystore.Keystore
	Secret []byte
}

// Ensure EncryptedKeystore implements the Keystorer interface
var _ Keystorer = (*EncryptedKeystore)(nil)

// NewEncryptedKeystore returns a new freshly initialized Keystore
func NewEncryptedKeystore(secret []byte) *EncryptedKeystore {
	if len(secret) != 16 {
		return nil
	}
	return &EncryptedKeystore{
		Keystore: &keystore.Keystore{},
		Secret:   secret,
	}
}

func (enc *EncryptedKeystore) GetIDs() ([]uuid.UUID, error) {
	var ids []uuid.UUID
	for name := range *enc.Keystore {
		if strings.HasPrefix(name, "_") {
			id, err := uuid.Parse(strings.TrimPrefix(name, "_"))
			if err != nil {
				return nil, err
			}
			ids = append(ids, id)
		}
	}
	return ids, nil
}

// GetKey returns a Key from the Keystore
func (enc *EncryptedKeystore) getKey(keyname string) ([]byte, error) {
	return enc.Keystore.Get(keyname, enc.Secret)
}

// SetKey sets a key in the Keystore
func (enc *EncryptedKeystore) setKey(keyname string, keyvalue []byte) error {
	return enc.Keystore.Set(keyname, keyvalue, enc.Secret)
}

func (enc *EncryptedKeystore) GetPrivateKey(id uuid.UUID) ([]byte, error) {
	return enc.getKey(privKeyEntryTitle(id))
}

func (enc *EncryptedKeystore) SetPrivateKey(id uuid.UUID, key []byte) error {
	return enc.setKey(privKeyEntryTitle(id), key)
}

func (enc *EncryptedKeystore) GetPublicKey(id uuid.UUID) ([]byte, error) {
	return enc.getKey(pubKeyEntryTitle(id))
}

func (enc *EncryptedKeystore) SetPublicKey(id uuid.UUID, key []byte) error {
	return enc.setKey(pubKeyEntryTitle(id), key)
}

// MarshalJSON implements the json.Marshaler interface. The Password will not be
// marshaled.
func (enc *EncryptedKeystore) MarshalJSON() ([]byte, error) {
	return json.Marshal(enc.Keystore)
}

// UnmarshalJSON implements the json.Unmarshaler interface. The struct must not be
// null, and the password will not be read from the json, and needs to be set
// seperately.
func (enc *EncryptedKeystore) UnmarshalJSON(b []byte) error {
	return json.Unmarshal(b, enc.Keystore)
}

// privKeyEntryTitle returns a string of the Private Key Entry
func privKeyEntryTitle(id uuid.UUID) string {
	return "_" + id.String()
}

// pubKeyEntryTitle returns a string of the Public Key Entry
func pubKeyEntryTitle(id uuid.UUID) string {
	return id.String()
}
