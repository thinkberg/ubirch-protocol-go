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
	"strings"

	"github.com/google/uuid"
	"github.com/ubirch/go.crypto/keystore"
)

// Keystorer contains the methods that must be implemented by the keystore
// implementation.
type Keystorer interface {
	GetKey(keyname string) ([]byte, error)
	SetKey(keyname string, keyvalue []byte) error

	// Required for saving and restoring
	MarshalJSON() ([]byte, error)
	UnmarshalJSON(b []byte) error
}

// EncryptedKeystore is the reference implementation for a simple keystore.
type EncryptedKeystore struct {
	*keystore.Keystore
	Secret []byte
}

// Ensure EncryptedKeystore implements the Keystorer interface
var _ Keystorer = (*EncryptedKeystore)(nil)

// NewEncryptedKeystore returns a new freshly initialized Keystore
func NewEncryptedKeystore(secret []byte) *EncryptedKeystore {
	return &EncryptedKeystore{
		Keystore: &keystore.Keystore{},
		Secret:   secret,
	}
}

// GetKey returns a Key from the Keystore
func (enc *EncryptedKeystore) GetKey(keyname string) ([]byte, error) {
	content, err := enc.Keystore.Get(keyname, enc.Secret)
	if err != nil {
		// try old format, where the key was derived from the keyname
		// itself.
		if content, err := enc.compatDecrypt(keyname); err == nil {
			return content, nil
		}

		// if that didnt work, return original error.
		return nil, err
	}
	return content, nil
}

// SetKey sets a key in the Keystore
func (enc *EncryptedKeystore) SetKey(keyname string, keyvalue []byte) error {
	return enc.Keystore.Set(keyname, keyvalue, enc.Secret)
}

// compatDecrypt is the compatibility to the old version. Originally the
// kek (key encrypting key) was derived from the UUID.
func (enc *EncryptedKeystore) compatDecrypt(keyname string) ([]byte, error) {
	// Private key entry titles were prefixed with an underscore
	keyname = strings.TrimPrefix(keyname, "_")

	u, err := uuid.Parse(keyname)
	if err != nil {
		return nil, err
	}
	kek, err := u.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return enc.Keystore.Get(keyname, kek)
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
