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
	return enc.Keystore.Get(keyname, enc.Secret)
}

// SetKey sets a key in the Keystore
func (enc *EncryptedKeystore) SetKey(keyname string, keyvalue []byte) error {
	return enc.Keystore.Set(keyname, keyvalue, enc.Secret)
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
