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
	"encoding/hex"
	"testing"

	"github.com/google/uuid"
	"github.com/paypal/go.crypto/keystore"
)

func TestSetKey(t *testing.T) {
	//Set up test objects and parameters
	var context = &CryptoContext{
		Keystore: &keystore.Keystore{},
		Names:    map[string]uuid.UUID{},
	}
	id := uuid.MustParse(defaultUUID)
	privBytesCorrect, err := hex.DecodeString(defaultPriv)
	if err != nil {
		panic(err)
	}
	privBytesTooLong := append(privBytesCorrect, 0xFF)
	privBytesTooShort := privBytesCorrect[1:]

	//Test valid key length
	err = context.SetKey(defaultName, id, privBytesCorrect)
	if err != nil {
		t.Errorf("SetKey() failed with error: %v", err)
	}
	err = context.SetKey(defaultName, id, privBytesTooShort)
	if err == nil {
		t.Errorf("SetKey() accepts too short keys.")
	}
	err = context.SetKey(defaultName, id, privBytesTooLong)
	if err == nil {
		t.Errorf("SetKey() accepts too long keys")
	}
}

func TestSetPublicKey(t *testing.T) {
	//Set up test objects and parameters
	var context = &CryptoContext{
		Keystore: &keystore.Keystore{},
		Names:    map[string]uuid.UUID{},
	}
	id := uuid.MustParse(defaultUUID)
	pubBytesCorrect, err := hex.DecodeString(defaultPub)
	if err != nil {
		panic(err)
	}
	pubBytesTooLong := append(pubBytesCorrect, 0xFF)
	pubBytesTooShort := pubBytesCorrect[1:]

	//Test valid key length
	err = context.SetPublicKey(defaultName, id, pubBytesCorrect)
	if err != nil {
		t.Errorf("SetPublicKey() failed with error: %v", err)
	}
	err = context.SetPublicKey(defaultName, id, pubBytesTooShort)
	if err == nil {
		t.Errorf("SetPublicKey() accepts too short keys.")
	}
	err = context.SetPublicKey(defaultName, id, pubBytesTooLong)
	if err == nil {
		t.Errorf("SetPublicKey() accepts too long keys")
	}
}
