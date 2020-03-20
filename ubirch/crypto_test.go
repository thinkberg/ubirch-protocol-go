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
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"

	"github.com/google/uuid"
	"github.com/paypal/go.crypto/keystore"
)

// TestCreateKeyStore tests, if a new keystore can be created
func TestCreateKeystore(t *testing.T) {
	asserter := assert.New(t)
	//create new crypto context and check, if the kystore is correct TODO not sure if this test is valid
	var context = &CryptoContext{
		Keystore: &keystore.Keystore{},
		Names:    map[string]uuid.UUID{},
	}
	asserter.IsTypef(&keystore.Keystore{}, context.Keystore, "Keystore creation failed")
}

// TODO saveProtocolContext why is this function in the main
// TODO loadProtocolContext, why is this function in the main
// TODO: Answer, the load and store functions are outside, to keep the protocol outside the keystore

func TestLoadKeystore(t *testing.T) {
	asserter := assert.New(t)
	//	requirer := require.New(t)
	//Set up test objects and parameters
	var context = &CryptoContext{
		Keystore: &keystore.Keystore{},
		Names:    map[string]uuid.UUID{},
	}
	p := Protocol{
		Crypto:     context,
		Signatures: map[uuid.UUID][]byte{},
	}
	asserter.NoErrorf(loadProtocolContext(&p, "test.json"), "Failed loading")
	id := uuid.MustParse(defaultUUID)
	asserter.Nilf(context.GenerateKey(defaultName, id), "Failed to generate Key")
}

func TestSetPrivateKey(t *testing.T) {
	asserter := assert.New(t)
	//Set up test objects and parameters
	var context = &CryptoContext{
		Keystore: &keystore.Keystore{},
		Names:    map[string]uuid.UUID{},
	}
	id := uuid.MustParse(defaultUUID)
	privBytesCorrect, err := hex.DecodeString(defaultPriv)
	asserter.NoErrorf(err, "Decoding private Key Bytes failed")

	privBytesTooLong := append(privBytesCorrect, 0xFF)
	privBytesTooShort := privBytesCorrect[1:]

	// Test valid key length
	asserter.Nilf(context.SetKey(defaultName, id, privBytesCorrect), "set key with correct length failed")
	// Test a key, which is too short
	asserter.Errorf(context.SetKey(defaultName, id, privBytesTooShort), "not recognized too short key")
	// Test a key, which is too long
	asserter.Errorf(context.SetKey(defaultName, id, privBytesTooLong), "not recognized too long key")
	// Test a key, which is empty
	asserter.Errorf(context.SetKey(defaultName, id, nil), "not recognized empty key")
}

func TestSetPublicKey(t *testing.T) {
	asserter := assert.New(t)
	//Set up test objects and parameters
	var context = &CryptoContext{
		Keystore: &keystore.Keystore{},
		Names:    map[string]uuid.UUID{},
	}
	id := uuid.MustParse(defaultUUID)
	pubBytesCorrect, err := hex.DecodeString(defaultPub)
	asserter.NoErrorf(err, "Decoding public key failed")
	pubBytesTooLong := append(pubBytesCorrect, 0xFF)
	pubBytesTooShort := pubBytesCorrect[1:]

	// Test valid key length
	asserter.Nilf(context.SetPublicKey(defaultName, id, pubBytesCorrect), "set key with correct length failed")
	// Test a key, which is too short
	asserter.Errorf(context.SetPublicKey(defaultName, id, pubBytesTooShort), "not recognized too short key")
	// Test a key, which is too long
	asserter.Errorf(context.SetPublicKey(defaultName, id, pubBytesTooLong), "not recognized too long key")
	// Test a key, which is empty
	asserter.Errorf(context.SetPublicKey(defaultName, id, nil), "not recognized empty key")
}

func TestGenerateKey(t *testing.T) {
	asserter := assert.New(t)
	var context = &CryptoContext{
		Keystore: &keystore.Keystore{},
		Names:    map[string]uuid.UUID{},
	}
	id := uuid.MustParse(defaultUUID)

	asserter.Nilf(context.GenerateKey(defaultName, id), "Generating key failed")
	pph, _ := id.MarshalBinary()
	pubKeyBytes, err := context.Keystore.Get("_"+id.String(), pph)
	asserter.Nilf(err, "Getting key failed")
	fmt.Print(hex.Dump(pubKeyBytes))

	name := ""
	asserter.Errorf(context.GenerateKey(name, id), "Generating key without name")
	pph, _ = id.MarshalBinary()
	pubKeyBytes, err = context.Keystore.Get("_"+id.String(), pph)
	asserter.Nilf(err, "Getting key failed")
	fmt.Print(hex.Dump(pubKeyBytes))

	id = uuid.Nil
	asserter.Errorf(context.GenerateKey(defaultName, id), "Generating key without id")
	pph, _ = id.MarshalBinary()
	pubKeyBytes, err = context.Keystore.Get("_"+id.String(), pph)
	asserter.Nilf(err, "Getting key failed")
	fmt.Print(hex.Dump(pubKeyBytes))
	//asserter.Lenf(len(pubKeyBytes), 64, "the key is not in the right format")

}
