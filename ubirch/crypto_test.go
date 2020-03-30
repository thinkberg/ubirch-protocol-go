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
 * NOTE:
 * These testing functions include tests, which will fail, because the
 * tested libraries do not yet support the functionality.
 * To perform tests on the already implemented modules, use:
 *
 * `go test -v -test.run=.*([^N].....|[^O]....|[^T]...|[^R]..|[^D].|[^Y])$`
 *
 * which will skip all test with the name `Test...NOTRDY()`
 */

package ubirch

import (
	"encoding/hex"
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"

	"github.com/google/uuid"
	"github.com/paypal/go.crypto/keystore"
)

// TestCreateKeyStore tests, if a new keystore can be created
func TestCreateKeystore(t *testing.T) {
	asserter := assert.New(t)
	//create new crypto context and check, if the kystore is correct TODO not sure if this test is valid
	var kstore = &EncryptedKeystore{
		Keystore: &keystore.Keystore{},
		Secret:   []byte("1234567890123456"),
	}
	var context = &CryptoContext{Keystore: kstore, Names: map[string]uuid.UUID{}}

	asserter.IsTypef(kstore, context.Keystore, "Keystore creation failed")
}

// TODO saveProtocolContext why is this function in the main
// TODO loadProtocolContext, why is this function in the main
// TODO: Answer, the load and store functions are outside, to keep the protocol outside the keystore

// TestTestLoadKeystore uses saveProtocolContext and loadProtocolContext to use the underlying functions
// to set and get content from the Keystore. The content is compared to check if these methods work.
// At the end the temporary file is deleted
func TestLoadKeystore_SaveKeystore(t *testing.T) {
	asserter := assert.New(t)
	//Set up test objects and parameters
	var context = &CryptoContext{
		Keystore: &EncryptedKeystore{
			Keystore: &keystore.Keystore{},
			Secret:   []byte("1234567890123456"),
		},
		Names: map[string]uuid.UUID{},
	}
	p := Protocol{Crypto: context, Signatures: map[uuid.UUID][]byte{}}

	id := uuid.MustParse(defaultUUID)
	asserter.Nilf(p.GenerateKey(defaultName, id), "Generating key failed")
	pubKeyBytesNew, err := p.GetPublicKey(defaultName)
	asserter.Nilf(err, "Getting key failed")
	asserter.NotNilf(pubKeyBytesNew, "Public Key for existing Key empty")
	asserter.NoErrorf(saveProtocolContext(&p, "temp.json"), "Failed Saving protocol context")

	context2 := &CryptoContext{
		Keystore: &EncryptedKeystore{
			Keystore: &keystore.Keystore{},
			Secret:   []byte("1234567890123456"),
		},
		Names: map[string]uuid.UUID{},
	}
	p2 := Protocol{Crypto: context2, Signatures: map[uuid.UUID][]byte{}}
	asserter.NoErrorf(loadProtocolContext(&p2, "temp.json"), "Failed loading protocol context")
	pubKeyBytesLoad, err := p2.GetPublicKey(defaultName)
	asserter.Nilf(err, "Getting Public key failed")
	asserter.NotNilf(pubKeyBytesLoad, "Public Key for existing Key empty")

	asserter.Equalf(pubKeyBytesNew, pubKeyBytesLoad, "Loading failed, because the keys are not equal")
	deleteProtocolContext("temp.json")
}

// TestCryptoContext_GetUUID gets the UUID for a specific name
//		Get UUID without providing context
// 		Get the correct UUID with provided context
//		Get the UUID for unknown Name
func TestCryptoContext_GetUUID(t *testing.T) {
	const (
		unknownName = "NOBODY"
	)
	// prepare
	asserter := assert.New(t)
	var kstore = &EncryptedKeystore{
		Keystore: &keystore.Keystore{},
		Secret:   []byte("1234567890123456"),
	}
	var context = &CryptoContext{Keystore: kstore, Names: map[string]uuid.UUID{}}
	p := Protocol{Crypto: context, Signatures: map[uuid.UUID][]byte{}}

	// test the correct UUID but before loading the context
	id, err := p.GetUUID(defaultName)
	asserter.Errorf(err, "Cannot get UUID")
	asserter.Equalf(id, uuid.Nil, "the uuid is not nil")

	// test the correct UUID, with loaded context
	asserter.NoErrorf(loadProtocolContext(&p, "test.json"), "Failed loading protocol context")
	id, err = p.GetUUID(defaultName)
	asserter.NoErrorf(err, "Cannot get UUID")
	asserter.Equalf(id, uuid.MustParse(defaultUUID), "the uuid is not correct")

	// test the unknown UUID
	id, err = p.GetUUID(unknownName)
	asserter.Errorf(err, "Found unknown UUID")
	asserter.Equalf(id, uuid.Nil, "the uuid is not Nil")
}

// TestCryptoContext_SetPublicKey Tests the set function for a public key
//		Set a public key with correct length
//		Set a public key, which is too long
//		Set a public key, which is too short
//		Set a public key, which is nil
func TestCryptoContext_SetKey(t *testing.T) {
	asserter := assert.New(t)
	//Set up test objects and parameters
	var context = &CryptoContext{
		Keystore: &EncryptedKeystore{
			Keystore: &keystore.Keystore{},
			Secret:   []byte("1234567890123456"),
		},
		Names: map[string]uuid.UUID{},
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

// TestCryptoContext_SetPublicKey Tests the set function for a public key
//		Set a public key with correct length
//		Set a public key, which is too long
//		Set a public key, which is too short
//		Set a public key, which is nil
func TestCryptoContext_SetPublicKey(t *testing.T) {
	asserter := assert.New(t)
	//Set up test objects and parameters
	var context = &CryptoContext{
		Keystore: &EncryptedKeystore{
			Keystore: &keystore.Keystore{},
			Secret:   []byte("2234567890123456"),
		},
		Names: map[string]uuid.UUID{},
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

// TestCryptoContext_GenerateKey tests the generation of a KeyPair
//		Generate key with name
//		Generate Key with empty name
//		Generate Key with no uuid
func TestCryptoContext_GenerateKey(t *testing.T) {
	asserter := assert.New(t)
	var context = &CryptoContext{
		Keystore: &EncryptedKeystore{
			Keystore: &keystore.Keystore{},
			Secret:   []byte("2234567890123456"),
		},
		Names: map[string]uuid.UUID{},
	}
	p := Protocol{Crypto: context, Signatures: map[uuid.UUID][]byte{}}

	asserter.NoErrorf(loadProtocolContext(&p, "test.json"), "Failed loading")
	id := uuid.MustParse(defaultUUID)

	// TODO find out how to chek, if a new key was generated
	asserter.Nilf(p.GenerateKey(defaultName, id), "Generating key failed")
	pubKeyBytes, err := p.GetPublicKey(defaultName)
	asserter.NoErrorf(err, "Getting Public key failed")
	asserter.NotNilf(pubKeyBytes, "Public Key for existing Key empty")
	privKeyBytes, err := getPrivateKey(context, defaultName)
	asserter.NoErrorf(err, "Getting Private key failed")
	asserter.NotNilf(privKeyBytes, "Private Key for existing Key empty")

	// TODO find out how to chek, if a new key was generated
	// generate key with empty name
	name := ""
	asserter.Errorf(p.GenerateKey(name, id), "Generating key without name")
	pubKeyBytes, err = p.GetPublicKey(name)
	asserter.Errorf(err, "Getting Public without name")
	asserter.Nilf(pubKeyBytes, "Public Key without name not empty")
	privKeyBytes, err = getPrivateKey(context, name)
	asserter.Errorf(err, "Getting Private Key without name")
	asserter.Nilf(privKeyBytes, "Private Key without name not empty")

	// generate Keypair with uuid = 00000000-0000-0000-0000-000000000000
	id = uuid.Nil
	asserter.Errorf(p.GenerateKey(defaultName, id), "Generating key without id")
	pubKeyBytes, err = p.GetPublicKey(name)
	asserter.Errorf(err, "Getting Public without uuid")
	asserter.Nilf(pubKeyBytes, "Public Key without uuid not empty")
	privKeyBytes, err = getPrivateKey(context, name)
	asserter.Errorf(err, "Getting Private Key without uuid")
	asserter.Nilf(privKeyBytes, "Private Key without uuid not empty")
}

// TestGetPublicKey
//		Get not existing key
//		Get new generated key
//		Get Key from file and compare with generated key
func TestCryptoContext_GetPublicKey(t *testing.T) {
	const (
		unknownName = "NOBODY"
	)
	asserter := assert.New(t)
	var context = &CryptoContext{
		Keystore: &EncryptedKeystore{
			Keystore: &keystore.Keystore{},
			Secret:   []byte("2234567890123456"),
		},
		Names: map[string]uuid.UUID{},
	}
	p := Protocol{Crypto: context, Signatures: map[uuid.UUID][]byte{}}
	// check for non existing key
	pubKeyBytes, err := p.GetPublicKey(unknownName)
	asserter.Errorf(err, "Getting non exisitng Public key failed")
	asserter.Nilf(pubKeyBytes, "Public Key for non existing Key not empty")

	// check for new generated key
	id := uuid.MustParse(defaultUUID)
	asserter.Nilf(p.GenerateKey(defaultName, id), "Generating key failed")
	pubKeyBytesNew, err := p.GetPublicKey(defaultName)
	asserter.NoErrorf(err, "Getting Public key failed")
	asserter.NotNilf(pubKeyBytesNew, "Public Key for existing Key empty")

	// load the protocol and check if the Public key remains the same, as the new generated
	asserter.NoErrorf(loadProtocolContext(&p, "test.json"), "Failed loading")
	pubKeyBytesLoad, err := p.GetPublicKey(defaultName)
	asserter.NoErrorf(err, "Getting Public key failed")
	asserter.NotEqualf(pubKeyBytesLoad, pubKeyBytesNew, "the public key did not change")
}

// TestCryptoContext_GetPrivateKey performs tests to get the PrivateKey, which is not a library function, but
// provides test results for the underlying functions
//		Get not existing key
//		Get new generated key
//		Get Key from file and compare with generated key
func TestCryptoContext_GetPrivateKey(t *testing.T) {
	const (
		unknownName = "NOBODY"
	)
	asserter := assert.New(t)
	var context = &CryptoContext{Keystore: &keystore.Keystore{}, Names: map[string]uuid.UUID{}}
	p := Protocol{Crypto: context, Signatures: map[uuid.UUID][]byte{}}
	// check for non existing key
	privKeyBytes, err := getPrivateKey(context, unknownName)
	asserter.Errorf(err, "Getting non exisitng Public key failed")
	asserter.Nilf(privKeyBytes, "Public Key for non existing Key not empty")

	// check for new generated key
	id := uuid.MustParse(defaultUUID)
	asserter.Nilf(p.GenerateKey(defaultName, id), "Generating key failed")
	privKeyBytesNew, err := getPrivateKey(context, defaultName)
	asserter.NoErrorf(err, "Getting Public key failed")
	asserter.NotNilf(privKeyBytesNew, "Public Key for existing Key empty")

	// load the protocol and check if the Private key remains the same, as the new generated
	asserter.NoErrorf(loadProtocolContext(&p, "test.json"), "Failed loading")
	privKeyBytesLoad, err := getPrivateKey(context, defaultName)
	asserter.NoErrorf(err, "Getting Public key failed")
	asserter.NotEqualf(privKeyBytesLoad, privKeyBytesNew, "the public key did not change")
}

// TestCryptoContext_GetCSR_NOTRDY the required method is not implemented yet
func TestCryptoContext_GetCSR_NOTRDY(t *testing.T) {
	asserter := assert.New(t)
	var context = &CryptoContext{
		Keystore: &EncryptedKeystore{
			Keystore: &keystore.Keystore{},
			Secret:   []byte("2234567890123456"),
		},
		Names: map[string]uuid.UUID{},
	}
	p := Protocol{Crypto: context, Signatures: map[uuid.UUID][]byte{}}
	certificate, err := p.GetCSR(defaultName)
	asserter.Nilf(err, "Getting CSR failed")
	asserter.NotNilf(certificate, "The Certificate is \"Nil\"")
	t.Errorf("not implemented")
}

// TestCryptoContext_Sign test the (CryptoContext) Sign function with defaultData, which should pass
func TestCryptoContext_Sign(t *testing.T) {
	var tests = []struct {
		testName    string
		name        string
		UUID        string
		privateKey  string
		hashForSign string
	}{
		{
			testName:    "DEFAULT",
			name:        defaultName,
			UUID:        defaultUUID,
			privateKey:  defaultPriv,
			hashForSign: defaultHash,
		},
	}

	//Iterate over all tests
	for _, currTest := range tests {
		//Create identifier to append to test name
		t.Run(currTest.testName, func(t *testing.T) {
			asserter := assert.New(t)
			requirer := require.New(t)

			//Create new crypto context
			var context = &CryptoContext{Keystore: &keystore.Keystore{}, Names: map[string]uuid.UUID{}}
			id := uuid.MustParse(currTest.UUID)
			privBytes, err := hex.DecodeString(currTest.privateKey)
			//Check created UPP (data/structure only, signature is checked later)
			hashBytes, err := hex.DecodeString(currTest.hashForSign)
			requirer.NoErrorf(err, "Test configuration string (hashForSign) can't be decoded.\nString was: %v", currTest.hashForSign)
			//Set the PrivateKey and check, that it is set correct
			requirer.NoErrorf(context.SetKey(currTest.name, id, privBytes), "Setting the Private Key failed")

			//Call Sign() and assert error
			signature, err := context.Sign(id, hashBytes)
			asserter.NoErrorf(err, "Sign() returned an error for valid input")
			asserter.NotNilf(signature, "the signature should not be Nil")
		})
	}
}

// TestCryptoContext_SignFails performs the (CryptoContext) Sign tests, which fail, due to incorrect parameters
func TestCryptoContext_SignFails(t *testing.T) {
	var tests = []struct {
		testName    string
		name        string
		UUID        uuid.UUID
		UUIDforKey  uuid.UUID
		privateKey  string
		hashForSign string
	}{
		{
			testName:    "uuid.Nil",
			name:        defaultName,
			UUID:        uuid.Nil,
			UUIDforKey:  uuid.MustParse(defaultUUID),
			privateKey:  defaultPriv,
			hashForSign: defaultHash,
		},
		{
			testName:    "uuidUnknown",
			name:        defaultName,
			UUID:        uuid.MustParse("12345678-1234-1234-1234-123456789abc"),
			UUIDforKey:  uuid.MustParse(defaultUUID),
			privateKey:  defaultPriv,
			hashForSign: defaultHash,
		},
		{
			testName:    "noData",
			name:        defaultName,
			UUID:        uuid.MustParse(defaultUUID),
			UUIDforKey:  uuid.MustParse(defaultUUID),
			privateKey:  defaultPriv,
			hashForSign: "", // empty hash/data
		},
	}

	//Iterate over all tests
	for _, currTest := range tests {
		//Create identifier to append to test name
		t.Run(currTest.testName, func(t *testing.T) {
			asserter := assert.New(t)
			requirer := require.New(t)

			//Create new crypto context
			var context = &CryptoContext{Keystore: &keystore.Keystore{}, Names: map[string]uuid.UUID{}}
			privBytes, err := hex.DecodeString(currTest.privateKey)
			//Check created UPP (data/structure only, signature is checked later)
			hashBytes, err := hex.DecodeString(currTest.hashForSign)
			//fmt.Printf("HASH: %v", hashBytes)
			requirer.NoErrorf(err, "Test configuration string (hashForSign) can't be decoded.\nString was: %v", currTest.hashForSign)
			// Set the PrivateKey and checkt, that it was set correctly
			requirer.NoErrorf(context.SetKey(currTest.name, currTest.UUIDforKey, privBytes), "Setting the Private Key failed")

			fmt.Printf("data len %v", len(hashBytes))
			//Call Sign() and assert error
			signature, err := context.Sign(currTest.UUID, hashBytes)
			asserter.Errorf(err, "Sign() did not return an error for invalid input")
			asserter.Nilf(signature, "the signature should be Nil, but is not")
		})
	}
}

func TestCryptoContext_Verify(t *testing.T) {
	var tests = []struct {
		testName          string
		name              string
		UUID              string
		publicKey         string
		signatureToVerify string
		dataToVerify      string
	}{
		{
			testName:          "DEFAULT",
			name:              defaultName,
			UUID:              defaultUUID,
			publicKey:         defaultPub,
			signatureToVerify: "b9fbd39289ac3d464662bb1277d183b697282bc08c56b6dba986b32f7a2778134441b006683a242733a80ef7f732cdbb6e9455d33f7a4350086b075db8f10d75",
			dataToVerify:      defaultHash,
		},
	}

	//Iterate over all tests
	for _, currTest := range tests {
		//Create identifier to append to test name
		t.Run(currTest.testName, func(t *testing.T) {
			asserter := assert.New(t)
			requirer := require.New(t)

			//Create new crypto context
			var context = &CryptoContext{Keystore: &keystore.Keystore{}, Names: map[string]uuid.UUID{}}
			id := uuid.MustParse(currTest.UUID)
			pubBytes, err := hex.DecodeString(currTest.publicKey)
			requirer.NoErrorf(err, "Test configuration string (UUID) can't be decoded.\nString was: %v", currTest.UUID)
			//Check inputs (data/structure only, signature is checked later)
			signatureBytes, err := hex.DecodeString(currTest.signatureToVerify)
			requirer.NoErrorf(err, "Test configuration string (signatureToVerify) can't be decoded.\nString was: %v", currTest.signatureToVerify)
			dataBytes, err := hex.DecodeString(currTest.dataToVerify)
			requirer.NoErrorf(err, "Test configuration string (dataToVerify) can't be decoded.\nString was: %v", currTest.dataToVerify)
			//Set the PublicKey for the Verification and check, that it is set correctly
			requirer.NoErrorf(context.SetPublicKey(currTest.name, id, pubBytes), "Setting the Private Key failed")

			//Call Verify() and assert error
			valid, err := context.Verify(id, dataBytes, signatureBytes)
			asserter.NoErrorf(err, "An unexpected error occured")
			asserter.Truef(valid, "the verification failed")
		})
	}
}

// TestCryptoContext_Verify performs fail tests for the (CryptoContext) Verify function
func TestCryptoContext_VerifyFails(t *testing.T) {
	var tests = []struct {
		testName          string
		name              string
		UUID              uuid.UUID
		UUIDforKey        uuid.UUID
		publicKey         string
		signatureToVerify string
		dataToVerify      string
	}{
		{
			testName:          "uuid.Nil",
			name:              defaultName,
			UUID:              uuid.Nil,
			UUIDforKey:        uuid.MustParse(defaultUUID),
			publicKey:         defaultPub,
			signatureToVerify: "b9fbd39289ac3d464662bb1277d183b697282bc08c56b6dba986b32f7a2778134441b006683a242733a80ef7f732cdbb6e9455d33f7a4350086b075db8f10d75",
			dataToVerify:      defaultHash,
		},
		{
			testName:          "uuidUnknown",
			name:              defaultName,
			UUID:              uuid.MustParse("12345678-1234-1234-1234-123456789abc"),
			UUIDforKey:        uuid.MustParse(defaultUUID),
			publicKey:         defaultPub,
			signatureToVerify: "b9fbd39289ac3d464662bb1277d183b697282bc08c56b6dba986b32f7a2778134441b006683a242733a80ef7f732cdbb6e9455d33f7a4350086b075db8f10d75",
			dataToVerify:      defaultHash,
		},
		{
			testName:          "noHash",
			name:              defaultName,
			UUID:              uuid.MustParse(defaultUUID),
			UUIDforKey:        uuid.MustParse(defaultUUID),
			publicKey:         defaultPub,
			signatureToVerify: "b9fbd39289ac3d464662bb1277d183b697282bc08c56b6dba986b32f7a2778134441b006683a242733a80ef7f732cdbb6e9455d33f7a4350086b075db8f10d75",
			dataToVerify:      "",
		},
		{
			testName:          "noSignature",
			name:              defaultName,
			UUID:              uuid.MustParse(defaultUUID),
			UUIDforKey:        uuid.MustParse(defaultUUID),
			publicKey:         defaultPub,
			signatureToVerify: "",
			dataToVerify:      defaultHash,
		},
	}

	//Iterate over all tests
	for _, currTest := range tests {
		//Create identifier to append to test name
		t.Run(currTest.testName, func(t *testing.T) {
			asserter := assert.New(t)
			requirer := require.New(t)

			//Create new crypto context
			var context = &CryptoContext{Keystore: &keystore.Keystore{}, Names: map[string]uuid.UUID{}}
			pubBytes, err := hex.DecodeString(currTest.publicKey)
			//Check the inputs (data/structure only, signature is checked later)
			signatureBytes, err := hex.DecodeString(currTest.signatureToVerify)
			requirer.NoErrorf(err, "Test configuration string (signatureToVerify) can't be decoded.\nString was: %v", currTest.signatureToVerify)
			dataBytes, err := hex.DecodeString(currTest.dataToVerify)
			requirer.NoErrorf(err, "Test configuration string (dataToVerify) can't be decoded.\nString was: %v", currTest.dataToVerify)
			// deliberately set UUIDforKey and not the UUID
			requirer.NoErrorf(context.SetPublicKey(currTest.name, currTest.UUIDforKey, pubBytes), "Setting the Private Key failed")

			//Call Verify() with UUID and assert error
			valid, err := context.Verify(currTest.UUID, dataBytes, signatureBytes)
			asserter.Errorf(err, "No error was returned from the Verification")
			asserter.Falsef(valid, "the verification succeeded unexpected")
		})
	}
}
