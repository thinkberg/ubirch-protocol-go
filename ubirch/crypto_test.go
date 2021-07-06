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
	"flag"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//Flags used for testing pkcs#11 implementations of ubirch.crypto (as opposed to go library ubirch.crypto.)
var pkcs11CryptoTests = flag.Bool("pkcs11CryptoTests", false, "perform tests using the pkcs#11 implementation of crypto where possible")
var pkcs11LibLocation = flag.String("pkcs11LibLocation", "library_file.so", "where to find the pkcs#11 library file")
var pkcs11SlotUserPin = flag.String("pkcs11SlotUserPin", "0000", "PIN for logging in the pkcs#11 user")

// TestCreateKeyStore tests, if a new keystore can be created. Generally incompatible with pkcs#11 crypto. (No keystore.)
func TestCreateKeystore(t *testing.T) {
	asserter := assert.New(t)
	//create new crypto context and check, if the kystore is correct TODO not sure if this test is valid
	var kstore = NewEncryptedKeystore([]byte(defaultSecret))
	var context = &ECDSACryptoContext{Keystore: kstore}

	asserter.IsTypef(kstore, context.Keystore, "Keystore creation failed")
}

// TODO saveProtocolContext why is this function in the main
// TODO loadProtocolContext, why is this function in the main
// TODO: Answer, the load and store functions are outside, to keep the protocol outside the keystore

//TestCryptoContext_FaultyKeystores tests proper behavior with faulty keystores such as nil/uninitialized. Generally incompatible with pkcs#11 crypto. (No keystore.)
func TestCryptoContext_FaultyKeystores(t *testing.T) {
	var tests = []struct {
		testName       string
		faultyKeystore Keystorer
	}{
		{
			testName:       "ExplicitNilNewkeystore",
			faultyKeystore: nil, //keystore is (nil)
		},
		{
			testName:       "ErrorCreatingNewKeystore",
			faultyKeystore: NewEncryptedKeystore([]byte("")), //no proper secret given -> (*EncryptedKeystore)(nil) is returned
		},
	}
	//Iterate over all tests
	for _, currTest := range tests {
		t.Run(currTest.testName, func(t *testing.T) {
			asserter := assert.New(t)

			//create the Context with the faulty keystore
			var kstore = currTest.faultyKeystore
			var context = &ECDSACryptoContext{Keystore: kstore}

			//Test all the (keystore-using) functions of the ECDSACryptoContext interface for proper behavior
			//(no panics, error returned instead)
			//context.GenerateKey
			testUUID := uuid.MustParse(defaultUUID)
			err := context.GenerateKey(testUUID)
			asserter.Error(err, "GenerateKey() did not return an error for a faulty keystore")
			//context.GetCSR
			bytes, err := context.GetCSR(testUUID, "DE", "Test GmbH")
			asserter.Error(err, "GetCSR() did not return an error for a faulty keystore")
			asserter.Nil(bytes, "GetCSR() did return data for a faulty keystore")
			//context.SetKey
			err = context.SetKey(testUUID, make([]byte, nistp256PrivkeyLength))
			asserter.Error(err, "SetKey() did not return an error for a faulty keystore")
			//context.PrivateKeyExists (make sure setkey is tried firstm so we don't get an error just because of "no key")
			result, err := context.PrivateKeyExists(testUUID)
			asserter.Error(err, "PrivateKeyExists(): no error for faulty keystore")
			asserter.False(result, "Private key found in faulty keystore")
			//context.SetPublicKey
			err = context.SetPublicKey(testUUID, make([]byte, nistp256PubkeyLength))
			asserter.Error(err, "SetPublicKey() did not return an error for a faulty keystore")
			//context.Sign
			bytes, err = context.Sign(testUUID, []byte("justsomedata"))
			asserter.Error(err, "context.Sign() did not return an error for a faulty keystore")
			asserter.Nil(bytes, "context.Sign() did return data for a faulty keystore")
			//context.Verify (since this does not use a matching signature, the test will always fail,
			//but the main purpose of the test is to catch panics caused by the faulty keystore)
			result, err = context.Verify(testUUID, []byte("justsomedata"), make([]byte, nistp256SignatureLength))
			asserter.Error(err, "context.Verify() did not return an error for a faulty keystore")
			asserter.False(result, "context.Verify() incorrect signature is verifiable with faulty keystore")
		})
	}
}

// TestTestLoadKeystore uses saveProtocolContext and loadProtocolContext to use the underlying functions
// to set and get content from the Keystore. The content is compared to check if these methods work.
// At the end the temporary file is deleted. Generally incompatible with pkcs#11 crypto. (No keystore.)
func TestLoadKeystore_SaveKeystore(t *testing.T) {
	asserter := assert.New(t)
	//Set up test objects and parameters
	var context = &ECDSACryptoContext{
		Keystore: NewEncryptedKeystore([]byte(defaultSecret)),
	}
	p := NewExtendedProtocol(context, map[uuid.UUID][]byte{})

	id := uuid.MustParse(defaultUUID)
	asserter.Nilf(p.GenerateKey(id), "Generating key failed")
	pubKeyBytesNew, err := p.GetPublicKey(id)
	asserter.Nilf(err, "Getting key failed")
	asserter.NotNilf(pubKeyBytesNew, "Public Key for existing Key empty")
	asserter.NoErrorf(saveProtocolContext(p, "temp.json"), "Failed Saving protocol context")

	context2 := &ECDSACryptoContext{
		Keystore: NewEncryptedKeystore([]byte(defaultSecret)),
	}
	p2 := NewExtendedProtocol(context2, map[uuid.UUID][]byte{})
	asserter.NoErrorf(loadProtocolContext(p2, "temp.json"), "Failed loading protocol context")
	pubKeyBytesLoad, err := p2.GetPublicKey(id)
	asserter.Nilf(err, "Getting Public key failed")
	asserter.NotNilf(pubKeyBytesLoad, "Public Key for existing Key empty")

	asserter.Equalf(pubKeyBytesNew, pubKeyBytesLoad, "Loading failed, because the keys are not equal")
	asserter.NoErrorf(deleteProtocolContext("temp.json"), "context not deleted")
}

// TestCryptoContext_SetKey Tests the set function for a private key. Supports pkcs#11 crypto.
//		Set a private key with correct length
//		Set a private key, which is too long
//		Set a private key, which is too short
//		Set a private key, which is nil
//		Set a private key, which has correct length but is an invalid elliptic curve private key value
func TestCryptoContext_SetKey(t *testing.T) {
	asserter := assert.New(t)
	requirer := require.New(t)
	//Set up test objects and parameters
	//create golang or pkcs#11 crypto context depending on test settings
	var context Crypto
	var err error
	if *pkcs11CryptoTests { // if pkcs#11 interface should be used
		context, err = NewECDSAPKCS11CryptoContext(
			*pkcs11LibLocation,
			*pkcs11SlotUserPin,
			0,
			false,
			2,
			50*time.Millisecond)
		requirer.NoError(err, "creating new pkcs#11 crypto context failed")
		defer context.Close() //TODO: handle error?
	} else {
		context = &ECDSACryptoContext{
			Keystore: NewEncryptedKeystore([]byte(defaultSecret)),
		}
		defer context.Close() //TODO: handle error?
	}

	id := uuid.MustParse(defaultUUID)
	privBytesCorrect, err := hex.DecodeString(defaultPriv)
	requirer.NoErrorf(err, "Decoding private Key Bytes failed")

	privBytesTooLong := append(privBytesCorrect, 0xFF)
	privBytesTooShort := privBytesCorrect[1:]
	privBytesInvalid, err := hex.DecodeString("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	requirer.NoErrorf(err, "Decoding invalid key bytes failed")

	// Test valid key length
	asserter.Nilf(context.SetKey(id, privBytesCorrect), "set key with correct length failed")
	if *pkcs11CryptoTests { //remove key from HSM again if this is a pkcs 11 test
		requirer.NoError(pkcs11DeleteKeypair(context, id))
	}
	// Test a key, which is too short
	asserter.Errorf(context.SetKey(id, privBytesTooShort), "not recognized too short key")
	if *pkcs11CryptoTests { //remove key from HSM again if this is a pkcs 11 test
		requirer.NoError(pkcs11DeleteKeypair(context, id))
	}
	// Test a key, which is too long
	asserter.Errorf(context.SetKey(id, privBytesTooLong), "not recognized too long key")
	if *pkcs11CryptoTests { //remove key from HSM again if this is a pkcs 11 test
		requirer.NoError(pkcs11DeleteKeypair(context, id))
	}
	// Test a key, which is empty
	asserter.Errorf(context.SetKey(id, nil), "not recognized empty key")
	if *pkcs11CryptoTests { //remove key from HSM again if this is a pkcs 11 test
		requirer.NoError(pkcs11DeleteKeypair(context, id))
	}
	// Test a key, which is an invalid elliptic curve private key value
	asserter.Errorf(context.SetKey(id, privBytesInvalid), "not recognized invalid key")
	if *pkcs11CryptoTests { //remove key from HSM again if this is a pkcs 11 test
		requirer.NoError(pkcs11DeleteKeypair(context, id))
	}
}

// TestCryptoContext_SetPublicKey Tests the set function for a public key. Incompatible with pkcs#11 crypto. (No SetPublicKey() for HSMs)
//		Set a public key with correct length
//		Set a public key, which is too long
//		Set a public key, which is too short
//		Set a public key, which is nil
//		Set a public key, which has correct length but is an invalid elliptic curve public key value
func TestCryptoContext_SetPublicKey(t *testing.T) {
	asserter := assert.New(t)
	requirer := require.New(t)
	//Set up test objects and parameters
	var context = &ECDSACryptoContext{
		Keystore: NewEncryptedKeystore([]byte(defaultSecret)),
	}

	id := uuid.MustParse(defaultUUID)
	pubBytesCorrect, err := hex.DecodeString(defaultPub)
	requirer.NoErrorf(err, "Decoding public key failed")

	pubBytesTooLong := append(pubBytesCorrect, 0xFF)
	pubBytesTooShort := pubBytesCorrect[1:]
	pubBytesInvalid, err := hex.DecodeString("55f0feac4f2bcf879330eff348422ab3abf5237a24acaf0aef3bb876045c4e532fbd6cd8e265f6cf28b46e7e4512cd06ba84bcd3300efdadf28750f43dafd777")
	requirer.NoErrorf(err, "Decoding invalid key bytes failed")

	// Test valid key length
	asserter.Nilf(context.SetPublicKey(id, pubBytesCorrect), "set key with correct length failed")
	// Test a key, which is too short
	asserter.Errorf(context.SetPublicKey(id, pubBytesTooShort), "not recognized too short key")
	// Test a key, which is too long
	asserter.Errorf(context.SetPublicKey(id, pubBytesTooLong), "not recognized too long key")
	// Test a key, which is empty
	asserter.Errorf(context.SetPublicKey(id, nil), "not recognized empty key")
	// Test a key, which is an invalid elliptic curve public key value
	asserter.Errorf(context.SetPublicKey(id, pubBytesInvalid), "not recognized invalid key")
}

// TestCryptoContext_GenerateKey tests the generation of a KeyPair. Supports pkcs#11 crypto.
//		Generate key with uuid
//		Generate Key with no uuid
func TestCryptoContext_GenerateKey(t *testing.T) {
	//TODO: move deleting keypair from HSM into helper function
	asserter := assert.New(t)
	requirer := require.New(t)
	var err error

	//create golang or pkcs#11 crypto context depending on test settings
	var context Crypto
	if *pkcs11CryptoTests { // if pkcs#11 interface should be used
		context, err = NewECDSAPKCS11CryptoContext(
			*pkcs11LibLocation,
			*pkcs11SlotUserPin,
			0,
			false,
			2,
			50*time.Millisecond)
		requirer.NoError(err, "creating new pkcs#11 crypto context failed")
		defer context.Close() //TODO: handle error when closing?
	} else {
		context = &ECDSACryptoContext{
			Keystore: NewEncryptedKeystore([]byte(defaultSecret)),
		}
		defer context.Close() //TODO: handle error when closing?
	}

	p := NewExtendedProtocol(context, map[uuid.UUID][]byte{})

	//Generate Key with valid uuid
	id := uuid.MustParse(defaultUUID)
	asserter.Nilf(p.GenerateKey(id), "Generating key failed")
	pubKeyBytes, err := p.GetPublicKey(id)
	asserter.NoErrorf(err, "Getting Public key failed")
	asserter.NotNilf(pubKeyBytes, "Public Key for existing Key empty")
	if !*pkcs11CryptoTests { // can't get private keys from HSMs, so skip this part
		privKeyBytes, err := getPrivateKey(context.(*ECDSACryptoContext), id)
		asserter.NoErrorf(err, "Getting Private key failed")
		asserter.NotNilf(privKeyBytes, "Private Key for existing Key empty")
	}
	if *pkcs11CryptoTests { //remove key from HSM again if this is a pkcs 11 test
		requirer.NoError(pkcs11DeleteKeypair(context, id))
	}

	// generate Keypair with uuid = 00000000-0000-0000-0000-000000000000
	id = uuid.Nil
	asserter.Errorf(p.GenerateKey(id), "Generating key without id")
	pubKeyBytes, err = p.GetPublicKey(id)
	asserter.Errorf(err, "Getting Public without uuid")
	asserter.Nilf(pubKeyBytes, "Public Key without uuid not empty")
	if !*pkcs11CryptoTests { // can't get private keys from HSMs
		privKeyBytes, err := getPrivateKey(context.(*ECDSACryptoContext), id)
		asserter.Errorf(err, "Getting Private Key without uuid")
		asserter.Nilf(privKeyBytes, "Private Key without uuid not empty")
	}
	if *pkcs11CryptoTests { //remove key from HSM again if this is a pkcs 11 test
		requirer.NoError(pkcs11DeleteKeypair(context, id))
	}
}

// TestGetPublicKey
//		Get not existing key
//		Get new generated key
//		Get Key from file and compare with generated key
// TODO: add support for pkcs#11 crypto
func TestCryptoContext_GetPublicKey(t *testing.T) {
	const (
		unknownID = "12345678-1234-1234-1234-123456789012"
	)
	asserter := assert.New(t)
	var context = &ECDSACryptoContext{
		Keystore: NewEncryptedKeystore([]byte(defaultSecret)),
	}
	p := NewExtendedProtocol(context, map[uuid.UUID][]byte{})
	// check for non existing key
	pubKeyBytes, err := p.GetPublicKey(uuid.MustParse(unknownID))
	asserter.Errorf(err, "Getting non existing Public key did not fail as expected")
	asserter.Nilf(pubKeyBytes, "Public Key for non existing Key not empty")

	// check for new generated key
	id := uuid.MustParse(defaultUUID)
	asserter.NoError(p.GenerateKey(id), "Generating key failed")
	pubKeyBytesNew, err := p.GetPublicKey(id)
	asserter.NoError(err, "Getting Public key failed")
	asserter.NotNilf(pubKeyBytesNew, "Public Key for existing Key empty")
	asserter.Equal(lenPubkeyECDSA, len(pubKeyBytesNew), "len(public key) not correct for a public key")

	// load the protocol and check if the Public key remains the same, as the new generated
	asserter.NoErrorf(loadProtocolContext(p, "test2.json"), "Failed loading")
	pubKeyBytesLoad, err := p.GetPublicKey(id)
	asserter.NoError(err, "Getting Public key failed")
	asserter.NotEqualf(pubKeyBytesLoad, pubKeyBytesNew, "the public key did not change when loading context")
}

// TestCryptoContext_GetPrivateKey performs tests to get the PrivateKey, which is not a library function, but
// provides test results for the underlying functions. Generally incompatible with pkcs#11 crypto. (Private key never leaves HSM.)
//		Get not existing key
//		Get new generated key
//		Get Key from file and compare with generated key
func TestCryptoContext_GetPrivateKey(t *testing.T) {
	const (
		unknownID = "12345678-1234-1234-1234-123456789012"
	)
	asserter := assert.New(t)
	var context = &ECDSACryptoContext{
		Keystore: NewEncryptedKeystore([]byte(defaultSecret)),
	}
	p := NewExtendedProtocol(context, map[uuid.UUID][]byte{})
	// check for non existing key
	privKeyBytes, err := getPrivateKey(context, uuid.MustParse(unknownID))
	asserter.Errorf(err, "Getting non exisitng Public key failed")
	asserter.Nilf(privKeyBytes, "Public Key for non existing Key not empty")

	// check for new generated key
	id := uuid.MustParse(defaultUUID)
	asserter.Nilf(p.GenerateKey(id), "Generating key failed")
	privKeyBytesNew, err := getPrivateKey(context, id)
	asserter.NoErrorf(err, "Getting Private key failed")
	asserter.NotNilf(privKeyBytesNew, "Private Key for existing Key empty")
	asserter.Containsf(string(privKeyBytesNew), "-----BEGIN PRIVATE KEY-----", "not a private key")

	// load the protocol and check if the Private key remains the same, as the new generated
	asserter.NoErrorf(loadProtocolContext(p, "test2.json"), "Failed loading")
	privKeyBytesLoad, err := getPrivateKey(context, id)
	asserter.NoErrorf(err, "Getting Private key failed")
	asserter.NotEqualf(privKeyBytesLoad, privKeyBytesNew, "the Private key did not change")
	asserter.Containsf(string(privKeyBytesLoad), "-----BEGIN PRIVATE KEY-----", "not a private key")
}

// TestCryptoContext_GetCSR_NOTRDY the required method is not implemented yet
func TestCryptoContext_GetCSR_NOTRDY(t *testing.T) {
	// asserter := assert.New(t)
	// var context = &ECDSACryptoContext{
	// 	Keystore: NewEncryptedKeystore([]byte(defaultSecret)),
	// 	Names:    map[string]uuid.UUID{},
	// }
	// p := Protocol{Crypto: context, signatures: map[uuid.UUID][]byte{}}
	// certificate, err := p.GetCSR(defaultName)
	// asserter.Nilf(err, "Getting CSR failed")
	// asserter.NotNilf(certificate, "The Certificate is \"Nil\"")
	t.Errorf("not implemented")
}

// TestCryptoContext_Sign test the (ECDSACryptoContext) Sign function with defaultData, which should pass.
//TODO: add support for pkcs#11 crypto
func TestCryptoContext_Sign(t *testing.T) {
	var tests = []struct {
		testName    string
		UUID        string
		privateKey  string
		hashForSign string
	}{
		{
			testName:    "DEFAULT",
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
			var context = &ECDSACryptoContext{
				Keystore: NewEncryptedKeystore([]byte(defaultSecret)),
			}
			id := uuid.MustParse(currTest.UUID)
			privBytes, err := hex.DecodeString(currTest.privateKey)
			//Check created UPP (data/structure only, signature is checked later)
			hashBytes, err := hex.DecodeString(currTest.hashForSign)
			requirer.NoErrorf(err, "Test configuration string (hashForSign) can't be decoded.\nString was: %v", currTest.hashForSign)
			//Set the PrivateKey and check, that it is set correct
			requirer.NoErrorf(context.SetKey(id, privBytes), "Setting the Private Key failed")

			//Call Sign() and assert error
			signature, err := context.Sign(id, hashBytes)
			asserter.NoErrorf(err, "Sign() returned an error for valid input")
			asserter.NotNilf(signature, "the signature should not be Nil")
		})
	}
}

// TestCryptoContext_SignFails performs the (ECDSACryptoContext) Sign tests, which fail, due to incorrect parameters
// TODO: add support for pkcs#11 crypto
func TestCryptoContext_SignFails(t *testing.T) {
	var tests = []struct {
		testName    string
		UUID        uuid.UUID
		UUIDforKey  uuid.UUID
		privateKey  string
		hashForSign string
	}{
		{
			testName:    "uuid.Nil",
			UUID:        uuid.Nil,
			UUIDforKey:  uuid.MustParse(defaultUUID),
			privateKey:  defaultPriv,
			hashForSign: defaultHash,
		},
		{
			testName:    "uuidUnknown",
			UUID:        uuid.MustParse("12345678-1234-1234-1234-123456789abc"),
			UUIDforKey:  uuid.MustParse(defaultUUID),
			privateKey:  defaultPriv,
			hashForSign: defaultHash,
		},
		{
			testName:    "noData",
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
			var context = &ECDSACryptoContext{
				Keystore: NewEncryptedKeystore([]byte(defaultSecret)),
			}
			privBytes, err := hex.DecodeString(currTest.privateKey)
			//Check created UPP (data/structure only, signature is checked later)
			hashBytes, err := hex.DecodeString(currTest.hashForSign)
			//fmt.Printf("HASH: %v", hashBytes)
			requirer.NoErrorf(err, "Test configuration string (hashForSign) can't be decoded.\nString was: %v", currTest.hashForSign)
			// Set the PrivateKey and checkt, that it was set correctly
			requirer.NoErrorf(context.SetKey(currTest.UUIDforKey, privBytes), "Setting the Private Key failed")

			//Call Sign() and assert error
			signature, err := context.Sign(currTest.UUID, hashBytes)
			asserter.Errorf(err, "Sign() did not return an error for invalid input")
			asserter.Nilf(signature, "the signature should be Nil, but is not")
		})
	}
}

// TODO: add support for pkcs#11 crypto
func TestCryptoContext_Verify(t *testing.T) {
	var tests = []struct {
		testName          string
		UUID              string
		publicKey         string
		signatureToVerify string
		dataToVerify      string
	}{
		{
			testName:          "DEFAULT",
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
			var context = &ECDSACryptoContext{
				Keystore: NewEncryptedKeystore([]byte(defaultSecret)),
			}
			id := uuid.MustParse(currTest.UUID)
			pubBytes, err := hex.DecodeString(currTest.publicKey)
			requirer.NoErrorf(err, "Test configuration string (UUID) can't be decoded.\nString was: %v", currTest.UUID)
			//Check inputs (data/structure only, signature is checked later)
			signatureBytes, err := hex.DecodeString(currTest.signatureToVerify)
			requirer.NoErrorf(err, "Test configuration string (signatureToVerify) can't be decoded.\nString was: %v", currTest.signatureToVerify)
			dataBytes, err := hex.DecodeString(currTest.dataToVerify)
			requirer.NoErrorf(err, "Test configuration string (dataToVerify) can't be decoded.\nString was: %v", currTest.dataToVerify)
			//Set the PublicKey for the Verification and check, that it is set correctly
			requirer.NoErrorf(context.SetPublicKey(id, pubBytes), "Setting the Private Key failed")

			//Call Verify() and assert error
			valid, err := context.Verify(id, dataBytes, signatureBytes)
			asserter.NoErrorf(err, "An unexpected error occured")
			asserter.Truef(valid, "the verification failed")
		})
	}
}

// TestCryptoContext_Verify performs fail tests for the (ECDSACryptoContext) Verify function
// TODO: add support for pkcs#11 crypto
func TestCryptoContext_VerifyFails(t *testing.T) {
	var tests = []struct {
		testName          string
		UUID              uuid.UUID
		UUIDforKey        uuid.UUID
		publicKey         string
		signatureToVerify string
		dataToVerify      string
	}{
		{
			testName:          "uuid.Nil",
			UUID:              uuid.Nil,
			UUIDforKey:        uuid.MustParse(defaultUUID),
			publicKey:         defaultPub,
			signatureToVerify: "b9fbd39289ac3d464662bb1277d183b697282bc08c56b6dba986b32f7a2778134441b006683a242733a80ef7f732cdbb6e9455d33f7a4350086b075db8f10d75",
			dataToVerify:      defaultHash,
		},
		{
			testName:          "uuidUnknown",
			UUID:              uuid.MustParse("12345678-1234-1234-1234-123456789abc"),
			UUIDforKey:        uuid.MustParse(defaultUUID),
			publicKey:         defaultPub,
			signatureToVerify: "b9fbd39289ac3d464662bb1277d183b697282bc08c56b6dba986b32f7a2778134441b006683a242733a80ef7f732cdbb6e9455d33f7a4350086b075db8f10d75",
			dataToVerify:      defaultHash,
		},
		{
			testName:          "noHash",
			UUID:              uuid.MustParse(defaultUUID),
			UUIDforKey:        uuid.MustParse(defaultUUID),
			publicKey:         defaultPub,
			signatureToVerify: "b9fbd39289ac3d464662bb1277d183b697282bc08c56b6dba986b32f7a2778134441b006683a242733a80ef7f732cdbb6e9455d33f7a4350086b075db8f10d75",
			dataToVerify:      "",
		},
		{
			testName:          "noSignature",
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
			var context = &ECDSACryptoContext{
				Keystore: NewEncryptedKeystore([]byte(defaultSecret)),
			}
			pubBytes, err := hex.DecodeString(currTest.publicKey)
			//Check the inputs (data/structure only, signature is checked later)
			signatureBytes, err := hex.DecodeString(currTest.signatureToVerify)
			requirer.NoErrorf(err, "Test configuration string (signatureToVerify) can't be decoded.\nString was: %v", currTest.signatureToVerify)
			dataBytes, err := hex.DecodeString(currTest.dataToVerify)
			requirer.NoErrorf(err, "Test configuration string (dataToVerify) can't be decoded.\nString was: %v", currTest.dataToVerify)
			// deliberately set UUIDforKey and not the UUID
			requirer.NoErrorf(context.SetPublicKey(currTest.UUIDforKey, pubBytes), "Setting the Private Key failed")

			//Call Verify() with UUID and assert error
			valid, err := context.Verify(currTest.UUID, dataBytes, signatureBytes)
			asserter.Errorf(err, "No error was returned from the Verification")
			asserter.Falsef(valid, "the verification succeeded unexpected")
		})
	}
}

func TestCryptoContext_PrivateKeyExists_NOTRDY(t *testing.T) {
	const (
		unknownID = "12345678-1234-1234-1234-123456789012"
	)
	asserter := assert.New(t)
	requirer := require.New(t)
	var context = &ECDSACryptoContext{
		Keystore: NewEncryptedKeystore([]byte(defaultSecret)),
	}
	p := NewExtendedProtocol(context, map[uuid.UUID][]byte{})
	// check for non existing key
	keyExists, err := p.PrivateKeyExists(uuid.MustParse(unknownID))
	asserter.NoErrorf(err, "Error when checking for key with unknown ID")
	asserter.Falsef(keyExists, "Key for unknown Name should not exist")

	// check for new generated key
	id := uuid.MustParse(defaultUUID)
	requirer.Nilf(p.GenerateKey(id), "Generating key failed")
	keyExists, err = p.PrivateKeyExists(id)
	asserter.NoErrorf(err, "Error when checking for key with default ID")
	asserter.Truef(keyExists, "Key should exist")
}

func TestCryptoContext_getDecodedPrivateKey_NOTRDY(t *testing.T) {
	t.Error("TestgetDecodedPrivateKey() not implemented")
}
