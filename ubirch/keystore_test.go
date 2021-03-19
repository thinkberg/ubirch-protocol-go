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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewEncryptedKeystore tests the creation of a new keystore
//		with correct secret length
// 		with empty secret
// 		with too long secret length
func TestNewEncryptedKeystore(t *testing.T) {
	asserter := assert.New(t)
	//create new encrypted keystore with valid secret
	testkeystore := NewEncryptedKeystore([]byte(defaultSecret))
	asserter.NotNilf(testkeystore, "KeyStore not created")
	asserter.IsTypef(testkeystore, &EncryptedKeystore{}, "Type is not correct")
	asserter.Equalf(testkeystore.Secret, []byte(defaultSecret), "the secret is different, should be the same")

	// try to create a KeyStore without secret
	testkeystore2 := NewEncryptedKeystore([]byte(""))
	asserter.Nilf(testkeystore2, "KeyStore created, should be Nil")

	// try to create a KeyStore with too long secret
	testkeystore3 := NewEncryptedKeystore(append([]byte(defaultSecret), 0x00))
	asserter.Nilf(testkeystore3, "KeyStore created, should be Nil")
}

// TestEncryptedKeystore_GetKey tests to Get a specific key from the keystore
//		Load a protocol context from file and
//			get the public key
//			get the private key
func TestEncryptedKeystore_GetKey(t *testing.T) {
	asserter := assert.New(t)
	requirer := require.New(t)
	//Set up test objects and parameters
	var testKeystore = NewEncryptedKeystore([]byte(defaultSecret))
	var context = &CryptoContext{
		Keystore: testKeystore,
		Names:    map[string]uuid.UUID{},
	}
	p := Protocol{Crypto: context, signatures: map[uuid.UUID][]byte{}}
	requirer.NoErrorf(loadProtocolContext(&p, "test3.json"), "Failed loading protocol context")
	id := uuid.MustParse(defaultUUID)
	// Get the public key
	pubKeyEncoded, err := testKeystore.GetKey(pubKeyEntryTitle(id))
	asserter.NoErrorf(err, "failed to get the public key")
	asserter.NotNilf(pubKeyEncoded, "pubkey is 'Nil'")
	// decode the key and compare it
	pubKey, err := decodePublicKeyTestHelper(pubKeyEncoded)
	pubKeyBytes := pubKey.X.Bytes()
	pubKeyBytes = append(pubKeyBytes, pubKey.Y.Bytes()...)
	pubKeyString := hex.EncodeToString(pubKeyBytes)
	asserter.Equalf(defaultPub, pubKeyString, "not equal")
	// Get the private key
	privKeyEncoded, err := testKeystore.GetKey(privKeyEntryTitle(id))
	asserter.NoErrorf(err, "failed to get the privlic key")
	asserter.NotNilf(privKeyEncoded, "privkey is 'Nil'")
	// decode the private key and compare it
	privKey, err := decodePrivateKeyTestHelper(privKeyEncoded)
	privKeyBytes := privKey.D.Bytes()
	privKeyString := hex.EncodeToString(privKeyBytes)
	asserter.Equalf(defaultPriv, privKeyString, "not equal")
}

// test, where the get method should fail
func TestEncryptedKeystore_GetKeyFails_NOTRDY(t *testing.T) {
	t.Errorf("not yet implemented")
}

// TestEncryptedKeystore_SetKey tests the Set method for a key in the keystore
//		Create an encoded private key
// 			set the complete key
//			set only part of the key, which is not practical, but allows the testing of different lengths
//		Create an encoded public key
// 			set the complete key
//			set only part of the key, which is not practical, but allows the testing of different lengths
func TestEncryptedKeystore_SetKey(t *testing.T) {
	asserter := assert.New(t)
	requirer := require.New(t)
	//Set up test objects and parameters
	var testKeystore = NewEncryptedKeystore([]byte(defaultSecret))
	// make Encoded private Key and test
	privBytesCorrect, err := hex.DecodeString(defaultPriv)
	requirer.NoErrorf(err, "Decoding private Key Bytes failed")
	privEncodedCorrect, err := encodePrivateKeyTestHelper(privBytesCorrect)
	requirer.NoErrorf(err, "Encoding PrivateKey failed")
	id := uuid.MustParse(defaultUUID)
	// Test valid key length
	asserter.NoErrorf(testKeystore.SetKey(privKeyEntryTitle(id), privEncodedCorrect),
		"set private key with correct length failed")
	// test different lengths for the key
	for i := 1; i < len(privEncodedCorrect); i++ {
		asserter.NoErrorf(testKeystore.SetKey(privKeyEntryTitle(id), privEncodedCorrect[:i]),
			"set private key with length (%v) failed", i)
	}
	// make Encoded public Key and test
	pubBytesCorrect, err := hex.DecodeString(defaultPub)
	requirer.NoErrorf(err, "Decoding private Key Bytes failed")
	pubEncodedCorrect, err := encodePublicKeyTestHelper(pubBytesCorrect)
	requirer.NoErrorf(err, "Encoding PrivateKey failed")
	// Test valid key length
	asserter.NoErrorf(testKeystore.SetKey(pubKeyEntryTitle(id), pubEncodedCorrect),
		"set public key with correct length failed")
	// test different lengths for the key
	for i := 1; i < len(pubEncodedCorrect); i++ {
		asserter.NoErrorf(testKeystore.SetKey(pubKeyEntryTitle(id), pubEncodedCorrect[:i]),
			"set public key with length (%v) failed", i)
	}
}

// Test the set method with keylengths of n*8 Bytes, where n >=1, which currently fails
// because of a bug in the paypal/keystore library
func TestEncryptedKeystore_SetKey2(t *testing.T) {
	asserter := assert.New(t)
	requirer := require.New(t)
	//Set up test objects and parameters
	var testKeystore = NewEncryptedKeystore([]byte(defaultSecret))
	// make Encoded private key and test
	privBytesCorrect, err := hex.DecodeString(defaultPriv)
	requirer.NoErrorf(err, "Decoding private Key Bytes failed")
	privEncodedCorrect, err := encodePrivateKeyTestHelper(privBytesCorrect)
	requirer.NoErrorf(err, "Encoding PrivateKey failed")
	id := uuid.MustParse(defaultUUID)
	// test all available legths n*8 Byte
	for i := 8; i < len(privEncodedCorrect); {
		i += 8
		asserter.NoErrorf(testKeystore.SetKey(privKeyEntryTitle(id), privEncodedCorrect[:i]),
			"set private key with length (%v) failed", i)
	}
	// make Encoded public Key and test
	pubBytesCorrect, err := hex.DecodeString(defaultPub)
	requirer.NoErrorf(err, "Decoding private Key Bytes failed")
	pubEncodedCorrect, err := encodePublicKeyTestHelper(pubBytesCorrect)
	requirer.NoErrorf(err, "Encoding PrivateKey failed")
	// test all available legths n*8 Byte
	for i := 8; i < len(pubEncodedCorrect); {
		i += 8
		asserter.NoErrorf(testKeystore.SetKey(pubKeyEntryTitle(id), pubEncodedCorrect[:i]),
			"set public key with length (%v) failed", i)
	}
}

func TestEncryptedKeystore_MarshalUnmarshalJSON(t *testing.T) {
	asserter := assert.New(t)
	requirer := require.New(t)

	// initialize new Keystore
	ks := NewEncryptedKeystore([]byte(defaultSecret))
	requirer.NotNilf(ks, "Newly initialized keystore is nil")
	id := uuid.MustParse(defaultUUID)

	// make+set encoded private Key
	privBytes, err := hex.DecodeString(defaultPriv)
	requirer.NoErrorf(err, "Decoding private key bytes failed")
	privEncoded, err := encodePrivateKeyTestHelper(privBytes)
	requirer.NoError(err, "Encoding private key failed")
	requirer.NoError(ks.SetKey(privKeyEntryTitle(id), privEncoded), "Setting private key failed")

	// can marshal keystore into byte representation
	byteRepr, err := ks.MarshalJSON()
	requirer.NoError(err, "Error marshaling keystore to bytes")

	//Can load keystore from marshaled bytes
	loadedKs := NewEncryptedKeystore([]byte(defaultSecret))
	requirer.NoError(loadedKs.UnmarshalJSON(byteRepr), "Error loading keystore from marshaled bytes")

	retrievedKey, err := ks.GetKey(privKeyEntryTitle(id))
	requirer.NoErrorf(err, "Error getting key %q", privKeyEntryTitle(id), err)
	asserter.Equal(privEncoded, retrievedKey, "Retrieved key (%v) does not match saved key %q: retrieved: %x expected: %x", defaultUUID)
}

func TestEncryptedKeystore_WrongSecret(t *testing.T) {
	requirer := require.New(t)

	// initialize new Keystore
	ks := NewEncryptedKeystore([]byte(defaultSecret))
	requirer.NotNilf(ks, "Newly initialized keystore is nil")

	// make+set encoded private Key
	privBytes, err := hex.DecodeString(defaultPriv)
	requirer.NoErrorf(err, "Decoding private key bytes failed")
	privEncoded, err := encodePrivateKeyTestHelper(privBytes)
	requirer.NoError(err, "Encoding private key failed")
	requirer.NoError(ks.SetKey(defaultUUID, privEncoded), "Setting private key failed")

	//change the secret so decryption fails
	ks.Secret = []byte("0000000000000000")

	//try to retrive key (should fail)
	_, err = ks.GetKey(defaultUUID)
	requirer.Errorf(err, "Key could be retrived with wrong secret")
}

// Testing the Marshal JSON functionality
//		This test depends on the file test3.json
func TestEncryptedKeystore_MarshalJSON(t *testing.T) {
	asserter := assert.New(t)
	requirer := require.New(t)
	//Set up test objects and parameters
	var testKeystore = NewEncryptedKeystore([]byte(defaultSecret))
	var context = &CryptoContext{
		Keystore: testKeystore,
		Names:    map[string]uuid.UUID{},
	}
	// test empty Keystore
	jsonKeystore, err := testKeystore.MarshalJSON()
	asserter.NoErrorf(err, "there should be no error")
	asserter.Containsf(string(jsonKeystore), "{}", "This should be empty")

	// test with keystore file "test3.json" and check if the relevant information is provided
	p := Protocol{Crypto: context, signatures: map[uuid.UUID][]byte{}}
	requirer.NoErrorf(loadProtocolContext(&p, "test3.json"), "Failed loading protocol context")

	jsonKeystore, err = testKeystore.MarshalJSON()
	asserter.NoErrorf(err, "there should be no error")
	asserter.Containsf(string(jsonKeystore), "6eac4d0b-16e6-4508-8c46-22e7451ea5a1", "keyname not present")
	asserter.Containsf(string(jsonKeystore), "_6eac4d0b-16e6-4508-8c46-22e7451ea5a1", "keyname not present")
	asserter.Containsf(string(jsonKeystore),
		"Y8hIgKipGokgjlUrL8gi1P17TmiHiZ0jqGQlRB2512GwVmaHZTjwgbdc019m1dODp0NPDIh2JstexjqCsAwHjIuA/DPvhLoIDqY35ZJCoZ7LqY/ISeujnZUXQWqcET7DcyDZHPBQQ67NDTa6urajiYNGoiGI8q82h7g3Pn5jGRdZRqrAyhyYP7tEt1vsgqfsCAEYCwroRdXb1VQv8YBLhDRTZVCPm2BkKt/SM14bzoS1KLKTZtjMoxWlQIiZPu1p2BEgFwQ6KgRa9+6zIGbBm9EQ81EdFWZ18PfVLCzb/qgxrOZ5R+fduQ==",
		"keyvalue not present")
	asserter.Containsf(string(jsonKeystore),
		"6fZv2OPrI+NdpPtCNY3Xqh+7Q/HTcJ6geD+HJM5eaNCb7V417kK0fLO8tGnbkLtntkSgXNskOzDdL73nKxDufwWpauKUOBuiaTTXuei1IVl/6VlQsXy1hlcL3vl8dNbgVKNdO7lYcWb0/s2XWGXvbYvN5d0F1VdByqOBUBk6ARbxt1ALWd72aLRK+EGQuc5x6GhjxcTSB8KIcMfbsmtVvXFhnX4UE6PeB0lbryP9II7gPaEqQ7272Dcb7Fyq9e6t",
		"keyvalue not present")
}

// todo: figure out, how to test this
func TestEncryptedKeystore_UnmarshalJSON_NOTRDY(t *testing.T) {
	t.Errorf("not yet implemented")
}
