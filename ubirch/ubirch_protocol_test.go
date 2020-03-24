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
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"math"
	"math/big"
	"math/bits"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//TestDecodeArrayToStruct decodes a 'Chained' type UPP and checks expected UUID
// and payload/hash data (currently no signature verification tests)
func TestDecodeArrayToStruct(t *testing.T) {

	var tests = []struct {
		testName        string
		inputUPP        string
		expectedUUID    string
		expectedPayload string
	}{
		{
			"ChainedUPP-32BytesPayload-Packet1",
			"9623c4106eac4d0b16e645088c4622e7451ea5a1c440855d94b0ec9c7bcd21149f2044f8f93a6d83dea968ed96c18e02c11c2fe3a04e75a84f3d73adaeb1a0b975e70c5d21a22fb0db8ea6473516210b01404862e92400c420397edf2cf58afb187156d7c4ade27330a92ecf5c653aeb48e106c7f41d926360c440c3456908c392342f34df464f48fc7a44fe2e93d56f097b173629d4d891b1c8542a5237fe2c69310d4462adcb642d4da44ca84629dfa980805057e0642069c96b",
			"6eac4d0b-16e6-4508-8c46-22e7451ea5a1",
			"397edf2cf58afb187156d7c4ade27330a92ecf5c653aeb48e106c7f41d926360",
		},
		{
			"ChainedUPP-32BytesPayload-Packet2",
			"9623c4106eac4d0b16e645088c4622e7451ea5a1c4406beb37362b68e6afe66eb33b7ed8d2a5a059e6ca4f627923faa35d2ded50e69a75733b8f006ac8198b67e22ae0489d8d314b16cf59f60f4cb060b84d398d8c8700c4201bb891f6f764cd8293d0c9ceeffc85da0be801a6e7943d328300397edf2cf58ac440c436a0e8ca003d849e1e3a8ca756cf56d6a0599f399f58d8cdbee813ce340cd3bd27ec509b15d5dffeef6b2792f666cf4ecbe8a8e5c58806983fef7ecbaa7182",
			"6eac4d0b-16e6-4508-8c46-22e7451ea5a1",
			"1bb891f6f764cd8293d0c9ceeffc85da0be801a6e7943d328300397edf2cf58a",
		},
	}

	//Iterate over all tests
	for _, currTest := range tests {
		t.Run(currTest.testName, func(t *testing.T) {
			//Try to decode chained UPP
			bytesUPP, err := hex.DecodeString(currTest.inputUPP)
			if err != nil {
				t.Fatalf("Error decoding expected input UPP string: %v, string was: %v", err, currTest.inputUPP)
			}
			o, err := Decode(bytesUPP)
			if err != nil {
				t.Errorf("upp can't be decoded: %v", err)
			}
			//Create/cast chained UPP data
			c := o.(*ChainedUPP) //TODO:extend test for other UPP types than 'chained'
			//Check decoded UUID
			if uuid.MustParse(currTest.expectedUUID) != c.Uuid {
				t.Errorf("uuid does not match:\nexpected: %v\ngot:      %v", currTest.expectedUUID, c.Uuid)
			}
			//Check decoded payload/hash
			expectedPayloadBytes, err := hex.DecodeString(currTest.expectedPayload)
			if err != nil {
				t.Fatalf("Error decoding expected payload string: %v, string was: %v", err, currTest.expectedPayload)
			}
			if !(bytes.Equal(expectedPayloadBytes, c.Payload)) {
				t.Errorf("Decoded hash/payload does not match:\nexpected: %x\ngot:      %x", expectedPayloadBytes, c.Payload)
			}
		})
	}
}

func TestGetLastSignatureNOTRDY(t *testing.T) {
	t.Error("GetLastSignature() not implemented")
}

func TestSetLastSignatureNOTRDY(t *testing.T) {
	t.Error("SetLastSignature() not implemented")
}

func TestResettLastSignatureNOTRDY(t *testing.T) {
	t.Error("ResetLastSignature() not implemented")
}

//TestSignFails tests the cases where the Sign function must return an error
//it tests the defined inputs for each of the protocols defined in protocolsToTest(per case)
func TestSignFails(t *testing.T) {
	var tests = []struct {
		testName             string
		nameForContext       string
		UUIDForContext       string
		privateKeyForContext string
		lastSigForContext    string
		nameForSign          string
		hashForSign          string
		protocolsToTest      []ProtocolType
	}{
		{
			testName:             "NameNotPresent",
			nameForContext:       "name",
			UUIDForContext:       defaultUUID,
			privateKeyForContext: defaultPriv,
			lastSigForContext:    "",
			nameForSign:          "naamee",
			hashForSign:          defaultHash,
			protocolsToTest:      []ProtocolType{Signed, Chained},
		},
		{
			testName:             "ContextNotInitializedEmptyName",
			nameForContext:       "",
			UUIDForContext:       "",
			privateKeyForContext: "",
			lastSigForContext:    "",
			nameForSign:          "",
			hashForSign:          defaultHash,
			protocolsToTest:      []ProtocolType{Signed, Chained},
		},
		{
			testName:             "ContextNotInitializedNonEmptyName",
			nameForContext:       "",
			UUIDForContext:       "",
			privateKeyForContext: "",
			lastSigForContext:    "",
			nameForSign:          "a",
			hashForSign:          defaultHash,
			protocolsToTest:      []ProtocolType{Signed, Chained},
		},
		{
			testName:             "EmptyName",
			nameForContext:       defaultName,
			UUIDForContext:       defaultUUID,
			privateKeyForContext: defaultPriv,
			lastSigForContext:    defaultLastSig,
			nameForSign:          "",
			hashForSign:          defaultHash,
			protocolsToTest:      []ProtocolType{Signed, Chained},
		},
		//{
		//	testName:             "UUIDNotSet",
		//	nameForContext:       defaultName,
		//	UUIDForContext:       "",
		//	privateKeyForContext: defaultPriv,
		//	lastSigForContext:    "",
		//	nameForSign:          defaultName,
		//	hashForSign:          defaultHash,
		//	protocolsToTest:      []ProtocolType{Signed, Chained},
		//},
		{
			testName:             "PrivkeyNotSet",
			nameForContext:       defaultName,
			UUIDForContext:       defaultUUID,
			privateKeyForContext: "",
			lastSigForContext:    "",
			nameForSign:          defaultName,
			hashForSign:          defaultHash,
			protocolsToTest:      []ProtocolType{Signed, Chained},
		},
		{
			testName:             "EmptyHash",
			nameForContext:       defaultName,
			UUIDForContext:       defaultUUID,
			privateKeyForContext: defaultPriv,
			lastSigForContext:    defaultLastSig,
			nameForSign:          defaultName,
			hashForSign:          "",
			protocolsToTest:      []ProtocolType{Signed, Chained},
		},
		{
			testName:             "33ByteHash",
			nameForContext:       defaultName,
			UUIDForContext:       defaultUUID,
			privateKeyForContext: defaultPriv,
			lastSigForContext:    defaultLastSig,
			nameForSign:          defaultName,
			hashForSign:          "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			protocolsToTest:      []ProtocolType{Signed, Chained},
		},
		{
			testName:             "31ByteHash",
			nameForContext:       defaultName,
			UUIDForContext:       defaultUUID,
			privateKeyForContext: defaultPriv,
			lastSigForContext:    defaultLastSig,
			nameForSign:          defaultName,
			hashForSign:          "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			protocolsToTest:      []ProtocolType{Signed, Chained},
		},
	}

	//Iterate over all tests
	for _, currTest := range tests {
		//Run each test for each protocol that should be tested
		for _, currProtocolToTest := range currTest.protocolsToTest {
			//Create identifier to append to test name
			protocolTypeString := fmt.Sprintf("(ProtocolType=%v)", currProtocolToTest)
			t.Run(currTest.testName+protocolTypeString, func(t *testing.T) {
				asserter := assert.New(t)
				requirer := require.New(t)

				//Create new crypto context
				protocol, err := newProtocolContextSigner(currTest.nameForContext, currTest.UUIDForContext, currTest.privateKeyForContext, currTest.lastSigForContext)
				requirer.NoError(err, "Can't continue with test: Creating protocol context failed")

				//Check created UPP (data/structure only, signature is checked later)
				hashBytes, err := hex.DecodeString(currTest.hashForSign)
				requirer.NoErrorf(err, "Test configuration string (hashForSign) can't be decoded.\nString was: %v", currTest.hashForSign)

				//Call Sign() and assert error
				_, err = protocol.Sign(currTest.nameForSign, hashBytes, currProtocolToTest)
				asserter.Error(err, "Sign() did not return an error for invalid input")
				// Todo this is just to see what happens, will have to be removed later
				//filename := fmt.Sprintf("Save2_%s.json", currTest.testName)
				//err = saveProtocolContext(protocol, filename)
				//asserter.NoErrorf(err,"something went wrong %v", err)
			})
		}
	}
}

//TestCreateMessageFails tests the cases where the create message function must return an error
func TestCreateMessageFailsNOTRDY(t *testing.T) {
	t.Error("Creating a message from user data not implemented")
}

func TestCreateMessageDataInputLengthNOTRDY(t *testing.T) {
	t.Error("Creating a message from user data not implemented")
}

//TestCreateMessageSigned tests 'Signed' type UPP creation from given user data. Data is hashed, hash is
//used as UPP payload and then the created encoded UPP data is compared to the expected values,
//the signature is also checked. as it's non-deterministic, signature in expected UPPs are ignored,
//instead a proper verification with the public key is performed
func TestCreateMessageSigned(t *testing.T) {
	var tests = []struct {
		testName    string
		privateKey  string
		publicKey   string
		deviceUUID  string
		userData    string //this is not a hash but the data that the user wants to be sealed/ubirchified
		expectedUPP string //signature contained in expected UPP is only placeholder, instead, actual created signature is checked
	}{
		{
			testName:    "Data='1'",
			privateKey:  defaultPriv,
			publicKey:   defaultPub,
			deviceUUID:  "6eac4d0b-16e6-4508-8c46-22e7451ea5a1",
			userData:    "31", //equals the character "1" string
			expectedUPP: "9522c4106eac4d0b16e645088c4622e7451ea5a100c4206b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4bc44000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		},
		{
			testName:    "Data='Hello World!'",
			privateKey:  defaultPriv,
			publicKey:   defaultPub,
			deviceUUID:  "6eac4d0b-16e6-4508-8c46-22e7451ea5a1",
			userData:    "48656c6c6f20576f726c6421", //"Hello World!"
			expectedUPP: "9522c4106eac4d0b16e645088c4622e7451ea5a100c4207f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069c44000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		},
	}

	//Iterate over all tests
	for _, currTest := range tests {
		t.Run(currTest.testName, func(t *testing.T) {
			asserter := assert.New(t)
			requirer := require.New(t)

			//Create new crypto context
			protocol, err := newProtocolContextSigner(defaultName, currTest.deviceUUID, currTest.privateKey, defaultLastSig)
			requirer.NoError(err, "Creating protocol context failed")

			//Create 'Signed' type UPP with user data
			userDataBytes, err := hex.DecodeString(currTest.userData)
			requirer.NoErrorf(err, "Test configuration string (input data) can't be decoded.\nString was: %v", currTest.userData)
			//TODO: This hashing should be removed as soon as a proper
			// "Create UPP from data" is implemented in the library
			hash := sha256.Sum256(userDataBytes)
			createdUpp, err := protocol.Sign(defaultName, hash[:], Signed)
			requirer.NoError(err, "Protocol.Sign() failed")

			//Check created UPP (data/structure only, signature is checked later)
			expectedUPPBytes, err := hex.DecodeString(currTest.expectedUPP)
			requirer.NoErrorf(err, "Test configuration string (expected UPP) can't be decoded.\nString was: %v", currTest.expectedUPP)

			createdUppNoSignature := createdUpp[:len(createdUpp)-64]
			expectedUppNoSignature := expectedUPPBytes[:len(expectedUPPBytes)-64]
			asserter.Equal(createdUppNoSignature, expectedUppNoSignature, "Created UPP data is not as expected")

			//Check signature
			pubkeyBytes, err := hex.DecodeString(currTest.publicKey)
			requirer.NoErrorf(err, "Test configuration string (pubkey) can't be decoded.\nString was: %v", currTest.publicKey)

			verifyOK, err := verifyUPPSignature(t, createdUpp, pubkeyBytes)
			requirer.NoError(err, "Signature verification could not be performed due to errors")
			asserter.True(verifyOK, "Signature is not OK")
		})
	}
}

//TestCreateChainedMessage tests 'Chained' type UPP creation across multiple chained packets. Each input is hashed, hash is
//used as UPP payload and then the created encoded UPP data (without the signature, as its
//non-deterministic) is compared to the expected values. During this, the signature of the last UPP is manually copied into the
//expected data, as ECDSA is non-deterministic, thus only testing if the basic UPP encoding works.
func TestCreateMessageChained(t *testing.T) {
	var tests = []struct {
		testName            string
		privateKey          string
		publicKey           string
		deviceUUID          string
		lastSignature       string   // last signature before first packet in array of expected packets
		UserDataInputs      []string // array of user data input (not a hash) for hashing and UPP creation
		expectedChainedUpps []string //signature in expected UPPs is only placeholder, instead, actual created signature is checked
	}{
		{
			testName:      "dontSetLastSignature",
			privateKey:    defaultPriv,
			publicKey:     defaultPub,
			deviceUUID:    "6eac4d0b-16e6-4508-8c46-22e7451ea5a1",
			lastSignature: "", //""=don't set signature
			UserDataInputs: []string{
				"01",
				"02",
				"03",
			},
			expectedChainedUpps: []string{
				"9623c4106eac4d0b16e645088c4622e7451ea5a1c4400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c4204bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459ac44000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
				"9623c4106eac4d0b16e645088c4622e7451ea5a1c4400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c420dbc1b4c900ffe48d575b5da5c638040125f65db0fe3e24494b76ea986457d986c44000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
				"9623c4106eac4d0b16e645088c4622e7451ea5a1c4400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c420084fed08b978af4d7d196a7446a86b58009e636b611db16211b65a9aadff29c5c44000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
			},
		},
		{
			testName:      "SpecificPrivAndPubKey",
			privateKey:    "10a0bef246575ea219e15bffbb6704d2a58b0e4aa99f101f12f0b1ce7a143559",
			publicKey:     "92bbd65d59aecbdf7b497fb4dcbdffa22833613868ddf35b44f5bd672496664a2cc1d228550ae36a1d0210a3b42620b634dc5d22ecde9e12f37d66eeedee3e6a",
			deviceUUID:    "6eac4d0b-16e6-4508-8c46-22e7451ea5a1",
			lastSignature: defaultLastSig,
			UserDataInputs: []string{
				"01",
				"02",
				"03",
			},
			expectedChainedUpps: []string{
				"9623c4106eac4d0b16e645088c4622e7451ea5a1c4400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c4204bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459ac44000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
				"9623c4106eac4d0b16e645088c4622e7451ea5a1c4400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c420dbc1b4c900ffe48d575b5da5c638040125f65db0fe3e24494b76ea986457d986c44000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
				"9623c4106eac4d0b16e645088c4622e7451ea5a1c4400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c420084fed08b978af4d7d196a7446a86b58009e636b611db16211b65a9aadff29c5c44000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
			},
		},
	}

	//Iterate over all tests
	for _, currTest := range tests {
		t.Run(currTest.testName, func(t *testing.T) {
			asserter := assert.New(t)
			requirer := require.New(t)

			//Create new crypto context
			protocol, err := newProtocolContextSigner(defaultName, currTest.deviceUUID, currTest.privateKey, currTest.lastSignature)
			requirer.NoError(err, "Creating protocol context failed")

			requirer.Equal(len(currTest.UserDataInputs), len(currTest.expectedChainedUpps), "Number of input data sets does not match number of expected UPPs")

			createdUpps := make([][]byte, len(currTest.UserDataInputs))
			//Loop over input data and create all UPP packets for this test
			for currInputIndex, currInputData := range currTest.UserDataInputs {
				//Create 'chained' type UPP with user data
				userDataBytes, err := hex.DecodeString(currInputData)
				requirer.NoErrorf(err, "Test configuration string (input data) can't be decoded for input %v. String was: %v", currInputIndex, currInputData)
				//TODO: This hashing should be removed as soon as a proper
				// "Create UPP from data" is implemented in the library
				hash := sha256.Sum256(userDataBytes)
				createdUppData, err := protocol.Sign(defaultName, hash[:], Chained)
				requirer.NoErrorf(err, "Protocol.Sign() failed for input data at index %v", currInputIndex)
				//Save UPP into array of all created UPPs
				createdUpps[currInputIndex] = createdUppData
			}

			//Check all created UPPs (data/structure only, signature and lastSignature are ignored and are checked later)
			for currCreatedUppIndex, currCreatedUppData := range createdUpps {
				//Decode expected UPP data
				expectedUppString := currTest.expectedChainedUpps[currCreatedUppIndex]
				expectedUPPBytes, err := hex.DecodeString(expectedUppString)
				requirer.NoErrorf(err, "Test configuration string (expected UPP) can't be decoded for input %v.\nString was: %v", currCreatedUppIndex, expectedUppString)

				//Overwrite lastSignature and signature with zeroes (these are checked separately later)
				//we need to copy into a new slice for this, so we don't modify the array with the created UPPs
				//TODO use library defines instead of magic numbers for signature length and position as soon as they are available
				//create new slicesby appending to an empty slice all source slice elements
				createdUppNoSignatures := append([]byte{}, currCreatedUppData...)
				expectedUppNoSignatures := append([]byte{}, expectedUPPBytes...)
				//zeroize signature
				copy(createdUppNoSignatures[len(createdUppNoSignatures)-64:], make([]byte, 64))
				copy(expectedUppNoSignatures[len(expectedUppNoSignatures)-64:], make([]byte, 64))
				//zeroize lastSignature
				copy(createdUppNoSignatures[22:22+64], make([]byte, 64))
				copy(expectedUppNoSignatures[22:22+64], make([]byte, 64))

				//Do the check
				asserter.Equalf(createdUppNoSignatures, expectedUppNoSignatures, "Created UPP data is not as expected for UPP at index %v", currCreatedUppIndex)
			}

			//check chaining of created UPPs
			var lastSignatureBytes []byte
			if currTest.lastSignature == "" { //check if no signature was set
				lastSignatureBytes = make([]byte, 64) //in that case, chain should start with 00...00 in lastSignature field
			} else { //else decode last signature string
				lastSignatureBytes, err = hex.DecodeString(currTest.lastSignature)
				requirer.NoErrorf(err, "Test configuration string (last Signature) can't be decoded . String was: %v", currTest.lastSignature)
			}
			err = verifyUPPChain(t, createdUpps, lastSignatureBytes)
			asserter.NoError(err, "Chain verification failed")

			//Check signatures of the created UPPs
			for currCreatedUppIndex, currCreatedUppData := range createdUpps {
				pubkeyBytes, err := hex.DecodeString(currTest.publicKey)
				requirer.NoErrorf(err, "Test configuration string (pubkey) can't be decoded for input %v. String was: %v", currCreatedUppIndex, currTest.publicKey)

				verifyOK, err := verifyUPPSignature(t, currCreatedUppData, pubkeyBytes)
				requirer.NoErrorf(err, "Signature verification could not be performed due to errors for created UPP at index %v", currCreatedUppIndex)
				asserter.Truef(verifyOK, "Signature is not OK for created UPP at index %v", currCreatedUppIndex)
			}
		})
	}
}

//TestVerifyHashedMessage in its current state only tests if the ECDSA library behaves as expected
func TestVerifyHashedMessage(t *testing.T) {
	asserter := assert.New(t)

	vkb, _ := base64.StdEncoding.DecodeString("o71ufIY0rP4GXQELZcXlm6t2s/LB29jzGfmheG3q8dJecxrGc/bqIODYcfROx6ofgunyarvG4lFiP+7p18qZqg==")
	hsh, _ := base64.StdEncoding.DecodeString("T2v511D0Upfr7Vl0DY5xnganDXlUCILCfZvetExHgzQ=")
	sig, _ := base64.StdEncoding.DecodeString("WQ/xDF7LVU/CVFzqGwopleefBe5xMLFrnkyEUzE08s0pxZgbtudReaWw70FSPvf2f83kgMvd5gfLNBd1V3AGng==")

	x := &big.Int{}
	x.SetBytes(vkb[0:32])
	y := &big.Int{}
	y.SetBytes(vkb[32:64])

	vk := ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}

	r, s := &big.Int{}, &big.Int{}
	r.SetBytes(sig[:32])
	s.SetBytes(sig[32:])

	asserter.True(ecdsa.Verify(&vk, hsh, r, s), "ecdsa.Verify() failed to verify known-good signature")
}

func TestVerify(t *testing.T) {
	var tests = []struct {
		testName   string
		UUID       string
		pubKey     string
		input      string
		protoType  ProtocolType
		verifiable bool
	}{
		{
			testName:   "signed UPP",
			UUID:       "6eac4d0b-16e6-4508-8c46-22e7451ea5a1",
			pubKey:     defaultPub,
			input:      "9522c4106eac4d0b16e645088c4622e7451ea5a100c4206b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4bc440bc2a01322c679b9648a9391704e992c041053404aafcdab08fc4ce54a57eb16876d741918d01219abf2dc7913f2d9d49439d350f11d05cdb3f85972ac95c45fc",
			protoType:  Signed,
			verifiable: true,
		},
	}

	//Iterate over all tests
	for _, currTest := range tests {
		t.Run(currTest.testName, func(t *testing.T) {
			requirer := require.New(t)

			// Create new context
			protocol, err := newProtocolContextVerifier(defaultName, currTest.UUID, currTest.pubKey)
			requirer.NoError(err, "Creating protocol context failed: %v", err)

			// convert test input string to bytes
			inputBytes, err := hex.DecodeString(currTest.input)
			requirer.NoErrorf(err, "Decoding test input from string failed: %v, string was: %v", err, currTest.input)

			// verify test input
			verified, err := protocol.Verify(defaultName, inputBytes, currTest.protoType)
			requirer.NoErrorf(err, "protocol.Verify() returned error: %v", err)
			requirer.Equal(currTest.verifiable, verified,
				"test input was verifiable = %v, but protocol.Verify() returned %v. Input was %s",
				currTest.verifiable, verified, currTest.input)
		})
	}
}

// TestDecode tests the Decode function of the ubirch package.
// To test invalid input, don't set the `protoType`-attribute of the test-struct (defaults to 0).
// If the input is decoded successfully despite being invalid, the test should fail.
func TestDecode(t *testing.T) {
	var tests = []struct {
		testName      string
		UPP           string
		protoType     ProtocolType
		UUID          string
		PrevSignature string
		Hint          uint8
		Payload       string
		Signature     string
	}{
		{
			testName:      "signed UPP",
			UPP:           "9522c4106eac4d0b16e645088c4622e7451ea5a100c4206b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4bc440bc2a01322c679b9648a9391704e992c041053404aafcdab08fc4ce54a57eb16876d741918d01219abf2dc7913f2d9d49439d350f11d05cdb3f85972ac95c45fc",
			protoType:     Signed,
			UUID:          "6eac4d0b-16e6-4508-8c46-22e7451ea5a1",
			PrevSignature: "",
			Hint:          0x00,
			Payload:       "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b",
			Signature:     "bc2a01322c679b9648a9391704e992c041053404aafcdab08fc4ce54a57eb16876d741918d01219abf2dc7913f2d9d49439d350f11d05cdb3f85972ac95c45fc",
		},
		{
			testName:      "chained UPP",
			UPP:           "9623c4106eac4d0b16e645088c4622e7451ea5a1c440bc2a01322c679b9648a9391704e992c041053404aafcdab08fc4ce54a57eb16876d741918d01219abf2dc7913f2d9d49439d350f11d05cdb3f85972ac95c45fc00c4206b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4bc44062328171c464a73084c25728ddfa2959b5cd5f440451bf9b9a6aec11de4612d654bb3b2378aa5a88137ba8b3cce582a13d7a58a8742acbbf67d198448fb0ad70",
			protoType:     Chained,
			UUID:          "6eac4d0b-16e6-4508-8c46-22e7451ea5a1",
			PrevSignature: "bc2a01322c679b9648a9391704e992c041053404aafcdab08fc4ce54a57eb16876d741918d01219abf2dc7913f2d9d49439d350f11d05cdb3f85972ac95c45fc",
			Hint:          0x00,
			Payload:       "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b",
			Signature:     "62328171c464a73084c25728ddfa2959b5cd5f440451bf9b9a6aec11de4612d654bb3b2378aa5a88137ba8b3cce582a13d7a58a8742acbbf67d198448fb0ad70",
		},
		{
			testName: "invalid UPP",
			UPP:      "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b",
		},
		{
			testName: "incomplete UPP",
			UPP:      "9623c4106eac4d0b16e645088c4622e7451ea5a1c440bc2a01322c679b9648a9391704e992c041053404aafcda",
		},
	}

	//Iterate over all tests
	for _, currTest := range tests {
		t.Run(currTest.testName, func(t *testing.T) {
			asserter := assert.New(t)
			requirer := require.New(t)

			// parse test parameters into correct types
			var id uuid.UUID
			var err error
			if currTest.UUID != "" {
				id, err = uuid.Parse(currTest.UUID)
				requirer.NoErrorf(err, "Parsing UUID from string failed: %v, string was: %v", err, currTest.UUID)
			}

			prevSigBytes, err := hex.DecodeString(currTest.PrevSignature)
			requirer.NoErrorf(err, "Decoding test PrevSignature from string failed: %v, string was: %v", err, currTest.PrevSignature)

			payloadBytes, err := hex.DecodeString(currTest.Payload)
			requirer.NoErrorf(err, "Decoding test Payload from string failed: %v, string was: %v", err, currTest.Payload)

			signatureBytes, err := hex.DecodeString(currTest.Signature)
			requirer.NoErrorf(err, "Decoding test Signature from string failed: %v, string was: %v", err, currTest.Signature)

			uppBytes, err := hex.DecodeString(currTest.UPP)
			requirer.NoErrorf(err, "Decoding test input from string failed: %v, string was: %v", err, currTest.UPP)

			// decode test input
			decoded, err := Decode(uppBytes)

			switch currTest.protoType {
			case Signed:
				// make sure UPP was decoded to correct type and cast type
				requirer.IsType(&SignedUPP{}, decoded, "signed UPP input was decoded to type %T", decoded)
				requirer.NoError(err, "Decode() returned error: %v", err)
				signed := decoded.(*SignedUPP)

				// check if decoded UPP has expected attributes
				asserter.Equal(currTest.protoType, signed.Version, "decoded incorrect protocol version")
				asserter.Equal(id, signed.Uuid, "decoded incorrect uuid")
				asserter.Equal(currTest.Hint, signed.Hint, "decoded incorrect hint")
				asserter.Equal(payloadBytes, signed.Payload, "decoded incorrect payload")
				asserter.Equal(signatureBytes, signed.Signature, "decoded incorrect signature")

			case Chained:
				// make sure UPP was decoded to correct type and cast type
				requirer.IsType(&ChainedUPP{}, decoded, "chained UPP input was decoded to type %T", decoded)
				requirer.NoError(err, "Decode() returned error: %v", err)
				chained := decoded.(*ChainedUPP)

				// check if decoded UPP has expected attributes
				asserter.Equal(currTest.protoType, chained.Version, "decoded incorrect protocol version")
				asserter.Equal(id, chained.Uuid, "decoded incorrect uuid")
				asserter.Equal(prevSigBytes, chained.PrevSignature, "decoded incorrect previous signature")
				asserter.Equal(currTest.Hint, chained.Hint, "decoded incorrect hint")
				asserter.Equal(payloadBytes, chained.Payload, "decoded incorrect payload")
				asserter.Equal(signatureBytes, chained.Signature, "decoded incorrect signature")

			default:
				requirer.Nil(decoded, "invalid input was decoded to UPP. input was: %s", currTest.UPP)
				requirer.Error(err, "Decode() did not return error with invalid input")
			}
		})
	}
}

// test random numbers from package "crypto/rand"
func TestRandomNOTRDY(t *testing.T) {
	requirer := require.New(t)

	//Frequency (Monobit) Test
	r := rand.Reader                         // the RNG under test
	n := 100                                 // the length of the random number to be tested for randomness
	randomNumberUnderTest := make([]byte, n) // the random number to be tested for randomness
	_, err := io.ReadFull(r, randomNumberUnderTest)
	requirer.NoError(err, "generating random number failed: %v", err)

	//calculate the frequency of ones and zeros in the random number
	s := 0
	for i := 0; i < n; i++ {
		// get number of one bits (population count)
		ones := bits.OnesCount8(randomNumberUnderTest[i])
		// count +1 for every one bit and -1 for every zero bit
		s += (2 * ones) - 8
	}
	log.Printf("s: %v", s)

	// calculate the test statistic
	s_obs := math.Abs(float64(s)) / math.Sqrt(float64(n))

	pValue := math.Erfc(s_obs / math.Sqrt2)
	log.Printf("pValue: %v", pValue)

	//Decision Rule at the 1% Level: If the computed P-value is < 0.01, then conclude that the sequence is non-random.
	//Otherwise, conclude that the sequence is random.
	requirer.Greater(pValue, 0.01, "random number did not pass Frequency (Monobit) Test: %v", randomNumberUnderTest)
}
